//! Socket Takeover for zero-downtime deployments
//!
//! Based on Meta's Zero Downtime Release paper.
//! Uses Unix domain sockets with SCM_RIGHTS to pass listening socket FDs
//! from old process to new process.

use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use tracing::{debug, error, info, warn};

/// Default socket path for takeover
pub const DEFAULT_TAKEOVER_SOCKET: &str = "/tmp/atlas-takeover.sock";

/// Protocol version for handshake
const PROTOCOL_VERSION: u32 = 1;

/// Message types in takeover protocol
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
enum MessageType {
    /// Handshake request from new process
    Hello = 1,
    /// Handshake response from old process
    HelloAck = 2,
    /// Request to transfer listening sockets
    RequestSockets = 3,
    /// Sockets being transferred (with SCM_RIGHTS)
    SocketsTransfer = 4,
    /// Acknowledgment of socket receipt
    SocketsAck = 5,
    /// Signal old process to start draining
    StartDrain = 6,
    /// Confirmation drain has started
    DrainStarted = 7,
    /// Error message
    ProtocolError = 255,
}

impl TryFrom<u8> for MessageType {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(MessageType::Hello),
            2 => Ok(MessageType::HelloAck),
            3 => Ok(MessageType::RequestSockets),
            4 => Ok(MessageType::SocketsTransfer),
            5 => Ok(MessageType::SocketsAck),
            6 => Ok(MessageType::StartDrain),
            7 => Ok(MessageType::DrainStarted),
            255 => Ok(MessageType::ProtocolError),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unknown message type: {}", value),
            )),
        }
    }
}

/// Message header: type (1 byte) + length (4 bytes)
const HEADER_SIZE: usize = 5;

/// Maximum number of FDs that can be passed at once
const MAX_FDS: usize = 16;

/// Takeover server running in the old process
pub struct TakeoverServer {
    listener: UnixListener,
    socket_path: String,
}

impl TakeoverServer {
    /// Create a new takeover server
    pub fn new<P: AsRef<Path>>(socket_path: P) -> io::Result<Self> {
        let path = socket_path.as_ref();

        // Remove stale socket if it exists
        if path.exists() {
            std::fs::remove_file(path)?;
        }

        let listener = UnixListener::bind(path)?;
        listener.set_nonblocking(false)?;

        info!("Takeover server listening on {}", path.display());

        Ok(Self {
            listener,
            socket_path: path.to_string_lossy().to_string(),
        })
    }

    /// Wait for a new process to connect and perform takeover
    /// Returns true if takeover was successful and old process should drain
    pub fn handle_takeover(&self, listening_fds: &[RawFd]) -> io::Result<bool> {
        info!("Waiting for new process to connect for takeover...");

        let (mut stream, _addr) = self.listener.accept()?;
        info!("New process connected for takeover");

        // Receive Hello
        let (msg_type, payload) = recv_message(&mut stream)?;
        if msg_type != MessageType::Hello {
            error!("Expected Hello, got {:?}", msg_type);
            return Ok(false);
        }

        // Parse Hello payload (version)
        if payload.len() < 4 {
            error!("Invalid Hello payload");
            return Ok(false);
        }
        let client_version = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        info!("New process version: {}", client_version);

        if client_version != PROTOCOL_VERSION {
            warn!("Version mismatch: client={}, server={}", client_version, PROTOCOL_VERSION);
            let error_msg = format!("Version mismatch: expected {}", PROTOCOL_VERSION);
            send_message(&mut stream, MessageType::ProtocolError, error_msg.as_bytes())?;
            return Ok(false);
        }

        // Send HelloAck with our version
        let version_bytes = PROTOCOL_VERSION.to_le_bytes();
        send_message(&mut stream, MessageType::HelloAck, &version_bytes)?;

        // Wait for RequestSockets
        let (msg_type, _) = recv_message(&mut stream)?;
        if msg_type != MessageType::RequestSockets {
            error!("Expected RequestSockets, got {:?}", msg_type);
            return Ok(false);
        }

        // Send listening sockets via SCM_RIGHTS
        info!("Transferring {} listening socket(s)...", listening_fds.len());
        send_fds(&mut stream, listening_fds)?;

        // Wait for SocketsAck
        let (msg_type, _) = recv_message(&mut stream)?;
        if msg_type != MessageType::SocketsAck {
            error!("Expected SocketsAck, got {:?}", msg_type);
            return Ok(false);
        }
        info!("New process acknowledged socket receipt");

        // Wait for StartDrain
        let (msg_type, _) = recv_message(&mut stream)?;
        if msg_type != MessageType::StartDrain {
            error!("Expected StartDrain, got {:?}", msg_type);
            return Ok(false);
        }

        // Confirm drain started
        send_message(&mut stream, MessageType::DrainStarted, &[])?;
        info!("Takeover complete, starting connection drain");

        Ok(true)
    }
}

impl Drop for TakeoverServer {
    fn drop(&mut self) {
        // Clean up socket file
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Takeover client running in the new process
pub struct TakeoverClient {
    stream: UnixStream,
}

impl TakeoverClient {
    /// Connect to an existing Atlas process for takeover
    pub fn connect<P: AsRef<Path>>(socket_path: P) -> io::Result<Self> {
        let path = socket_path.as_ref();
        info!("Connecting to existing process at {}...", path.display());

        let stream = UnixStream::connect(path)?;
        info!("Connected to existing process for takeover");

        Ok(Self { stream })
    }

    /// Perform the takeover handshake and receive listening sockets
    pub fn perform_takeover(&mut self) -> io::Result<Vec<RawFd>> {
        // Send Hello with our version
        let version_bytes = PROTOCOL_VERSION.to_le_bytes();
        send_message(&mut self.stream, MessageType::Hello, &version_bytes)?;

        // Receive HelloAck
        let (msg_type, payload) = recv_message(&mut self.stream)?;
        match msg_type {
            MessageType::HelloAck => {
                if payload.len() >= 4 {
                    let server_version = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    info!("Server version: {}", server_version);
                }
            }
            MessageType::ProtocolError => {
                let error_msg = String::from_utf8_lossy(&payload);
                return Err(io::Error::new(io::ErrorKind::Other, error_msg.to_string()));
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Expected HelloAck, got {:?}", msg_type),
                ));
            }
        }

        // Request sockets
        send_message(&mut self.stream, MessageType::RequestSockets, &[])?;

        // Receive sockets via SCM_RIGHTS
        let fds = recv_fds(&mut self.stream)?;
        info!("Received {} listening socket(s)", fds.len());

        // Acknowledge receipt
        send_message(&mut self.stream, MessageType::SocketsAck, &[])?;

        Ok(fds)
    }

    /// Signal the old process to start draining connections
    pub fn signal_drain(&mut self) -> io::Result<()> {
        send_message(&mut self.stream, MessageType::StartDrain, &[])?;

        // Wait for confirmation
        let (msg_type, _) = recv_message(&mut self.stream)?;
        if msg_type != MessageType::DrainStarted {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Expected DrainStarted, got {:?}", msg_type),
            ));
        }

        info!("Old process confirmed drain started");
        Ok(())
    }
}

/// Send a message with type and payload
fn send_message(stream: &mut UnixStream, msg_type: MessageType, payload: &[u8]) -> io::Result<()> {
    use std::io::Write;

    let mut header = [0u8; HEADER_SIZE];
    header[0] = msg_type as u8;
    let len = payload.len() as u32;
    header[1..5].copy_from_slice(&len.to_le_bytes());

    stream.write_all(&header)?;
    if !payload.is_empty() {
        stream.write_all(payload)?;
    }
    stream.flush()?;

    debug!("Sent {:?} ({} bytes payload)", msg_type, payload.len());
    Ok(())
}

/// Receive a message
fn recv_message(stream: &mut UnixStream) -> io::Result<(MessageType, Vec<u8>)> {
    use std::io::Read;

    let mut header = [0u8; HEADER_SIZE];
    stream.read_exact(&mut header)?;

    let msg_type = MessageType::try_from(header[0])?;
    let len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;

    let mut payload = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut payload)?;
    }

    debug!("Received {:?} ({} bytes payload)", msg_type, len);
    Ok((msg_type, payload))
}

/// Send file descriptors using SCM_RIGHTS
fn send_fds(stream: &mut UnixStream, fds: &[RawFd]) -> io::Result<()> {
    use libc::{c_void, cmsghdr, iovec, msghdr, CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN, CMSG_SPACE, SCM_RIGHTS, SOL_SOCKET};
    use std::mem;

    if fds.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "No FDs to send"));
    }

    if fds.len() > MAX_FDS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Too many FDs: {} > {}", fds.len(), MAX_FDS),
        ));
    }

    // First send the message header with number of FDs
    let num_fds = fds.len() as u32;
    send_message(stream, MessageType::SocketsTransfer, &num_fds.to_le_bytes())?;

    // Then send FDs via sendmsg with SCM_RIGHTS
    let fd = stream.as_raw_fd();

    // Data buffer (must send at least 1 byte)
    let data = [0u8; 1];
    let mut iov = iovec {
        iov_base: data.as_ptr() as *mut c_void,
        iov_len: data.len(),
    };

    // Control message buffer
    let cmsg_space = unsafe { CMSG_SPACE((fds.len() * mem::size_of::<RawFd>()) as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
    msg.msg_controllen = cmsg_space as _;  // u32 on macOS, usize on Linux

    // Set up the control message
    let cmsg: *mut cmsghdr = unsafe { CMSG_FIRSTHDR(&msg) };
    unsafe {
        (*cmsg).cmsg_level = SOL_SOCKET;
        (*cmsg).cmsg_type = SCM_RIGHTS;
        (*cmsg).cmsg_len = CMSG_LEN((fds.len() * mem::size_of::<RawFd>()) as u32) as _;

        let data_ptr = CMSG_DATA(cmsg) as *mut RawFd;
        for (i, &fd_val) in fds.iter().enumerate() {
            *data_ptr.add(i) = fd_val;
        }
    }

    let result = unsafe { libc::sendmsg(fd, &msg, 0) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    debug!("Sent {} FDs via SCM_RIGHTS", fds.len());
    Ok(())
}

/// Receive file descriptors using SCM_RIGHTS
fn recv_fds(stream: &mut UnixStream) -> io::Result<Vec<RawFd>> {
    use libc::{c_void, cmsghdr, iovec, msghdr, recvmsg, CMSG_DATA, CMSG_FIRSTHDR, CMSG_SPACE, SCM_RIGHTS, SOL_SOCKET};
    use std::mem;

    // First receive the message header with number of FDs
    let (msg_type, payload) = recv_message(stream)?;
    if msg_type != MessageType::SocketsTransfer {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Expected SocketsTransfer, got {:?}", msg_type),
        ));
    }

    if payload.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid payload"));
    }

    let num_fds = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    if num_fds == 0 || num_fds > MAX_FDS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid FD count: {}", num_fds),
        ));
    }

    // Receive FDs via recvmsg with SCM_RIGHTS
    let fd = stream.as_raw_fd();

    // Data buffer
    let mut data = [0u8; 1];
    let mut iov = iovec {
        iov_base: data.as_mut_ptr() as *mut c_void,
        iov_len: data.len(),
    };

    // Control message buffer (sized for expected FDs)
    let cmsg_space = unsafe { CMSG_SPACE((num_fds * mem::size_of::<RawFd>()) as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
    msg.msg_controllen = cmsg_space as _;  // u32 on macOS, usize on Linux

    let result = unsafe { recvmsg(fd, &mut msg, 0) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    // Extract FDs from control message
    let mut fds = Vec::new();
    let cmsg: *mut cmsghdr = unsafe { CMSG_FIRSTHDR(&msg) };

    if !cmsg.is_null() {
        unsafe {
            if (*cmsg).cmsg_level == SOL_SOCKET && (*cmsg).cmsg_type == SCM_RIGHTS {
                let data_ptr = CMSG_DATA(cmsg) as *const RawFd;
                for i in 0..num_fds {
                    fds.push(*data_ptr.add(i));
                }
            }
        }
    }

    if fds.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "No FDs received"));
    }

    debug!("Received {} FDs via SCM_RIGHTS", fds.len());
    Ok(fds)
}

/// Convert a raw FD to a TcpListener
///
/// # Safety
/// The FD must be a valid listening socket
pub unsafe fn fd_to_tcp_listener(fd: RawFd) -> std::net::TcpListener {
    std::net::TcpListener::from_raw_fd(fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::IntoRawFd;

    #[test]
    fn test_takeover_protocol() {
        use std::net::TcpListener;
        use std::thread;

        let socket_path = "/tmp/atlas-takeover-test.sock";

        // Create a test listening socket
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listener_fd = listener.into_raw_fd();

        // Start server in background
        let server_handle = thread::spawn(move || {
            let server = TakeoverServer::new(socket_path).unwrap();
            let result = server.handle_takeover(&[listener_fd]);
            // Clean up the FD
            unsafe { libc::close(listener_fd) };
            result
        });

        // Give server time to start
        thread::sleep(std::time::Duration::from_millis(100));

        // Connect as client
        let mut client = TakeoverClient::connect(socket_path).unwrap();
        let fds = client.perform_takeover().unwrap();
        assert_eq!(fds.len(), 1);

        // Signal drain
        client.signal_drain().unwrap();

        // Clean up received FD
        for fd in fds {
            unsafe { libc::close(fd) };
        }

        // Check server result
        let server_result = server_handle.join().unwrap();
        assert!(server_result.unwrap());
    }
}
