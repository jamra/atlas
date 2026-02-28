//! TLS support using monoio-rustls
//!
//! Provides async TLS streams compatible with monoio runtime.
//! Supports kTLS (kernel TLS) offload on Linux for better performance.

use monoio::net::TcpStream;
use monoio_rustls::{ServerTlsStream, TlsAcceptor};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::fs::File;
use std::io::{self, BufReader};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::ktls;

pub type TlsStream = ServerTlsStream<TcpStream>;

/// Result of TLS accept - either kTLS-enabled raw stream or userspace TLS stream
pub enum TlsResult {
    /// kTLS enabled - use raw TcpStream (kernel handles encryption)
    Ktls(TcpStream),
    /// Userspace TLS - use monoio-rustls stream
    Userspace(TlsStream),
}

/// Load TLS configuration from certificate and key files
pub fn load_tls_config(cert_path: &str, key_path: &str) -> io::Result<Arc<ServerConfig>> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Enable secret extraction for kTLS
    config.enable_secret_extraction = true;

    info!(
        "Loaded TLS config: cert={}, key={}",
        cert_path, key_path
    );

    Ok(Arc::new(config))
}

/// Create a TLS acceptor from config
pub fn create_acceptor(config: Arc<ServerConfig>) -> TlsAcceptor {
    TlsAcceptor::from(config)
}

/// Accept a TLS connection (userspace only)
pub async fn accept_tls(
    acceptor: &TlsAcceptor,
    stream: TcpStream,
) -> io::Result<TlsStream> {
    acceptor
        .accept(stream)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}

/// Accept TLS connection with kTLS offload when possible
/// Falls back to userspace TLS if kTLS is not available or fails
pub async fn accept_tls_with_ktls(
    acceptor: &TlsAcceptor,
    stream: TcpStream,
    try_ktls: bool,
) -> io::Result<TlsResult> {
    // If kTLS not requested or not on Linux, use userspace TLS
    #[cfg(not(target_os = "linux"))]
    {
        let tls_stream = acceptor
            .accept(stream)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        return Ok(TlsResult::Userspace(tls_stream));
    }

    #[cfg(target_os = "linux")]
    {
        // First do the TLS handshake
        let tls_stream = acceptor
            .accept(stream)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        if !try_ktls {
            return Ok(TlsResult::Userspace(tls_stream));
        }

        // Try to enable kTLS - on failure, connection is dropped
        match try_enable_ktls(tls_stream) {
            Ok(tcp_stream) => {
                debug!("kTLS enabled successfully");
                Ok(TlsResult::Ktls(tcp_stream))
            }
            Err(e) => {
                // kTLS failed - connection was consumed and is now invalid
                // Return error so caller can accept a new connection
                warn!("kTLS setup failed, connection dropped: {}", e);
                Err(e)
            }
        }
    }
}

/// Extract key and IV from ConnectionTrafficSecrets enum
/// Returns (combined_key, iv) where combined_key = salt (4 bytes) + key
/// This matches the format expected by configure_ktls_tx/rx
#[cfg(target_os = "linux")]
fn extract_aes_gcm_secrets(
    secrets: &rustls::ConnectionTrafficSecrets,
) -> Result<(Vec<u8>, Vec<u8>), io::Error> {
    use rustls::ConnectionTrafficSecrets;
    match secrets {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
            // IV is 12 bytes: first 4 = salt, last 8 = explicit nonce
            // kTLS expects key = salt (4) + key (16) = 20 bytes
            let mut combined_key = Vec::with_capacity(4 + key.as_ref().len());
            combined_key.extend_from_slice(&iv.as_ref()[..4]); // salt
            combined_key.extend_from_slice(key.as_ref());       // key
            // IV for kTLS is the last 8 bytes (explicit nonce)
            let explicit_iv = iv.as_ref()[4..].to_vec();
            Ok((combined_key, explicit_iv))
        }
        ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
            // Same layout: salt (4) + key (32) = 36 bytes
            let mut combined_key = Vec::with_capacity(4 + key.as_ref().len());
            combined_key.extend_from_slice(&iv.as_ref()[..4]); // salt
            combined_key.extend_from_slice(key.as_ref());       // key
            let explicit_iv = iv.as_ref()[4..].to_vec();
            Ok((combined_key, explicit_iv))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Only AES-GCM ciphers are supported for kTLS",
        )),
    }
}

/// Try to enable kTLS on a TLS stream
/// Returns the raw TcpStream on success, or an error on failure
/// Note: On failure, the connection is effectively closed
#[cfg(target_os = "linux")]
fn try_enable_ktls(tls_stream: TlsStream) -> Result<TcpStream, io::Error> {
    use monoio_rustls::TlsStream as GenericTlsStream;

    // Convert ServerTlsStream to generic TlsStream to access into_parts
    let generic_stream: GenericTlsStream<TcpStream> = tls_stream.into();

    // Extract the parts - this consumes the stream
    let (tcp_stream, connection) = generic_stream.into_parts();
    let fd = tcp_stream.as_raw_fd();

    // Get connection info before extracting secrets
    let protocol_version = connection.protocol_version();
    let cipher_suite = connection.negotiated_cipher_suite();

    // Get TLS version
    let tls_version = match protocol_version {
        Some(v) => ktls::tls_version_to_const(v),
        None => {
            return Err(io::Error::new(io::ErrorKind::Other, "Unknown TLS version"));
        }
    };

    // Get cipher name
    let cipher_name = match cipher_suite {
        Some(suite) => match ktls::cipher_suite_to_name(suite.suite()) {
            Some(name) => name,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Unsupported cipher: {:?}", suite),
                ));
            }
        },
        None => {
            return Err(io::Error::new(io::ErrorKind::Other, "No cipher suite"));
        }
    };

    // Try to extract secrets
    let secrets = match connection.dangerous_extract_secrets() {
        Ok(s) => s,
        Err(e) => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Secret extraction failed: {:?}", e),
            ));
        }
    };

    // Enable TLS ULP on the socket
    ktls::enable_tls_ulp(fd)?;

    // Extract key/iv from ConnectionTrafficSecrets enum
    // secrets.tx and secrets.rx are tuples of (seq: u64, ConnectionTrafficSecrets)
    let (tx_seq, tx_traffic_secrets) = &secrets.tx;
    let (tx_key, tx_iv) = extract_aes_gcm_secrets(tx_traffic_secrets)?;

    ktls::configure_ktls_tx(
        fd,
        tls_version,
        cipher_name,
        &tx_key,
        &tx_iv,
        *tx_seq,
    )?;

    let (rx_seq, rx_traffic_secrets) = &secrets.rx;
    let (rx_key, rx_iv) = extract_aes_gcm_secrets(rx_traffic_secrets)?;

    ktls::configure_ktls_rx(
        fd,
        tls_version,
        cipher_name,
        &rx_key,
        &rx_iv,
        *rx_seq,
    )?;

    info!("kTLS enabled: {} {:?}", cipher_name, protocol_version);
    Ok(tcp_stream)
}

/// Load certificates from PEM file
fn load_certs(path: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(Path::new(path))?;
    let mut reader = BufReader::new(file);

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;

    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "No certificates found in file",
        ));
    }

    Ok(certs)
}

/// Load private key from PEM file
fn load_private_key(path: &str) -> io::Result<PrivateKeyDer<'static>> {
    let file = File::open(Path::new(path))?;
    let mut reader = BufReader::new(file);

    // Try to read any type of private key
    loop {
        match rustls_pemfile::read_one(&mut reader)? {
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => {
                return Ok(PrivateKeyDer::Pkcs1(key));
            }
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => {
                return Ok(PrivateKeyDer::Pkcs8(key));
            }
            Some(rustls_pemfile::Item::Sec1Key(key)) => {
                return Ok(PrivateKeyDer::Sec1(key));
            }
            Some(_) => continue, // Skip other items (certs, etc)
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "No private key found in file",
                ));
            }
        }
    }
}
