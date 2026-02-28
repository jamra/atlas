//! Kernel TLS (kTLS) support
//!
//! After TLS handshake, offloads symmetric encryption to the Linux kernel.
//! This enables zero-copy with sendfile/splice even for encrypted traffic.

use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

// Linux kTLS constants (from linux/tls.h)
const SOL_TLS: libc::c_int = 282;
const TLS_TX: libc::c_int = 1;
const TLS_RX: libc::c_int = 2;

const TLS_1_2_VERSION: u16 = 0x0303;
const TLS_1_3_VERSION: u16 = 0x0304;

const TLS_CIPHER_AES_GCM_128: u16 = 51;
const TLS_CIPHER_AES_GCM_256: u16 = 52;
const TLS_CIPHER_CHACHA20_POLY1305: u16 = 54;

// Sizes
const TLS_CIPHER_AES_GCM_128_IV_SIZE: usize = 8;
const TLS_CIPHER_AES_GCM_128_KEY_SIZE: usize = 16;
const TLS_CIPHER_AES_GCM_128_SALT_SIZE: usize = 4;
const TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE: usize = 8;

const TLS_CIPHER_AES_GCM_256_IV_SIZE: usize = 8;
const TLS_CIPHER_AES_GCM_256_KEY_SIZE: usize = 32;
const TLS_CIPHER_AES_GCM_256_SALT_SIZE: usize = 4;
const TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE: usize = 8;

/// TLS crypto info header
#[repr(C)]
struct TlsCryptoInfo {
    version: u16,
    cipher_type: u16,
}

/// AES-128-GCM crypto info for kTLS
#[repr(C)]
struct TlsCryptoInfoAesGcm128 {
    info: TlsCryptoInfo,
    iv: [u8; TLS_CIPHER_AES_GCM_128_IV_SIZE],
    key: [u8; TLS_CIPHER_AES_GCM_128_KEY_SIZE],
    salt: [u8; TLS_CIPHER_AES_GCM_128_SALT_SIZE],
    rec_seq: [u8; TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE],
}

/// AES-256-GCM crypto info for kTLS
#[repr(C)]
struct TlsCryptoInfoAesGcm256 {
    info: TlsCryptoInfo,
    iv: [u8; TLS_CIPHER_AES_GCM_256_IV_SIZE],
    key: [u8; TLS_CIPHER_AES_GCM_256_KEY_SIZE],
    salt: [u8; TLS_CIPHER_AES_GCM_256_SALT_SIZE],
    rec_seq: [u8; TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE],
}

/// Check if kTLS is supported by the kernel
pub fn is_ktls_supported() -> bool {
    // Try to load the TLS module
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        // Check if tls module is available
        if let Ok(modules) = fs::read_to_string("/proc/modules") {
            if modules.contains("tls") {
                return true;
            }
        }
        // Try loading the module (might already be loaded or built-in)
        let _ = std::process::Command::new("modprobe")
            .arg("tls")
            .output();
        true // Assume available, will fail at setsockopt if not
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Enable TLS ULP (User Level Protocol) on a socket
#[cfg(target_os = "linux")]
pub fn enable_tls_ulp(fd: RawFd) -> io::Result<()> {
    let ulp_name = b"tls\0";
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_TCP,
            libc::TCP_ULP,
            ulp_name.as_ptr() as *const libc::c_void,
            ulp_name.len() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn enable_tls_ulp(_fd: RawFd) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "kTLS only supported on Linux",
    ))
}

/// Configure kTLS TX (transmit) direction
#[cfg(target_os = "linux")]
pub fn configure_ktls_tx(
    fd: RawFd,
    tls_version: u16,
    cipher: &str,
    key: &[u8],
    iv: &[u8],
    seq: u64,
) -> io::Result<()> {
    match cipher {
        "AES_128_GCM" => {
            if key.len() != TLS_CIPHER_AES_GCM_128_KEY_SIZE + TLS_CIPHER_AES_GCM_128_SALT_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Invalid key length for AES-128-GCM: {}", key.len()),
                ));
            }

            let mut crypto_info = TlsCryptoInfoAesGcm128 {
                info: TlsCryptoInfo {
                    version: tls_version,
                    cipher_type: TLS_CIPHER_AES_GCM_128,
                },
                iv: [0u8; TLS_CIPHER_AES_GCM_128_IV_SIZE],
                key: [0u8; TLS_CIPHER_AES_GCM_128_KEY_SIZE],
                salt: [0u8; TLS_CIPHER_AES_GCM_128_SALT_SIZE],
                rec_seq: seq.to_be_bytes(),
            };

            // Key is salt (4 bytes) + key (16 bytes)
            crypto_info.salt.copy_from_slice(&key[..4]);
            crypto_info.key.copy_from_slice(&key[4..20]);

            // IV is the explicit nonce part
            if iv.len() >= TLS_CIPHER_AES_GCM_128_IV_SIZE {
                crypto_info.iv.copy_from_slice(&iv[..TLS_CIPHER_AES_GCM_128_IV_SIZE]);
            }

            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    SOL_TLS,
                    TLS_TX,
                    &crypto_info as *const _ as *const libc::c_void,
                    std::mem::size_of::<TlsCryptoInfoAesGcm128>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        "AES_256_GCM" => {
            if key.len() != TLS_CIPHER_AES_GCM_256_KEY_SIZE + TLS_CIPHER_AES_GCM_256_SALT_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Invalid key length for AES-256-GCM: {}", key.len()),
                ));
            }

            let mut crypto_info = TlsCryptoInfoAesGcm256 {
                info: TlsCryptoInfo {
                    version: tls_version,
                    cipher_type: TLS_CIPHER_AES_GCM_256,
                },
                iv: [0u8; TLS_CIPHER_AES_GCM_256_IV_SIZE],
                key: [0u8; TLS_CIPHER_AES_GCM_256_KEY_SIZE],
                salt: [0u8; TLS_CIPHER_AES_GCM_256_SALT_SIZE],
                rec_seq: seq.to_be_bytes(),
            };

            crypto_info.salt.copy_from_slice(&key[..4]);
            crypto_info.key.copy_from_slice(&key[4..36]);

            if iv.len() >= TLS_CIPHER_AES_GCM_256_IV_SIZE {
                crypto_info.iv.copy_from_slice(&iv[..TLS_CIPHER_AES_GCM_256_IV_SIZE]);
            }

            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    SOL_TLS,
                    TLS_TX,
                    &crypto_info as *const _ as *const libc::c_void,
                    std::mem::size_of::<TlsCryptoInfoAesGcm256>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("Unsupported cipher: {}", cipher),
            ));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn configure_ktls_tx(
    _fd: RawFd,
    _tls_version: u16,
    _cipher: &str,
    _key: &[u8],
    _iv: &[u8],
    _seq: u64,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "kTLS only supported on Linux",
    ))
}

/// Configure kTLS RX (receive) direction
#[cfg(target_os = "linux")]
pub fn configure_ktls_rx(
    fd: RawFd,
    tls_version: u16,
    cipher: &str,
    key: &[u8],
    iv: &[u8],
    seq: u64,
) -> io::Result<()> {
    match cipher {
        "AES_128_GCM" => {
            if key.len() != TLS_CIPHER_AES_GCM_128_KEY_SIZE + TLS_CIPHER_AES_GCM_128_SALT_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Invalid key length for AES-128-GCM",
                ));
            }

            let mut crypto_info = TlsCryptoInfoAesGcm128 {
                info: TlsCryptoInfo {
                    version: tls_version,
                    cipher_type: TLS_CIPHER_AES_GCM_128,
                },
                iv: [0u8; TLS_CIPHER_AES_GCM_128_IV_SIZE],
                key: [0u8; TLS_CIPHER_AES_GCM_128_KEY_SIZE],
                salt: [0u8; TLS_CIPHER_AES_GCM_128_SALT_SIZE],
                rec_seq: seq.to_be_bytes(),
            };

            crypto_info.salt.copy_from_slice(&key[..4]);
            crypto_info.key.copy_from_slice(&key[4..20]);

            if iv.len() >= TLS_CIPHER_AES_GCM_128_IV_SIZE {
                crypto_info.iv.copy_from_slice(&iv[..TLS_CIPHER_AES_GCM_128_IV_SIZE]);
            }

            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    SOL_TLS,
                    TLS_RX,
                    &crypto_info as *const _ as *const libc::c_void,
                    std::mem::size_of::<TlsCryptoInfoAesGcm128>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        "AES_256_GCM" => {
            if key.len() != TLS_CIPHER_AES_GCM_256_KEY_SIZE + TLS_CIPHER_AES_GCM_256_SALT_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Invalid key length for AES-256-GCM",
                ));
            }

            let mut crypto_info = TlsCryptoInfoAesGcm256 {
                info: TlsCryptoInfo {
                    version: tls_version,
                    cipher_type: TLS_CIPHER_AES_GCM_256,
                },
                iv: [0u8; TLS_CIPHER_AES_GCM_256_IV_SIZE],
                key: [0u8; TLS_CIPHER_AES_GCM_256_KEY_SIZE],
                salt: [0u8; TLS_CIPHER_AES_GCM_256_SALT_SIZE],
                rec_seq: seq.to_be_bytes(),
            };

            crypto_info.salt.copy_from_slice(&key[..4]);
            crypto_info.key.copy_from_slice(&key[4..36]);

            if iv.len() >= TLS_CIPHER_AES_GCM_256_IV_SIZE {
                crypto_info.iv.copy_from_slice(&iv[..TLS_CIPHER_AES_GCM_256_IV_SIZE]);
            }

            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    SOL_TLS,
                    TLS_RX,
                    &crypto_info as *const _ as *const libc::c_void,
                    std::mem::size_of::<TlsCryptoInfoAesGcm256>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("Unsupported cipher: {}", cipher),
            ));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn configure_ktls_rx(
    _fd: RawFd,
    _tls_version: u16,
    _cipher: &str,
    _key: &[u8],
    _iv: &[u8],
    _seq: u64,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "kTLS only supported on Linux",
    ))
}

/// Get TLS version constant from rustls version
pub fn tls_version_to_const(version: rustls::ProtocolVersion) -> u16 {
    match version {
        rustls::ProtocolVersion::TLSv1_2 => TLS_1_2_VERSION,
        rustls::ProtocolVersion::TLSv1_3 => TLS_1_3_VERSION,
        _ => TLS_1_3_VERSION, // Default to 1.3
    }
}

/// Get cipher name from rustls cipher suite
pub fn cipher_suite_to_name(suite: rustls::CipherSuite) -> Option<&'static str> {
    match suite {
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256 => Some("AES_128_GCM"),
        rustls::CipherSuite::TLS13_AES_256_GCM_SHA384 => Some("AES_256_GCM"),
        rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => Some("AES_128_GCM"),
        rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => Some("AES_256_GCM"),
        rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => Some("AES_128_GCM"),
        rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => Some("AES_256_GCM"),
        _ => None, // ChaCha20-Poly1305 and others not yet supported
    }
}
