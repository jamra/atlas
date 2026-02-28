# SSL/TLS Implementation Plan

## Goal
Add high-performance TLS termination to Atlas with minimal overhead.

## Approach: kTLS First, rustls Fallback

### Phase 1: kTLS (Kernel TLS)

kTLS offloads symmetric encryption to the kernel after userspace handshake. This enables zero-copy with sendfile/splice even for encrypted traffic.

**How it works:**
1. Perform TLS handshake in userspace (using rustls or OpenSSL)
2. Extract session keys after handshake completes
3. Call `setsockopt(SO_TLS)` to enable kernel TLS on the socket
4. Pass cipher keys to kernel via `setsockopt(TLS_TX)` / `setsockopt(TLS_RX)`
5. Kernel handles record encryption/decryption transparently
6. Regular read/write (and splice/sendfile) now work on encrypted socket

**Requirements:**
- Linux 4.13+ (TLS_TX), 4.17+ (TLS_RX)
- `CONFIG_TLS=y` in kernel
- Supported ciphers: AES-GCM-128, AES-GCM-256, ChaCha20-Poly1305

**Implementation steps:**
1. Add `rustls` for TLS handshake
2. After handshake, extract `ClientKey`, `ServerKey`, `ClientIV`, `ServerIV`
3. Use `libc::setsockopt` with `SOL_TLS` to configure kernel TLS
4. Continue using monoio's normal async read/write

**Crates:**
- `rustls` - TLS handshake
- `libc` - setsockopt calls for kTLS setup

**Code outline:**
```rust
// After TLS handshake completes
fn enable_ktls(fd: RawFd, cipher_info: &CipherInfo) -> io::Result<()> {
    // Enable TLS on socket
    let mode: libc::c_int = 1;
    unsafe {
        libc::setsockopt(fd, SOL_TLS, TLS_TX, &mode, size_of_val(&mode));
    }

    // Set cipher keys for TX
    let crypto_info = tls12_crypto_info_aes_gcm_128 {
        info: tls_crypto_info { version: TLS_1_2_VERSION, cipher_type: TLS_CIPHER_AES_GCM_128 },
        iv: cipher_info.iv,
        key: cipher_info.key,
        salt: cipher_info.salt,
        rec_seq: cipher_info.seq,
    };
    unsafe {
        libc::setsockopt(fd, SOL_TLS, TLS_TX, &crypto_info, size_of_val(&crypto_info));
    }
    Ok(())
}
```

### Phase 2: Fallback to monoio-rustls

If kTLS is unavailable (older kernel, unsupported cipher, non-Linux):

**Implementation:**
- Use `monoio-rustls` crate for async TLS streams
- Wraps monoio `TcpStream` with TLS encryption
- All encryption in userspace

**Crates:**
- `monoio-rustls` - Async TLS for monoio runtime
- `rustls-pemfile` - Parse PEM certificates

**Code outline:**
```rust
use monoio_rustls::{TlsAcceptor, TlsStream};

let acceptor = TlsAcceptor::from(Arc::new(server_config));
let tls_stream: TlsStream<TcpStream> = acceptor.accept(tcp_stream).await?;
// Use tls_stream like normal TcpStream
```

## Configuration

```toml
[listen]
address = "0.0.0.0"
port = 443
mode = "http"

[tls]
cert = "/etc/ssl/certs/server.crt"
key = "/etc/ssl/private/server.key"
# Optional: prefer kTLS when available (default: true)
prefer_ktls = true
```

## Performance Expectations

| Mode | Overhead | Notes |
|------|----------|-------|
| kTLS | ~5-10% | Hardware AES-NI, zero-copy preserved |
| rustls | ~15-25% | Userspace encryption, still fast |
| OpenSSL | ~10-20% | Fastest userspace, but C dependency |

## Testing Plan

1. Unit tests for TLS handshake
2. Integration tests with self-signed certs
3. Benchmark: HTTPS vs HTTP throughput
4. Test cipher negotiation (TLS 1.2, 1.3)
5. Test kTLS fallback when kernel doesn't support

## References

- [Kernel TLS documentation](https://www.kernel.org/doc/html/latest/networking/tls.html)
- [Cloudflare kTLS blog](https://blog.cloudflare.com/optimizing-tcp-for-high-throughput-and-low-latency/)
- [rustls docs](https://docs.rs/rustls/latest/rustls/)
- [monoio-rustls](https://github.com/bytedance/monoio/tree/master/monoio-rustls)
