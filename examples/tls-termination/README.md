# TLS Termination

This example shows how to configure Atlas for TLS termination - accepting HTTPS from clients and proxying to HTTP backends.

## Configuration

```toml
[listen]
address = "0.0.0.0"
port = 443
mode = "http"

[listen.tls]
cert = "/etc/atlas/cert.pem"
key = "/etc/atlas/key.pem"

[[upstreams]]
name = "backend"
address = "127.0.0.1"
port = 3000

[routing]
strategy = "round_robin"
```

See [atlas.toml](atlas.toml) for the complete configuration.

## Features

- **rustls** - Memory-safe TLS implementation (no OpenSSL)
- **Modern ciphers** - TLS 1.2 and 1.3 only
- **High performance** - 128,000 req/s with ~22% overhead vs plain HTTP
- **Hot reload** - Certificate changes detected automatically

## Setup

### 1. Generate Certificates

For testing, create a self-signed certificate:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/CN=localhost"
```

For production, use Let's Encrypt or your certificate authority.

### 2. Start Backend

```bash
python3 -m http.server 3000
```

### 3. Run Atlas

```bash
atlas examples/tls-termination/atlas.toml
```

### 4. Test

```bash
# With self-signed cert
curl -k https://localhost:443/

# Or add cert to trusted store first
curl https://localhost:443/
```

## Performance

TLS termination adds approximately 22% overhead compared to plain HTTP:

| Mode | Requests/sec | Latency (avg) |
|------|--------------|---------------|
| Plain HTTP | 164,000 | 0.64ms |
| TLS (rustls) | 128,000 | 1.67ms |

## Certificate Formats

Atlas expects PEM-formatted certificates:

**cert.pem** - Certificate chain (server cert first, then intermediates):
```
-----BEGIN CERTIFICATE-----
(server certificate)
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
(intermediate certificate)
-----END CERTIFICATE-----
```

**key.pem** - Private key (RSA or ECDSA):
```
-----BEGIN PRIVATE KEY-----
(private key)
-----END PRIVATE KEY-----
```

## Let's Encrypt

With certbot:

```bash
certbot certonly --standalone -d example.com
```

Then configure:

```toml
[listen.tls]
cert = "/etc/letsencrypt/live/example.com/fullchain.pem"
key = "/etc/letsencrypt/live/example.com/privkey.pem"
```

## Cipher Suites

Atlas uses rustls defaults, which include only modern, secure ciphers:

**TLS 1.3:**
- TLS_AES_256_GCM_SHA384
- TLS_AES_128_GCM_SHA256
- TLS_CHACHA20_POLY1305_SHA256

**TLS 1.2:**
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
- TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256

## Notes

- Atlas terminates TLS and connects to backends over plain HTTP
- No support for mTLS (client certificates) currently
- ALPN for HTTP/2 not yet implemented
