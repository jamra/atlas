# Static File Serving

This example shows how to configure Atlas as a high-performance static file server.

## Configuration

```toml
[listen]
address = "0.0.0.0"
port = 8080
mode = "static"
workers = 4
root = "/var/www/html"
```

See [atlas.toml](atlas.toml) for the complete configuration.

## Features

- **In-memory caching** - Frequently accessed files cached in memory
- **Zero-copy sendfile** - Uses `sendfile()` on Linux for maximum throughput
- **Keep-alive** - Connection reuse for multiple requests

## Setup

1. Create your document root:

```bash
mkdir -p /var/www/html
echo "<h1>Hello from Atlas!</h1>" > /var/www/html/index.html
```

2. Run Atlas:

```bash
atlas examples/static-files/atlas.toml
```

3. Test:

```bash
curl http://localhost:8080/index.html
```

## Performance

On a 4-core Linux machine serving a 1KB file:

| Connections | Requests/sec |
|-------------|--------------|
| 100 | 328,000 |
| 500 | 323,000 |

## With TLS

To serve static files over HTTPS, add TLS configuration:

```toml
[listen]
address = "0.0.0.0"
port = 443
mode = "static"
root = "/var/www/html"

[listen.tls]
cert = "/etc/atlas/cert.pem"
key = "/etc/atlas/key.pem"
```

## Directory Structure

Atlas serves files relative to the `root` directory:

```
/var/www/html/
├── index.html      → http://localhost:8080/index.html
├── css/
│   └── style.css   → http://localhost:8080/css/style.css
└── js/
    └── app.js      → http://localhost:8080/js/app.js
```

## Notes

- Atlas does not currently support directory listing
- No automatic index.html resolution (must request exact path)
- MIME types are detected from file extensions
