# Reverse Proxy

This example shows how to configure Atlas as an HTTP reverse proxy with connection pooling and keep-alive support.

## Configuration

```toml
[listen]
address = "0.0.0.0"
port = 8080
mode = "http"
workers = 4

[[upstreams]]
name = "backend"
address = "127.0.0.1"
port = 3000

[routing]
strategy = "round_robin"
```

See [atlas.toml](atlas.toml) for the complete configuration.

## Features

- **HTTP/1.1 proxy** - Full HTTP/1.1 support with chunked encoding
- **Keep-alive** - Both client-side and upstream connection reuse
- **Connection pooling** - 32 idle connections per upstream per worker
- **Load balancing** - Round-robin, weighted, or random distribution
- **Header forwarding** - Preserves original headers

## Setup

1. Start your backend server:

```bash
# Example: Simple Python server
python3 -m http.server 3000

# Or Node.js
node -e "require('http').createServer((req,res) => res.end('Hello')).listen(3000)"
```

2. Run Atlas:

```bash
atlas examples/reverse-proxy/atlas.toml
```

3. Test:

```bash
curl http://localhost:8080/
```

## Multiple Backends

For load balancing across multiple backends:

```toml
[[upstreams]]
name = "backend1"
address = "10.0.0.1"
port = 3000

[[upstreams]]
name = "backend2"
address = "10.0.0.2"
port = 3000

[[upstreams]]
name = "backend3"
address = "10.0.0.3"
port = 3000

[routing]
strategy = "round_robin"
```

## Performance

On a 4-core Linux machine proxying to nginx (1KB response):

| Connections | Requests/sec | Latency (avg) |
|-------------|--------------|---------------|
| 100 | 164,000 | 0.64ms |
| 500 | 144,000 | 3.5ms |

## Connection Pooling

Atlas maintains a pool of idle connections to each upstream:

- **Pool size:** 32 connections per upstream per worker
- **Idle timeout:** 60 seconds
- **Keep-alive:** Enabled by default

This eliminates TCP handshake overhead for subsequent requests.

## Headers

Atlas forwards all headers from the client to the backend. Currently, it does not add `X-Forwarded-For` or similar headers automatically.

## TCP Mode

For non-HTTP protocols, use TCP mode:

```toml
[listen]
mode = "tcp"
```

In TCP mode, Atlas acts as a layer 4 proxy without HTTP parsing.
