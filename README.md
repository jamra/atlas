# Atlas

A high-performance load balancer and reverse proxy written in Rust, built on [monoio](https://github.com/bytedance/monoio) (io_uring).

## Features

- **io_uring backend** - Uses Linux's io_uring for maximum I/O performance
- **Thread-per-core architecture** - No cross-thread synchronization, each worker owns its connections
- **HTTP/1.1 reverse proxy** - Full keep-alive support with connection pooling
- **TLS termination** - Using rustls with monoio-rustls
- **Static file serving** - With in-memory caching and zero-copy sendfile
- **Hot config reload** - File watcher for configuration changes
- **Multiple load balancing strategies** - Round-robin, random, least connections
- **Socket takeover** - Zero-downtime deploys via FD passing (inspired by Meta's paper)

## Performance

Benchmarked on Linux (4 CPU cores) using wrk with 4 threads.

### Static File Serving (1KB file)

| Connections | Atlas | nginx | Difference |
|-------------|-------|-------|------------|
| 100 | 328,000 req/s | 162,000 req/s | **2x faster** |
| 500 | 323,000 req/s | 156,000 req/s | **2x faster** |

### Reverse Proxy (to nginx backend, 1KB response)

| Connections | Atlas | nginx |
|-------------|-------|-------|
| 100 | 164,000 req/s | 157,000 req/s |
| 500 | 144,000 req/s | 142,000 req/s |

### TLS Termination (reverse proxy mode)

| Mode | Requests/sec | Overhead |
|------|--------------|----------|
| Plain HTTP | 164,000 | baseline |
| TLS (rustls) | 128,000 | 22% |

### Latency

| Scenario | Atlas (avg) | Atlas (p99) |
|----------|-------------|-------------|
| Static files | 0.35ms | 1.2ms |
| Reverse proxy | 0.64ms | 2.1ms |
| TLS proxy | 1.67ms | 5.2ms |

## Building

```bash
cargo build --release
```

## Usage

```bash
./target/release/atlas config.toml
```

## Configuration

```toml
[listen]
address = "0.0.0.0"
port = 8080
mode = "http"  # http, tcp, or static
workers = 4

# Optional TLS
[listen.tls]
cert = "/path/to/cert.pem"
key = "/path/to/key.pem"

[[upstreams]]
name = "backend"
address = "127.0.0.1"
port = 8081

[routing]
strategy = "round_robin"  # round_robin, random, least_connections

# For static file serving
[static_files]
root = "/var/www/html"
```

## Hot Reload

Atlas watches the config file for changes and automatically reloads:
- Upstream server list
- Load balancing strategy
- Routing rules

Changes take effect immediately without restarting.

## Zero-Downtime Deployments

Atlas supports two methods for zero-downtime deployments:

### Socket Takeover (Recommended)

Based on [Meta's Zero Downtime Release paper](https://research.facebook.com/publications/zero-downtime-release-disruption-free-load-balancing-of-a-multi-billion-user-website/), Atlas can pass listening socket file descriptors from an old process to a new process via Unix domain sockets with `SCM_RIGHTS`. This ensures no connections are dropped during deployment.

```bash
# 1. New Atlas connects to old process and takes over listening sockets
./atlas-new config.toml --takeover

# 2. Old process automatically starts draining connections (30s timeout)
# 3. Old process exits when drain completes
```

The `--takeover` flag tells the new process to connect to the existing Atlas via a Unix socket (default: `/tmp/atlas-takeover.sock`) and receive the listening socket FDs. The old process then gracefully drains existing connections while the new process handles all new connections.

Options:
- `--takeover` - Connect to existing process and take over sockets
- `--takeover-socket PATH` - Custom path for takeover socket (default: `/tmp/atlas-takeover.sock`)

### SO_REUSEPORT (Fallback)

If socket takeover isn't available, you can use `SO_REUSEPORT`:

```bash
# 1. Start new Atlas version (binds alongside old via SO_REUSEPORT)
./atlas-new config.toml &

# 2. Signal old process to drain
kill -TERM $OLD_PID

# 3. Old process stops accepting, drains connections (30s timeout), exits
```

Note: With `SO_REUSEPORT`, there's a brief window where both processes accept connections, which may cause issues with stateful protocols.

### Signals

- `SIGTERM` / `SIGINT` / `SIGQUIT` - Graceful shutdown (drain connections)

## Architecture

- **monoio runtime** - Async runtime using io_uring on Linux, falling back to epoll/kqueue elsewhere
- **Thread-local pools** - Buffer pools and connection pools are thread-local to avoid contention
- **Zero-copy where possible** - Uses splice/sendfile for static files
- **Generic handlers** - HTTP proxy and static file handlers work with both plain TCP and TLS streams

## Requirements

- Rust 1.75+
- Linux (for io_uring) or macOS/BSD (falls back to kqueue)

## License

MIT
