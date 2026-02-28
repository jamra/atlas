# Atlas

A high-performance load balancer and reverse proxy written in Rust, built on [monoio](https://github.com/bytedance/monoio) (io_uring).

## Table of Contents

- [Features](#features)
- [Performance](#performance)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Examples](#examples)
- [Architecture](#architecture)
- [Zero-Downtime Deployments](#zero-downtime-deployments)
- [Building](#building)
- [Requirements](#requirements)
- [License](#license)

## Features

- **io_uring backend** - Uses Linux's io_uring for maximum I/O performance via monoio
- **Thread-per-core architecture** - No cross-thread synchronization, each worker owns its connections
- **HTTP/1.1 reverse proxy** - Full keep-alive support with connection pooling
- **TLS termination** - Using rustls with monoio-rustls (no OpenSSL dependency)
- **Static file serving** - With in-memory caching and zero-copy sendfile
- **Hot config reload** - File watcher for configuration changes without restart
- **Multiple load balancing strategies** - Round-robin, weighted round-robin, random
- **Socket takeover** - Zero-downtime deployments via FD passing (inspired by [Meta's paper](https://research.facebook.com/publications/zero-downtime-release-disruption-free-load-balancing-of-a-multi-billion-user-website/))
- **Graceful shutdown** - Connection draining with configurable timeout

## Performance

All benchmarks performed on Linux with 4 CPU cores using [wrk](https://github.com/wg/wrk) with 4 threads and 100-500 connections.

### Static File Serving (1KB file)

| Connections | Atlas | nginx 1.24 | Difference |
|-------------|-------|------------|------------|
| 100 | 328,000 req/s | 162,000 req/s | **2.0x faster** |
| 500 | 323,000 req/s | 156,000 req/s | **2.1x faster** |

### Reverse Proxy (to nginx backend, 1KB response)

| Connections | Atlas | nginx 1.24 |
|-------------|-------|------------|
| 100 | 164,000 req/s | 157,000 req/s |
| 500 | 144,000 req/s | 142,000 req/s |

### TLS Termination (reverse proxy mode, rustls)

| Mode | Requests/sec | Overhead vs Plain |
|------|--------------|-------------------|
| Plain HTTP | 164,000 | baseline |
| TLS (rustls) | 128,000 | 22% |

### Latency

| Scenario | Average | p99 |
|----------|---------|-----|
| Static files | 0.35ms | 1.2ms |
| Reverse proxy | 0.64ms | 2.1ms |
| TLS proxy | 1.67ms | 5.2ms |

### Why is Atlas fast?

1. **io_uring** - Batches syscalls, reducing kernel transitions
2. **Thread-per-core** - No locks, no cross-thread communication
3. **Zero-copy** - Uses `splice()` and `sendfile()` for data transfer
4. **Connection pooling** - Reuses upstream connections with keep-alive
5. **Buffer pooling** - Thread-local buffer pools eliminate allocation overhead

## Quick Start

```bash
# Build
cargo build --release

# Run with config
./target/release/atlas config.toml
```

Minimal config for reverse proxy:

```toml
[listen]
address = "0.0.0.0"
port = 8080
mode = "http"

[[upstreams]]
name = "backend"
address = "127.0.0.1"
port = 3000

[routing]
strategy = "round_robin"
```

## Configuration

Atlas uses TOML for configuration. See [examples/](examples/) for complete configurations.

### Listen Section

```toml
[listen]
address = "0.0.0.0"      # Bind address
port = 8080              # Bind port
mode = "http"            # http, tcp, or static
workers = 4              # Number of worker threads (default: CPU count)
root = "/var/www/html"   # Document root (static mode only)

# Optional TLS
[listen.tls]
cert = "/path/to/cert.pem"
key = "/path/to/key.pem"
```

### Upstreams Section

```toml
[[upstreams]]
name = "backend"
address = "127.0.0.1"
port = 8081
weight = 1               # For weighted round-robin (default: 1)
```

### Routing Section

```toml
[routing]
strategy = "round_robin"  # round_robin, weighted_round_robin, random
```

### Hot Reload

Atlas watches the config file for changes and automatically reloads:
- Upstream server list
- Load balancing strategy
- Routing rules

Changes take effect immediately without restarting.

## Examples

Complete example configurations with documentation:

| Example | Description |
|---------|-------------|
| [Static Files](examples/static-files/) | Serve static files with caching |
| [Reverse Proxy](examples/reverse-proxy/) | HTTP reverse proxy with load balancing |
| [TLS Termination](examples/tls-termination/) | HTTPS frontend with HTTP backend |
| [Load Balancing](examples/load-balancing/) | Multiple backends with weighted routing |

## Architecture

Atlas follows a **thread-per-core** architecture, eliminating cross-thread synchronization overhead.

```
                    ┌─────────────────────────────────────────────┐
                    │                   Atlas                     │
                    │                                             │
   Clients ────────►│  ┌─────────┐ ┌─────────┐ ┌─────────┐       │
                    │  │Worker 0 │ │Worker 1 │ │Worker 2 │  ...  │
                    │  │(CPU 0)  │ │(CPU 1)  │ │(CPU 2)  │       │
                    │  │         │ │         │ │         │       │
                    │  │ ┌─────┐ │ │ ┌─────┐ │ │ ┌─────┐ │       │
                    │  │ │Buf  │ │ │ │Buf  │ │ │ │Buf  │ │       │
                    │  │ │Pool │ │ │ │Pool │ │ │ │Pool │ │       │
                    │  │ └─────┘ │ │ └─────┘ │ │ └─────┘ │       │
                    │  │ ┌─────┐ │ │ ┌─────┐ │ │ ┌─────┐ │       │
                    │  │ │Conn │ │ │ │Conn │ │ │ │Conn │ │       │
                    │  │ │Pool │ │ │ │Pool │ │ │ │Pool │ │       │
                    │  │ └─────┘ │ │ └─────┘ │ │ └─────┘ │       │
                    │  └────┬────┘ └────┬────┘ └────┬────┘       │
                    │       │          │          │              │
                    └───────┼──────────┼──────────┼──────────────┘
                            │          │          │
                            ▼          ▼          ▼
                    ┌─────────────────────────────────────────────┐
                    │              Backend Servers                │
                    └─────────────────────────────────────────────┘
```

### Key Design Decisions

#### 1. monoio Runtime (io_uring)

Atlas uses [monoio](https://github.com/bytedance/monoio), an async runtime built on io_uring. Unlike epoll-based runtimes (tokio, async-std), io_uring:

- **Batches syscalls** - Multiple operations submitted in one syscall
- **Reduces copies** - Kernel can access user buffers directly
- **Completion-based** - No need to retry operations

On non-Linux systems, monoio falls back to kqueue/epoll.

#### 2. Thread-per-Core with SO_REUSEPORT

Each worker thread:
- Pins to a specific CPU core
- Has its own monoio runtime
- Binds to the same port via `SO_REUSEPORT`
- Maintains thread-local buffer and connection pools

This eliminates:
- Lock contention
- Cache line bouncing
- Cross-thread synchronization

#### 3. Zero-Copy Data Transfer

On Linux, Atlas uses `splice()` to transfer data between sockets without copying through userspace:

```
Client Socket ──splice──► Pipe ──splice──► Backend Socket
```

For static files, `sendfile()` transfers directly from page cache to socket.

#### 4. Connection Pooling

Upstream connections are pooled per-thread with keep-alive:
- 32 idle connections per upstream per worker
- 60-second idle timeout
- Connections reused across requests

#### 5. TLS with rustls

Atlas uses [rustls](https://github.com/rustls/rustls) for TLS:
- No OpenSSL dependency
- Memory-safe implementation
- Modern cipher suites only
- Async integration via monoio-rustls

## Zero-Downtime Deployments

Atlas supports two methods for zero-downtime deployments:

### Socket Takeover (Recommended)

Based on [Meta's Zero Downtime Release paper](https://research.facebook.com/publications/zero-downtime-release-disruption-free-load-balancing-of-a-multi-billion-user-website/), Atlas passes listening socket file descriptors from old process to new process using Unix domain sockets with `SCM_RIGHTS`.

```bash
# 1. New Atlas connects to old process and receives listening sockets
./atlas-new config.toml --takeover

# 2. Old process automatically drains connections (30s timeout)
# 3. Old process exits when drain completes
```

**How it works:**

```
┌──────────────┐                      ┌──────────────┐
│  Old Atlas   │                      │  New Atlas   │
│              │                      │              │
│  Listening   │──── Unix Socket ────►│  Receives    │
│  Socket FDs  │     (SCM_RIGHTS)     │  Socket FDs  │
│              │                      │              │
│  Draining... │                      │  Accepting!  │
└──────────────┘                      └──────────────┘
       │                                     │
       ▼                                     ▼
   Exits after                         Handles all
   drain timeout                       new connections
```

**Options:**
- `--takeover` - Connect to existing process and take over sockets
- `--takeover-socket PATH` - Custom socket path (default: `/tmp/atlas-takeover.sock`)

### SO_REUSEPORT Fallback

If socket takeover isn't available:

```bash
# 1. Start new Atlas (binds alongside old via SO_REUSEPORT)
./atlas-new config.toml &

# 2. Signal old process to drain
kill -TERM $OLD_PID

# 3. Old process drains and exits
```

**Note:** With `SO_REUSEPORT`, there's a brief window where both processes accept connections, which may cause issues with stateful protocols.

### Signals

- `SIGTERM` / `SIGINT` / `SIGQUIT` - Graceful shutdown (drain connections)

## Building

### Development

```bash
cargo build
cargo test
cargo run -- config.toml
```

### Release

```bash
cargo build --release
./target/release/atlas config.toml
```

### Cross-compilation

Atlas performs best on Linux with io_uring. For cross-compilation to Linux:

```bash
# Install target
rustup target add x86_64-unknown-linux-gnu

# Build (may need linker configuration)
cargo build --release --target x86_64-unknown-linux-gnu
```

## Requirements

- **Rust** 1.75+
- **Linux** 5.1+ (for io_uring) - recommended for production
- **macOS/BSD** - supported with kqueue fallback (reduced performance)

### Linux Kernel Features

For best performance on Linux:
- io_uring (kernel 5.1+)
- `splice()` support
- `SO_REUSEPORT` support

## Roadmap

- [ ] HTTP/2 support
- [ ] WebSocket proxying
- [ ] Health checks
- [ ] Metrics endpoint (Prometheus)
- [ ] Rate limiting
- [ ] Request routing (path-based, header-based)
- [ ] Lua/Wasm scripting for custom logic

## License

MIT
