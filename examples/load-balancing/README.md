# Load Balancing

This example shows how to configure Atlas for load balancing across multiple backend servers.

## Configuration

```toml
[listen]
address = "0.0.0.0"
port = 8080
mode = "http"

[[upstreams]]
name = "backend1"
address = "10.0.0.1"
port = 3000
weight = 3

[[upstreams]]
name = "backend2"
address = "10.0.0.2"
port = 3000
weight = 2

[[upstreams]]
name = "backend3"
address = "10.0.0.3"
port = 3000
weight = 1

[routing]
strategy = "weighted_round_robin"
```

See [atlas.toml](atlas.toml) for the complete configuration.

## Strategies

### Round Robin

Distributes requests evenly across all backends in order.

```toml
[routing]
strategy = "round_robin"
```

Request distribution: A → B → C → A → B → C → ...

### Weighted Round Robin

Distributes requests proportionally based on weights.

```toml
[[upstreams]]
name = "powerful-server"
address = "10.0.0.1"
port = 3000
weight = 3

[[upstreams]]
name = "small-server"
address = "10.0.0.2"
port = 3000
weight = 1

[routing]
strategy = "weighted_round_robin"
```

Request distribution: powerful-server gets 3x more requests than small-server.

### Random

Randomly selects a backend for each request.

```toml
[routing]
strategy = "random"
```

Useful when backends have equal capacity and you want to avoid coordination.

## Setup

1. Start multiple backends:

```bash
# Terminal 1
PORT=3001 node -e "require('http').createServer((req,res) => res.end('Server 1')).listen(3001)"

# Terminal 2
PORT=3002 node -e "require('http').createServer((req,res) => res.end('Server 2')).listen(3002)"

# Terminal 3
PORT=3003 node -e "require('http').createServer((req,res) => res.end('Server 3')).listen(3003)"
```

2. Run Atlas:

```bash
atlas examples/load-balancing/atlas.toml
```

3. Test:

```bash
# Make multiple requests to see distribution
for i in {1..10}; do curl -s http://localhost:8080/; echo; done
```

## Hot Reload

Backends can be added or removed without restart:

1. Edit the config file to add/remove upstreams
2. Atlas detects the change and reloads automatically
3. New requests use the updated backend list

```bash
# Add a new backend to atlas.toml while Atlas is running
echo '
[[upstreams]]
name = "backend4"
address = "10.0.0.4"
port = 3000
' >> atlas.toml

# Atlas logs: "Configuration hot-reloaded"
```

## Connection Behavior

- Each worker maintains its own connection pool to each upstream
- Connections are reused with HTTP keep-alive
- If a backend is unreachable, the connection fails (no automatic retry to another backend)

## Planned Features

The following features are on the roadmap:

- **Health checks** - Automatically remove unhealthy backends
- **Least connections** - Route to backend with fewest active connections
- **Sticky sessions** - Route same client to same backend
- **Circuit breaker** - Stop sending to failing backends temporarily
