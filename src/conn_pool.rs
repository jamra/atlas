use monoio::net::TcpStream;
use std::cell::RefCell;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::debug;

const MAX_IDLE_PER_HOST: usize = 256;
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

struct PooledConnection {
    stream: TcpStream,
    created_at: Instant,
}

pub struct ConnectionPool {
    pools: RefCell<HashMap<String, Vec<PooledConnection>>>,
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self {
            pools: RefCell::new(HashMap::new()),
        }
    }

    pub async fn get(&self, addr: &str) -> std::io::Result<TcpStream> {
        // Try to get an existing connection
        if let Some(conn) = self.try_get(addr) {
            debug!("Reusing pooled connection to {}", addr);
            return Ok(conn);
        }

        // Create new connection
        debug!("Creating new connection to {}", addr);
        TcpStream::connect(addr).await
    }

    pub fn try_get(&self, addr: &str) -> Option<TcpStream> {
        let mut pools = self.pools.borrow_mut();
        let pool = pools.get_mut(addr)?;

        // Remove expired connections and get a valid one
        let now = Instant::now();
        while let Some(conn) = pool.pop() {
            if now.duration_since(conn.created_at) < IDLE_TIMEOUT {
                return Some(conn.stream);
            }
            // Connection expired, drop it
        }
        None
    }

    pub fn put(&self, addr: &str, stream: TcpStream) {
        let mut pools = self.pools.borrow_mut();

        // Check if pool exists first to avoid String allocation when possible
        if let Some(pool) = pools.get_mut(addr) {
            if pool.len() < MAX_IDLE_PER_HOST {
                pool.push(PooledConnection {
                    stream,
                    created_at: Instant::now(),
                });
            }
        } else {
            // First connection for this host, need to allocate key
            let mut pool = Vec::new();
            pool.push(PooledConnection {
                stream,
                created_at: Instant::now(),
            });
            pools.insert(addr.to_string(), pool);
        }
    }

    pub fn cleanup_expired(&self) {
        let mut pools = self.pools.borrow_mut();
        let now = Instant::now();

        for pool in pools.values_mut() {
            pool.retain(|conn| now.duration_since(conn.created_at) < IDLE_TIMEOUT);
        }

        // Remove empty pools
        pools.retain(|_, pool| !pool.is_empty());
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

// Thread-local connection pool (monoio is thread-per-core)
thread_local! {
    pub static CONN_POOL: ConnectionPool = ConnectionPool::new();
}

pub async fn get_connection(addr: &str) -> std::io::Result<TcpStream> {
    // First try to get from pool (sync operation)
    let cached = CONN_POOL.with(|pool| pool.try_get(addr));

    if let Some(stream) = cached {
        tracing::debug!("Reusing pooled connection to {}", addr);
        return Ok(stream);
    }

    // Create new connection (async operation outside the closure)
    tracing::debug!("Creating new connection to {}", addr);
    TcpStream::connect(addr).await
}

pub fn return_connection(addr: &str, stream: TcpStream) {
    CONN_POOL.with(|pool| pool.put(addr, stream));
}
