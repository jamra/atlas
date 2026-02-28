mod buffer_pool;
mod config;
mod conn_pool;
mod http_proxy;
mod ktls;
mod pipe_pool;
mod static_files;
mod tls;

use anyhow::Result;
use arc_swap::ArcSwap;
use buffer_pool::PooledBuffer;
use config::{Config, ProxyMode};
use conn_pool::get_connection;
use http_proxy::proxy_http_connection;
use monoio::io::{AsyncReadRent, AsyncWriteRentExt, Splitable};
use monoio::net::tcp::{TcpOwnedReadHalf, TcpOwnedWriteHalf};
use monoio::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

struct LoadBalancer {
    config: Arc<ArcSwap<Config>>,
    connection_counter: AtomicUsize,
}

impl LoadBalancer {
    fn new(config: Config) -> Self {
        Self {
            config: Arc::new(ArcSwap::from_pointee(config)),
            connection_counter: AtomicUsize::new(0),
        }
    }

    fn select_upstream(&self) -> Option<(String, u16)> {
        let config = self.config.load();
        let upstreams = &config.upstreams;

        if upstreams.is_empty() {
            return None;
        }

        match config.routing.strategy {
            config::Strategy::RoundRobin => {
                let idx = self.connection_counter.fetch_add(1, Ordering::Relaxed);
                let upstream = &upstreams[idx % upstreams.len()];
                Some((upstream.address.clone(), upstream.port))
            }
            config::Strategy::Random => {
                let idx = rand_idx(upstreams.len());
                let upstream = &upstreams[idx];
                Some((upstream.address.clone(), upstream.port))
            }
            config::Strategy::WeightedRoundRobin => {
                let total_weight: u32 = upstreams.iter().map(|u| u.weight).sum();
                let idx = self.connection_counter.fetch_add(1, Ordering::Relaxed);
                let target = (idx as u32) % total_weight;

                let mut cumulative = 0u32;
                for upstream in upstreams {
                    cumulative += upstream.weight;
                    if target < cumulative {
                        return Some((upstream.address.clone(), upstream.port));
                    }
                }
                let upstream = &upstreams[0];
                Some((upstream.address.clone(), upstream.port))
            }
            _ => {
                let upstream = &upstreams[0];
                Some((upstream.address.clone(), upstream.port))
            }
        }
    }

    fn update_config(&self, new_config: Config) {
        self.config.store(Arc::new(new_config));
        info!("Configuration hot-reloaded");
    }

    fn proxy_mode(&self) -> ProxyMode {
        self.config.load().listen.mode.clone()
    }

    fn document_root(&self) -> Option<std::path::PathBuf> {
        self.config.load().listen.root.as_ref().map(|r| std::path::PathBuf::from(r))
    }

    fn tls_config(&self) -> Option<config::TlsConfig> {
        self.config.load().listen.tls.clone()
    }
}

fn rand_idx(max: usize) -> usize {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos() as usize;
    nanos % max
}

/// Zero-copy data transfer using splice (Linux only)
/// Falls back to buffered copy on other platforms
#[cfg(target_os = "linux")]
async fn copy_data_zerocopy(
    mut reader: TcpOwnedReadHalf,
    mut writer: TcpOwnedWriteHalf,
) -> std::io::Result<u64> {
    use monoio::io::splice::{SpliceSource, SpliceDestination};
    use crate::pipe_pool::PooledPipe;

    const PIPE_SIZE: u32 = 65536;

    // Use pooled pipe instead of creating new one each time
    let mut pooled_pipe = PooledPipe::new()?;
    let (pipe_read, pipe_write) = pooled_pipe.get();
    let mut total: u64 = 0;

    loop {
        // Splice from socket to pipe (zero-copy from kernel buffer)
        let spliced = reader.splice_to_pipe(pipe_write, PIPE_SIZE).await?;
        if spliced == 0 {
            break; // EOF
        }

        // Splice from pipe to socket (zero-copy to kernel buffer)
        let mut remaining = spliced;
        while remaining > 0 {
            let written = writer.splice_from_pipe(pipe_read, remaining).await?;
            if written == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "splice write returned 0",
                ));
            }
            remaining -= written;
        }
        total += spliced as u64;
    }

    Ok(total)
}

/// Buffered copy fallback for non-Linux or when splice isn't available
#[cfg(not(target_os = "linux"))]
async fn copy_data_zerocopy(
    mut reader: TcpOwnedReadHalf,
    mut writer: TcpOwnedWriteHalf,
) -> std::io::Result<u64> {
    copy_data_buffered(reader, writer).await
}

/// Buffered data transfer using pooled buffers (fallback)
async fn copy_data_buffered(
    reader: TcpOwnedReadHalf,
    writer: TcpOwnedWriteHalf,
) -> std::io::Result<u64> {
    let mut reader = reader;
    let mut writer = writer;
    let mut pooled = PooledBuffer::new();
    let mut total: u64 = 0;

    loop {
        let buf = pooled.take();
        let (res, b) = reader.read(buf).await;
        pooled.put(b);

        match res {
            Ok(0) => break,
            Ok(n) => {
                let buf = pooled.take();
                let data = buf[..n].to_vec();
                pooled.put(buf);

                let (res, _) = writer.write_all(data).await;
                if res.is_err() {
                    break;
                }
                total += n as u64;
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::ConnectionReset {
                    return Err(e);
                }
                break;
            }
        }
    }
    Ok(total)
}


/// Proxy with zero-copy splice (Linux) or buffered copy (other platforms)
async fn proxy_connection(
    incoming: monoio::net::TcpStream,
    upstream_addr: String,
    upstream_port: u16,
) -> Result<()> {
    let upstream_target = format!("{}:{}", upstream_addr, upstream_port);
    let upstream = get_connection(&upstream_target).await?;

    let (in_read, in_write) = incoming.into_split();
    let (up_read, up_write) = upstream.into_split();

    // Use zero-copy splice on Linux, buffered copy elsewhere
    let client_to_upstream = copy_data_zerocopy(in_read, up_write);
    let upstream_to_client = copy_data_zerocopy(up_read, in_write);

    let (c2u_result, u2c_result) = monoio::join!(client_to_upstream, upstream_to_client);

    debug!(
        "Connection closed: client->upstream {:?}, upstream->client {:?}",
        c2u_result, u2c_result
    );

    Ok(())
}

/// Worker thread running its own monoio runtime
fn run_worker(
    worker_id: usize,
    listen_addr: String,
    lb: Arc<LoadBalancer>,
    total_connections: Arc<AtomicUsize>,
    active_connections: Arc<AtomicUsize>,
    file_cache: Option<Arc<static_files::FileCache>>,
    tls_acceptor: Option<monoio_rustls::TlsAcceptor>,
) {
    // Pin thread to CPU core for better cache locality
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::thread::JoinHandleExt;
        let core_id = worker_id % num_cpus();
        unsafe {
            let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
            libc::CPU_SET(core_id, &mut cpuset);
            libc::pthread_setaffinity_np(
                libc::pthread_self(),
                std::mem::size_of::<libc::cpu_set_t>(),
                &cpuset,
            );
        }
    }

    let mut rt = monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
        .enable_timer()
        .build()
        .expect("Failed to build monoio runtime");

    rt.block_on(async move {
        // Use SO_REUSEPORT to allow multiple threads to accept on same port
        // SO_REUSEPORT must be set BEFORE bind()
        let listener = {
            use socket2::{Domain, Protocol, Socket, Type};
            use std::net::SocketAddr;

            let addr: SocketAddr = listen_addr.parse().expect("Invalid listen address");
            let domain = if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };

            let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
                .expect("Failed to create socket");

            // Set socket options before bind
            socket.set_reuse_address(true).expect("Failed to set SO_REUSEADDR");
            socket.set_reuse_port(true).expect("Failed to set SO_REUSEPORT");
            socket.set_nonblocking(true).expect("Failed to set non-blocking");

            // Bind and listen
            socket.bind(&addr.into()).expect("Failed to bind");
            socket.listen(1024).expect("Failed to listen");

            // Convert to monoio TcpListener
            let std_listener: std::net::TcpListener = socket.into();
            TcpListener::from_std(std_listener).expect("Failed to convert listener")
        };

        info!("Worker {} listening on {}{}", worker_id, listen_addr,
            if tls_acceptor.is_some() { " (TLS)" } else { "" });

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let mode = lb.proxy_mode();
                    let conn_num = total_connections.fetch_add(1, Ordering::Relaxed);
                    let active = active_connections.fetch_add(1, Ordering::Relaxed) + 1;
                    let active_conns = Arc::clone(&active_connections);

                    // Handle TLS if configured
                    if let Some(ref acceptor) = tls_acceptor {
                        let acceptor = acceptor.clone();
                        let cache = file_cache.clone();
                        let upstream = lb.select_upstream();

                        monoio::spawn(async move {
                            // TLS handshake with kTLS attempt on Linux
                            // Note: kTLS is disabled by default as userspace TLS is faster for small payloads
                            // Enable kTLS when serving large files via sendfile for best performance
                            #[cfg(target_os = "linux")]
                            let tls_result = tls::accept_tls_with_ktls(&acceptor, stream, false).await;
                            #[cfg(not(target_os = "linux"))]
                            let tls_result = tls::accept_tls(&acceptor, stream).await
                                .map(tls::TlsResult::Userspace);

                            let tls_result = match tls_result {
                                Ok(r) => r,
                                Err(e) => {
                                    debug!("TLS handshake failed: {}", e);
                                    active_conns.fetch_sub(1, Ordering::Relaxed);
                                    return;
                                }
                            };

                            // Handle based on mode and TLS result type
                            let result = match tls_result {
                                tls::TlsResult::Ktls(tcp_stream) => {
                                    // kTLS enabled - kernel handles encryption
                                    match mode {
                                        ProxyMode::Static => {
                                            if let Some(cache) = cache {
                                                static_files::serve_static_files(tcp_stream, cache).await
                                            } else {
                                                error!("Static mode but no file cache configured");
                                                return;
                                            }
                                        }
                                        ProxyMode::Http => {
                                            if let Some((addr, port)) = upstream {
                                                let target = format!("{}:{}", addr, port);
                                                proxy_http_connection(tcp_stream, target).await
                                            } else {
                                                error!("No upstreams available");
                                                return;
                                            }
                                        }
                                        ProxyMode::Tcp => {
                                            error!("TCP mode not supported with TLS");
                                            return;
                                        }
                                    }
                                }
                                tls::TlsResult::Userspace(tls_stream) => {
                                    // Userspace TLS
                                    match mode {
                                        ProxyMode::Static => {
                                            if let Some(cache) = cache {
                                                static_files::serve_static_files(tls_stream, cache).await
                                            } else {
                                                error!("Static mode but no file cache configured");
                                                return;
                                            }
                                        }
                                        ProxyMode::Http => {
                                            if let Some((addr, port)) = upstream {
                                                let target = format!("{}:{}", addr, port);
                                                proxy_http_connection(tls_stream, target).await
                                            } else {
                                                error!("No upstreams available");
                                                return;
                                            }
                                        }
                                        ProxyMode::Tcp => {
                                            error!("TCP mode not supported with TLS");
                                            return;
                                        }
                                    }
                                }
                            };

                            if let Err(e) = result {
                                warn!("Error: {}", e);
                            }
                            active_conns.fetch_sub(1, Ordering::Relaxed);
                        });
                        continue;
                    }

                    // Non-TLS path (original code)
                    // Handle Static mode separately (no upstream needed)
                    if mode == ProxyMode::Static {
                        if let Some(ref cache) = file_cache {
                            let cache = Arc::clone(cache);
                            debug!("[W{}:#{}] {} -> static (active: {})",
                                worker_id, conn_num, addr, active);

                            monoio::spawn(async move {
                                if let Err(e) = static_files::serve_static_files(stream, cache).await {
                                    warn!("Static file error: {}", e);
                                }
                                active_conns.fetch_sub(1, Ordering::Relaxed);
                            });
                        } else {
                            error!("Static mode but no file cache configured");
                            active_conns.fetch_sub(1, Ordering::Relaxed);
                        }
                        continue;
                    }

                    // Proxy modes need an upstream
                    let upstream = lb.select_upstream();
                    if let Some((upstream_addr, upstream_port)) = upstream {
                        debug!(
                            "[W{}:#{}] {} -> {}:{} (active: {})",
                            worker_id, conn_num, addr, upstream_addr, upstream_port, active
                        );

                        let upstream_target = format!("{}:{}", upstream_addr, upstream_port);

                        monoio::spawn(async move {
                            let result = match mode {
                                ProxyMode::Http => {
                                    proxy_http_connection(stream, upstream_target).await
                                }
                                ProxyMode::Tcp => {
                                    proxy_connection(stream, upstream_addr, upstream_port).await
                                }
                                ProxyMode::Static => unreachable!(),
                            };

                            if let Err(e) = result {
                                warn!("Proxy error: {}", e);
                            }
                            active_conns.fetch_sub(1, Ordering::Relaxed);
                        });
                    } else {
                        error!("No upstreams available");
                        active_conns.fetch_sub(1, Ordering::Relaxed);
                    }
                }
                Err(e) => {
                    error!("Accept error: {}", e);
                }
            }
        }
    });
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1)
}

/// Increase file descriptor limit for high concurrency
fn increase_fd_limit() {
    #[cfg(unix)]
    {
        use std::io;

        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };

        unsafe {
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) == 0 {
                let target = rlim.rlim_max.min(1_000_000);
                if rlim.rlim_cur < target {
                    rlim.rlim_cur = target;
                    if libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) == 0 {
                        info!("Increased fd limit to {}", target);
                    }
                }
            }
        }
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("atlas=info".parse().unwrap()),
        )
        .init();

    // Increase fd limit for high concurrency
    increase_fd_limit();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "atlas.toml".to_string());

    let config = Config::load(&config_path)?;
    let listen_addr = format!("{}:{}", config.listen.address, config.listen.port);

    let num_workers = config.listen.workers.unwrap_or_else(num_cpus);
    let proxy_mode = config.listen.mode.clone();

    info!("Atlas load balancer starting on {}", listen_addr);
    info!("Mode: {:?}", proxy_mode);
    info!("Workers: {} (thread-per-core with SO_REUSEPORT)", num_workers);
    info!(
        "Loaded {} upstream(s): {:?}",
        config.upstreams.len(),
        config.upstreams.iter().map(|u| &u.name).collect::<Vec<_>>()
    );
    info!("Buffer pool: 64KB buffers, 256 per thread");
    info!("Connection pool: 32 idle connections per upstream, 60s timeout");

    let lb = Arc::new(LoadBalancer::new(config));

    // Spawn config watcher in background
    let lb_clone = Arc::clone(&lb);
    let config_path_clone = config_path.clone();
    std::thread::spawn(move || {
        watch_config(config_path_clone, lb_clone);
    });

    // Stats counters shared across workers
    let total_connections = Arc::new(AtomicUsize::new(0));
    let active_connections = Arc::new(AtomicUsize::new(0));

    // Create shared file cache for static mode
    let file_cache: Option<Arc<static_files::FileCache>> = if proxy_mode == ProxyMode::Static {
        let root = lb.document_root().unwrap_or_else(|| {
            std::path::PathBuf::from("/var/www/html")
        });
        info!("Static file root: {}", root.display());
        Some(Arc::new(static_files::FileCache::new(root)))
    } else {
        None
    };

    // Create TLS acceptor if configured
    let tls_acceptor: Option<monoio_rustls::TlsAcceptor> = if let Some(tls_cfg) = lb.tls_config() {
        let server_config = tls::load_tls_config(&tls_cfg.cert, &tls_cfg.key)
            .expect("Failed to load TLS config");
        info!("TLS enabled");
        Some(tls::create_acceptor(server_config))
    } else {
        None
    };

    // Spawn worker threads
    let mut handles = Vec::new();
    for worker_id in 0..num_workers {
        let listen_addr = listen_addr.clone();
        let lb = Arc::clone(&lb);
        let total = Arc::clone(&total_connections);
        let active = Arc::clone(&active_connections);
        let cache = file_cache.clone();
        let tls = tls_acceptor.clone();

        let handle = std::thread::Builder::new()
            .name(format!("atlas-worker-{}", worker_id))
            .spawn(move || {
                run_worker(worker_id, listen_addr, lb, total, active, cache, tls);
            })
            .expect("Failed to spawn worker thread");

        handles.push(handle);
    }

    info!("All {} workers started", num_workers);

    // Wait for all workers (they run forever)
    for handle in handles {
        handle.join().expect("Worker thread panicked");
    }

    Ok(())
}

fn watch_config(config_path: String, lb: Arc<LoadBalancer>) {
    use notify::{Event, RecursiveMode, Watcher};
    use std::sync::mpsc::channel;

    let (tx, rx) = channel();

    let mut watcher =
        notify::recommended_watcher(move |res: std::result::Result<Event, notify::Error>| {
            if let Ok(event) = res {
                if event.kind.is_modify() {
                    let _ = tx.send(());
                }
            }
        })
        .expect("Failed to create file watcher");

    watcher
        .watch(
            std::path::Path::new(&config_path),
            RecursiveMode::NonRecursive,
        )
        .expect("Failed to watch config file");

    info!("Watching {} for changes", config_path);

    for _ in rx {
        std::thread::sleep(std::time::Duration::from_millis(100));
        match Config::load(&config_path) {
            Ok(new_config) => {
                lb.update_config(new_config);
            }
            Err(e) => {
                error!("Failed to reload config: {}", e);
            }
        }
    }
}
