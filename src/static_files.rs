//! Static file serving
//!
//! For small files, loads into memory and serves directly.
//! For larger files, streams from disk.

use anyhow::Result;
use monoio::io::{AsyncReadRent, AsyncWriteRentExt};
use monoio::net::TcpStream;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info, warn};

const MAX_HEADERS: usize = 64;
const CACHE_MAX_FILE_SIZE: u64 = 1024 * 1024; // 1MB

/// Cached file content
struct CachedFile {
    content_type: &'static str,
    data: Vec<u8>,
}

/// File cache for small files - shared across connections
pub struct FileCache {
    root: PathBuf,
    cache: std::sync::RwLock<HashMap<String, Arc<CachedFile>>>,
}

impl FileCache {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            cache: std::sync::RwLock::new(HashMap::new()),
        }
    }

    fn get_or_load(&self, path: &str) -> std::io::Result<Arc<CachedFile>> {
        // Check cache first
        {
            let cache = self.cache.read().unwrap();
            if let Some(cached) = cache.get(path) {
                return Ok(Arc::clone(cached));
            }
        }

        // Load file
        let file_path = sanitize_path(&self.root, path);
        let metadata = std::fs::metadata(&file_path)?;

        if metadata.len() > CACHE_MAX_FILE_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "File too large for cache",
            ));
        }

        let data = std::fs::read(&file_path)?;
        let content_type = get_content_type(&file_path);

        let cached = Arc::new(CachedFile { content_type, data });

        // Store in cache
        {
            let mut cache = self.cache.write().unwrap();
            cache.insert(path.to_string(), Arc::clone(&cached));
        }

        info!("Cached file: {} ({} bytes)", path, cached.data.len());
        Ok(cached)
    }
}

/// Serve static files with caching
pub async fn serve_static_files<S>(
    mut client: S,
    cache: Arc<FileCache>,
) -> Result<()>
where
    S: AsyncReadRent + AsyncWriteRentExt,
{
    let mut request_count = 0u64;
    let mut buf = vec![0u8; 4096];

    loop {
        // Read HTTP request
        let (res, b) = client.read(buf).await;
        buf = b;

        let n = match res {
            Ok(0) => {
                debug!("Client closed after {} requests", request_count);
                return Ok(());
            }
            Ok(n) => n,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::ConnectionReset {
                    warn!("Read error: {}", e);
                }
                return Ok(());
            }
        };

        // Parse request
        let (path, keep_alive) = match parse_request(&buf[..n]) {
            Some(p) => p,
            None => {
                let response = b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
                let _ = client.write_all(response.to_vec()).await;
                return Ok(());
            }
        };

        // Serve file
        match cache.get_or_load(&path) {
            Ok(file) => {
                // Build response with pre-allocated capacity
                let header = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: {}\r\n\
                     Content-Length: {}\r\n\
                     Connection: keep-alive\r\n\
                     \r\n",
                    file.content_type,
                    file.data.len()
                );

                // Combine header + body into single write for small files
                let mut response = header.into_bytes();
                response.extend_from_slice(&file.data);

                let (res, _) = client.write_all(response).await;
                if res.is_err() {
                    return Ok(());
                }
                request_count += 1;
            }
            Err(e) => {
                let response = if e.kind() == std::io::ErrorKind::NotFound {
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()
                } else {
                    b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".to_vec()
                };
                let (res, _) = client.write_all(response).await;
                if res.is_err() {
                    return Ok(());
                }
            }
        }

        if !keep_alive {
            return Ok(());
        }
    }
}

fn parse_request(buf: &[u8]) -> Option<(String, bool)> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);

    match req.parse(buf) {
        Ok(httparse::Status::Complete(_)) => {
            let path = req.path?.to_string();
            let mut keep_alive = true;
            for h in req.headers.iter() {
                if h.name.eq_ignore_ascii_case("connection") {
                    if let Ok(s) = std::str::from_utf8(h.value) {
                        keep_alive = !s.eq_ignore_ascii_case("close");
                    }
                }
            }
            Some((path, keep_alive))
        }
        _ => None,
    }
}

fn sanitize_path(root: &Path, request_path: &str) -> PathBuf {
    let path = request_path.split('?').next().unwrap_or("/");
    let path = path.replace("%20", " ");
    let path = path.trim_start_matches('/');

    let path = if path.is_empty() || path.ends_with('/') {
        format!("{}index.html", path)
    } else {
        path.to_string()
    };

    let mut full_path = root.to_path_buf();
    for component in Path::new(&path).components() {
        match component {
            std::path::Component::Normal(c) => full_path.push(c),
            std::path::Component::ParentDir => {}
            _ => {}
        }
    }
    full_path
}

fn get_content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") | Some("htm") => "text/html",
        Some("css") => "text/css",
        Some("js") => "application/javascript",
        Some("json") => "application/json",
        Some("txt") => "text/plain",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        _ => "application/octet-stream",
    }
}
