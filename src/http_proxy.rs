use crate::buffer_pool::{get_buffer, return_buffer};
use crate::conn_pool::{get_connection, return_connection};
use anyhow::Result;
use monoio::io::{AsyncReadRent, AsyncWriteRentExt};
use monoio::net::TcpStream;
use tracing::{debug, warn};

const MAX_HEADERS: usize = 64;

/// HTTP/1.1 aware proxy with TRUE single-buffering (no copies for common case)
///
/// Key insight: Most HTTP requests/responses complete in ONE read.
/// - Typical HTTP request: 100-500 bytes
/// - Our buffer: 64KB
///
/// So for 99%+ of requests:
/// 1. read() fills buffer with complete request
/// 2. Parse headers in-place
/// 3. write() sends the SAME buffer to upstream
/// 4. NO COPY!
pub async fn proxy_http_connection<S>(
    mut client: S,
    upstream_addr: String,
) -> Result<()>
where
    S: AsyncReadRent + AsyncWriteRentExt,
{
    let mut request_count = 0u64;

    loop {
        // === Read request ===
        // Get a buffer - we'll try to use this same buffer for write
        let mut buf = get_buffer();

        // First read - most requests complete here
        let (res, mut buf) = client.read(buf).await;
        let n = match res {
            Ok(0) => {
                return_buffer(buf);
                debug!("Client closed after {} requests", request_count);
                return Ok(());
            }
            Ok(n) => n,
            Err(e) => {
                return_buffer(buf);
                if e.kind() != std::io::ErrorKind::ConnectionReset {
                    warn!("Read error: {}", e);
                }
                return Ok(());
            }
        };

        // Parse headers
        let (headers_end, content_length, keep_alive) = match try_parse_request(&buf[..n]) {
            Some((end, cl, ka)) => (end, cl, ka),
            None => {
                // Incomplete headers in first read - need slow path
                // This is rare for normal HTTP requests
                let result = read_complete_request(&mut client, buf, n).await;
                match result {
                    Ok((b, end, cl, ka)) => {
                        buf = b;
                        (end, cl, ka)
                    }
                    Err(_) => return Ok(()),
                }
            }
        };

        let request_len = headers_end + content_length;

        // Check if we have complete request
        if n < request_len {
            // Need to read more body - slow path
            let result = read_remaining(&mut client, buf, n, request_len).await;
            match result {
                Ok(b) => buf = b,
                Err(_) => return Ok(()),
            }
        } else {
            // Truncate to exact request size
            buf.truncate(request_len);
        }

        // === Forward request to upstream ===
        // Write the SAME buffer we read into - ZERO COPY for common case!
        let (mut upstream, buf) = {
            let mut conn = get_connection(&upstream_addr).await?;
            let (res, data) = conn.write_all(buf).await;
            match res {
                Ok(_) => (conn, data),
                Err(_) => {
                    debug!("Stale connection, retrying");
                    let mut fresh = TcpStream::connect(&upstream_addr).await?;
                    let (res, data) = fresh.write_all(data).await;
                    if res.is_err() {
                        warn!("Write to fresh upstream failed");
                        return Ok(());
                    }
                    (fresh, data)
                }
            }
        };

        // Reuse buffer for response (just reset length, keep capacity)
        return_buffer(buf);
        let mut buf = get_buffer();

        // === Read response ===
        let (res, mut buf) = upstream.read(buf).await;
        let n = match res {
            Ok(0) => {
                return_buffer(buf);
                return Ok(());
            }
            Ok(n) => n,
            Err(_) => {
                return_buffer(buf);
                return Ok(());
            }
        };

        // Parse response headers
        let (headers_end, content_length, chunked, upstream_keep_alive) = match try_parse_response(&buf[..n]) {
            Some((end, cl, ch, ka)) => (end, cl, ch, ka),
            None => {
                // Incomplete headers - slow path
                let result = read_complete_response(&mut upstream, buf, n).await;
                match result {
                    Ok((b, end, cl, ch, ka)) => {
                        buf = b;
                        (end, cl, ch, ka)
                    }
                    Err(_) => return Ok(()),
                }
            }
        };

        // Check if complete response
        if chunked {
            // Chunked encoding - need to find end marker
            if !has_chunked_end(&buf[..n]) {
                let result = read_chunked_response(&mut upstream, buf, n).await;
                match result {
                    Ok(b) => buf = b,
                    Err(_) => return Ok(()),
                }
            } else {
                buf.truncate(n);
            }
        } else {
            let response_len = headers_end + content_length;
            if n < response_len {
                let result = read_remaining(&mut upstream, buf, n, response_len).await;
                match result {
                    Ok(b) => buf = b,
                    Err(_) => return Ok(()),
                }
            } else {
                buf.truncate(response_len);
            }
        }

        // === Send response to client ===
        // Write the SAME buffer - ZERO COPY!
        let (res, buf) = client.write_all(buf).await;
        return_buffer(buf);

        if res.is_err() {
            return Ok(());
        }

        request_count += 1;

        // Only return connection to pool if upstream allows keep-alive
        if upstream_keep_alive {
            return_connection(&upstream_addr, upstream);
        }
        // else: drop upstream connection (it will close)

        if !keep_alive {
            debug!("Connection close after {} requests", request_count);
            return Ok(());
        }
    }
}

/// Slow path: read more data when headers don't fit in first read
async fn read_complete_request<S: AsyncReadRent>(
    client: &mut S,
    mut buf: Vec<u8>,
    mut total: usize,
) -> Result<(Vec<u8>, usize, usize, bool), ()> {
    loop {
        if total >= buf.capacity() {
            buf.reserve(buf.capacity());
        }

        // Read more into buffer
        let start = total;
        buf.resize(buf.capacity(), 0);
        let read_buf = buf.split_off(start);
        let (res, read_buf) = client.read(read_buf).await;

        buf.truncate(start);

        match res {
            Ok(0) => {
                drop(read_buf);
                return_buffer(buf);
                return Err(());
            }
            Ok(n) => {
                buf.extend_from_slice(&read_buf[..n]);
                drop(read_buf);
                total += n;
            }
            Err(_) => {
                drop(read_buf);
                return_buffer(buf);
                return Err(());
            }
        }

        if let Some((end, cl, ka)) = try_parse_request(&buf[..total]) {
            buf.truncate(total);
            return Ok((buf, end, cl, ka));
        }
    }
}

/// Slow path: read remaining body bytes
async fn read_remaining<S: AsyncReadRent>(
    stream: &mut S,
    mut buf: Vec<u8>,
    mut total: usize,
    needed: usize,
) -> Result<Vec<u8>, ()> {
    while total < needed {
        if buf.capacity() < needed {
            buf.reserve(needed - buf.capacity());
        }

        let start = total;
        buf.resize(buf.capacity().max(needed), 0);
        let read_buf = buf.split_off(start);
        let (res, read_buf) = stream.read(read_buf).await;

        buf.truncate(start);

        match res {
            Ok(0) => {
                drop(read_buf);
                return_buffer(buf);
                return Err(());
            }
            Ok(n) => {
                buf.extend_from_slice(&read_buf[..n]);
                drop(read_buf);
                total += n;
            }
            Err(_) => {
                drop(read_buf);
                return_buffer(buf);
                return Err(());
            }
        }
    }
    buf.truncate(needed);
    Ok(buf)
}

/// Slow path: read complete response headers
/// Returns (buf, headers_end, content_length, chunked, keep_alive)
async fn read_complete_response<S: AsyncReadRent>(
    upstream: &mut S,
    mut buf: Vec<u8>,
    mut total: usize,
) -> Result<(Vec<u8>, usize, usize, bool, bool), ()> {
    loop {
        if total >= buf.capacity() {
            buf.reserve(buf.capacity());
        }

        let start = total;
        buf.resize(buf.capacity(), 0);
        let read_buf = buf.split_off(start);
        let (res, read_buf) = upstream.read(read_buf).await;

        buf.truncate(start);

        match res {
            Ok(0) => {
                drop(read_buf);
                return_buffer(buf);
                return Err(());
            }
            Ok(n) => {
                buf.extend_from_slice(&read_buf[..n]);
                drop(read_buf);
                total += n;
            }
            Err(_) => {
                drop(read_buf);
                return_buffer(buf);
                return Err(());
            }
        }

        if let Some((end, cl, ch, ka)) = try_parse_response(&buf[..total]) {
            buf.truncate(total);
            return Ok((buf, end, cl, ch, ka));
        }
    }
}

/// Slow path: read chunked response until end marker
async fn read_chunked_response<S: AsyncReadRent>(
    upstream: &mut S,
    mut buf: Vec<u8>,
    mut total: usize,
) -> Result<Vec<u8>, ()> {
    loop {
        if total >= buf.capacity() {
            buf.reserve(buf.capacity());
        }

        let start = total;
        buf.resize(buf.capacity(), 0);
        let read_buf = buf.split_off(start);
        let (res, read_buf) = upstream.read(read_buf).await;

        buf.truncate(start);

        match res {
            Ok(0) => {
                drop(read_buf);
                // EOF with chunked - return what we have
                buf.truncate(total);
                return Ok(buf);
            }
            Ok(n) => {
                buf.extend_from_slice(&read_buf[..n]);
                drop(read_buf);
                total += n;
            }
            Err(_) => {
                drop(read_buf);
                return_buffer(buf);
                return Err(());
            }
        }

        if has_chunked_end(&buf[..total]) {
            buf.truncate(total);
            return Ok(buf);
        }
    }
}

#[inline]
fn has_chunked_end(buf: &[u8]) -> bool {
    buf.len() >= 5 && memchr::memmem::find(buf, b"0\r\n\r\n").is_some()
}

fn try_parse_request(buf: &[u8]) -> Option<(usize, usize, bool)> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);

    match req.parse(buf) {
        Ok(httparse::Status::Complete(end)) => {
            let mut cl = 0;
            let mut ka = true;
            for h in req.headers.iter() {
                if h.name.eq_ignore_ascii_case("content-length") {
                    if let Ok(s) = std::str::from_utf8(h.value) {
                        cl = s.parse().unwrap_or(0);
                    }
                } else if h.name.eq_ignore_ascii_case("connection") {
                    if let Ok(s) = std::str::from_utf8(h.value) {
                        ka = !s.eq_ignore_ascii_case("close");
                    }
                }
            }
            Some((end, cl, ka))
        }
        Ok(httparse::Status::Partial) => None,
        Err(_) => Some((buf.len(), 0, false)),
    }
}

/// Returns (headers_end, content_length, chunked, upstream_keep_alive)
fn try_parse_response(buf: &[u8]) -> Option<(usize, usize, bool, bool)> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut resp = httparse::Response::new(&mut headers);

    match resp.parse(buf) {
        Ok(httparse::Status::Complete(end)) => {
            let mut cl = 0;
            let mut chunked = false;
            let mut keep_alive = true; // HTTP/1.1 default
            for h in resp.headers.iter() {
                if h.name.eq_ignore_ascii_case("content-length") {
                    if let Ok(s) = std::str::from_utf8(h.value) {
                        cl = s.parse().unwrap_or(0);
                    }
                } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
                    if let Ok(s) = std::str::from_utf8(h.value) {
                        chunked = s.eq_ignore_ascii_case("chunked");
                    }
                } else if h.name.eq_ignore_ascii_case("connection") {
                    if let Ok(s) = std::str::from_utf8(h.value) {
                        keep_alive = !s.eq_ignore_ascii_case("close");
                    }
                }
            }
            Some((end, cl, chunked, keep_alive))
        }
        Ok(httparse::Status::Partial) => None,
        Err(_) => Some((buf.len(), 0, false, false)),
    }
}
