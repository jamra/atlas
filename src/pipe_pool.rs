//! Thread-local pipe pool for zero-copy splice operations
//! Reuses pipes instead of creating/destroying per connection

use std::cell::RefCell;

#[cfg(target_os = "linux")]
use monoio::net::unix::Pipe;

#[cfg(target_os = "linux")]
use monoio::net::unix::new_pipe;

const POOL_SIZE: usize = 64;

#[cfg(target_os = "linux")]
thread_local! {
    static PIPE_POOL: RefCell<Vec<(Pipe, Pipe)>> = RefCell::new(Vec::with_capacity(POOL_SIZE));
}

/// A pooled pipe pair that returns to the pool on drop
#[cfg(target_os = "linux")]
pub struct PooledPipe {
    pipe: Option<(Pipe, Pipe)>,
}

#[cfg(target_os = "linux")]
impl PooledPipe {
    /// Get a pipe pair from the pool or create a new one
    pub fn new() -> std::io::Result<Self> {
        let pipe = PIPE_POOL.with(|pool| pool.borrow_mut().pop());

        match pipe {
            Some(p) => Ok(Self { pipe: Some(p) }),
            None => {
                let (r, w) = new_pipe()?;
                Ok(Self { pipe: Some((r, w)) })
            }
        }
    }

    /// Get references to the read and write ends
    pub fn get(&mut self) -> (&mut Pipe, &mut Pipe) {
        let (ref mut r, ref mut w) = self.pipe.as_mut().unwrap();
        (r, w)
    }
}

#[cfg(target_os = "linux")]
impl Drop for PooledPipe {
    fn drop(&mut self) {
        if let Some(pipe) = self.pipe.take() {
            PIPE_POOL.with(|pool| {
                let mut pool = pool.borrow_mut();
                if pool.len() < POOL_SIZE {
                    pool.push(pipe);
                }
                // If pool is full, pipe is dropped (closed)
            });
        }
    }
}

/// Non-Linux stub
#[cfg(not(target_os = "linux"))]
pub struct PooledPipe;

#[cfg(not(target_os = "linux"))]
impl PooledPipe {
    pub fn new() -> std::io::Result<Self> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Pipe pool not available on this platform",
        ))
    }
}
