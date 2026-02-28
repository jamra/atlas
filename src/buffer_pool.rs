use std::cell::RefCell;

const BUFFER_SIZE: usize = 65536; // 64KB buffers for better throughput
const POOL_SIZE: usize = 1024;

thread_local! {
    static BUFFER_POOL: RefCell<BufferPool> = RefCell::new(BufferPool::new());
}

pub struct BufferPool {
    buffers: Vec<Vec<u8>>,
}

impl BufferPool {
    fn new() -> Self {
        let mut buffers = Vec::with_capacity(POOL_SIZE);
        for _ in 0..POOL_SIZE {
            buffers.push(vec![0u8; BUFFER_SIZE]);
        }
        Self { buffers }
    }

    fn get(&mut self) -> Vec<u8> {
        self.buffers.pop().unwrap_or_else(|| vec![0u8; BUFFER_SIZE])
    }

    fn put(&mut self, buf: Vec<u8>) {
        if self.buffers.len() < POOL_SIZE && buf.capacity() >= BUFFER_SIZE {
            self.buffers.push(buf);
        }
    }
}

pub fn get_buffer() -> Vec<u8> {
    BUFFER_POOL.with(|pool| pool.borrow_mut().get())
}

pub fn return_buffer(buf: Vec<u8>) {
    BUFFER_POOL.with(|pool| pool.borrow_mut().put(buf));
}

pub struct PooledBuffer {
    inner: Option<Vec<u8>>,
}

impl PooledBuffer {
    pub fn new() -> Self {
        Self {
            inner: Some(get_buffer()),
        }
    }

    pub fn take(&mut self) -> Vec<u8> {
        self.inner.take().expect("Buffer already taken")
    }

    pub fn put(&mut self, buf: Vec<u8>) {
        self.inner = Some(buf);
    }

    pub fn into_inner(mut self) -> Vec<u8> {
        self.inner.take().expect("Buffer already taken")
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Some(buf) = self.inner.take() {
            return_buffer(buf);
        }
    }
}

impl Default for PooledBuffer {
    fn default() -> Self {
        Self::new()
    }
}
