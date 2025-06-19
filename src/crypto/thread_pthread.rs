use std::sync::{Once, RwLock};

// Equivalent type definitions for API compatibility
pub type CRYPTO_STATIC_MUTEX = RwLock<()>;
pub type CRYPTO_once_t = Once;

// For thread-local storage
pub type thread_local_data_t = usize;
pub type thread_local_destructor_t = fn(*mut libc::c_void);

// Assuming this is defined somewhere in the original code
const NUM_OPENSSL_THREAD_LOCALS: usize = 16; // Adjust based on your actual constant

pub struct CRYPTO_MUTEX {
    lock: RwLock<()>,
}

pub struct ReadGuard<'a> {
    _guard: std::sync::RwLockReadGuard<'a, ()>,
}

pub struct WriteGuard<'a> {
    _guard: std::sync::RwLockWriteGuard<'a, ()>,
}

impl CRYPTO_MUTEX {
    pub fn new() -> Self {
        CRYPTO_MUTEX {
            lock: RwLock::new(()),
        }
    }

    pub fn lock_read(&self) -> ReadGuard {
        match self.lock.read() {
            Ok(guard) => ReadGuard { _guard: guard },
            Err(_) => std::process::abort(),
        }
    }

    pub fn lock_write(&self) -> WriteGuard {
        match self.lock.write() {
            Ok(guard) => WriteGuard { _guard: guard },
            Err(_) => std::process::abort(),
        }
    }
}

pub fn CRYPTO_MUTEX_init(lock: &mut CRYPTO_MUTEX) {
    *lock = CRYPTO_MUTEX::new();
}

// These functions now return guards that automatically unlock when dropped
pub fn CRYPTO_MUTEX_lock_read(lock: &CRYPTO_MUTEX) -> ReadGuard {
    lock.lock_read()
}

pub fn CRYPTO_MUTEX_lock_write(lock: &CRYPTO_MUTEX) -> WriteGuard {
    lock.lock_write()
}

// These functions explicitly drop the guards
pub fn CRYPTO_MUTEX_unlock_read(_guard: ReadGuard) {
    // Guard is automatically dropped and lock is released
}

pub fn CRYPTO_MUTEX_unlock_write(_guard: WriteGuard) {
    // Guard is automatically dropped and lock is released
}

pub fn CRYPTO_MUTEX_cleanup(_lock: &mut CRYPTO_MUTEX) {
    // Nothing to do - Rust handles cleanup automatically
}
