#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]

use std::sync::atomic::{AtomicU32, Ordering};
pub type CRYPTO_refcount_t = AtomicU32;
const CRYPTO_REFCOUNT_MAX: u32 = u32::MAX;

pub fn CRYPTO_refcount_inc(count: &CRYPTO_refcount_t) {
    // Using Relaxed ordering would be unsafe here since we need consistency
    let current = count.load(Ordering::Acquire);
    if current < CRYPTO_REFCOUNT_MAX {
        count.store(current + 1, Ordering::Release);
    }
}

pub fn CRYPTO_refcount_dec_and_test_zero(count: &CRYPTO_refcount_t) -> bool {
    let current = count.load(Ordering::Acquire);
    if current == 0 {
        panic!("Attempt to decrement zero refcount");
    }

    let new_count = if current < CRYPTO_REFCOUNT_MAX {
        current - 1
    } else {
        current
    };

    count.store(new_count, Ordering::Release);
    new_count == 0
}
