//! Hash function implementations

pub mod sha1;
pub mod sha2;

pub trait Digest {
    fn init(&mut self);
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self, out: &mut [u8]);
}
