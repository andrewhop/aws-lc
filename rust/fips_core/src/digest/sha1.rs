use crate::digest::Digest;

pub const BLOCK_LEN: usize = 64;

#[repr(C)]
pub struct State {
    h: [u32; 5],
    Nl: u32,
    Nh: u32,
    data: [u8; BLOCK_LEN],
    num: u32,
}

impl Digest for State {
    fn init(&mut self) {
        todo!()
    }

    fn update(&mut self, data: &[u8]) {
        todo!()
    }

    fn finalize(&mut self, out: &mut [u8]) {
        todo!()
    }
}
