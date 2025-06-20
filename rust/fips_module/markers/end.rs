#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn AWS_LC_fips_text_end(a: u8, b: u8) -> u8 {
    a ^ b
}
