#[unsafe(no_mangle)]
pub extern "C" fn aws_lc_add_double(left: u64, right: u64) -> u64 {
    bailey::add_double(left, right)
}

#[unsafe(no_mangle)]
pub extern "C" fn aws_lc_add(left: u64, right: u64) -> u64 {
    keep::add(left, right)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = aws_lc_add(2, 3);
        assert_eq!(result, 5);

        let result = aws_lc_add_double(2, 3);
        assert_eq!(result, 10);
    }
}
