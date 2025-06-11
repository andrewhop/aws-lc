pub fn add_double(left: u64, right: u64) -> u64 {
    (left + right) * 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add_double(2, 3);
        assert_eq!(result, 10);
    }
}
