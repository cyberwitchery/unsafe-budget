/// A function with unsafe code for testing.
pub fn unsafe_example() -> i32 {
    unsafe {
        let x: i32 = 42;
        let ptr = &x as *const i32;
        *ptr
    }
}

/// Another unsafe block.
pub fn another_unsafe() {
    unsafe {
        std::ptr::null::<i32>().read_volatile();
    }
}

/// Safe function for comparison.
pub fn safe_function() -> i32 {
    42
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unsafe() {
        assert_eq!(unsafe_example(), 42);
    }
}
