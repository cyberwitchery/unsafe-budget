/// A sibling workspace member function with unsafe code.
pub fn sibling_unsafe() -> i32 {
    unsafe {
        let x: i32 = 99;
        let ptr = &x as *const i32;
        *ptr
    }
}

/// Another unsafe block in the sibling.
pub fn sibling_unsafe_two() {
    unsafe {
        std::ptr::null::<i32>().read_volatile();
    }
}
