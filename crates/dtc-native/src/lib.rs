//! Upstream dtc linked as a library.
//!
//! dtc keeps global state and calls `exit()` on errors, so [`main`] must only be
//! called once, from a process dedicated to running it.

use std::ffi::{CString, c_char, c_int};

unsafe extern "C" {
    fn bootimg_dtc_main(argc: c_int, argv: *mut *mut c_char) -> c_int;
}

/// Runs dtc with `args` (excluding argv[0]) and returns its exit status.
pub fn main(args: &[String]) -> i32 {
    let args: Vec<CString> = std::iter::once("dtc")
        .chain(args.iter().map(String::as_str))
        .map(|arg| CString::new(arg).expect("NUL byte in dtc argument"))
        .collect();
    let mut argv: Vec<*mut c_char> = args.iter().map(|arg| arg.as_ptr().cast_mut()).collect();
    argv.push(std::ptr::null_mut());
    // SAFETY: argv is a NULL-terminated array of NUL-terminated strings that outlive the call.
    unsafe { bootimg_dtc_main((argv.len() - 1) as c_int, argv.as_mut_ptr()) }
}
