use std::mem;
use std::any::Any;
use libc;

#[inline]
pub fn ref_to_u64(r: &dyn Any) -> u64 {
    r as *const _ as *const libc::c_void as u64
}

#[inline]
pub fn bpf<T>(cmd: u32, attr: &T) -> (i32, i32) {
    unsafe {(
        libc::syscall(libc::SYS_bpf, cmd, attr, mem::size_of::<T>()) as i32,
        errno(),
    )}
}

#[inline]
pub fn close(fd: u32) -> (i32, i32) {
    unsafe { (libc::close(fd as libc::c_int), errno()) }
}

#[inline]
pub fn errno() -> i32 {
    unsafe { *libc::__errno_location() as i32 }
}
