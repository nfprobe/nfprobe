use libc;
use std::io::Error;
use super::Result;

#[inline]
pub fn round_down(ts: u64, bucket_width: u64) -> u64 {
    ts - ts % bucket_width
}

#[inline]
pub fn get_ktime() -> Result<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    unsafe {
        if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) == -1 {
            return Err(Error::last_os_error().into());
        }
    }

    Ok(ts.tv_sec as u64 * 1000_000_000 + ts.tv_nsec as u64)
}

#[inline]
pub fn get_ktime_rounded(bucket_width: u64) -> Result<u64> {
    let ts = get_ktime()?;
    Ok(round_down(ts, bucket_width))
}
