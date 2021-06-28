extern crate libc;
extern crate elf_rs;

#[macro_use]
mod macros;
mod bpf;
mod consts;

pub mod elf;
pub mod time;
pub mod metrics;
mod map;
pub use map::{
    Bucket,
    NfpMap,
    NfpMapIter,
};

// FIXME: error and logging
// FIXME: may add backtrace
// FIXME: json output
// FIXME: do not use tc

pub struct Error {
    pub msg: String,
}

impl<T: std::fmt::Debug> std::convert::From<T> for Error {
    fn from(e: T) -> Self {
        Error{ msg: format!("{:?}", e) }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
