mod sys;

mod consts;
pub use consts::*;

mod map;
pub use map::{
    Any,
    BpfMap,
    BpfMapIter,
};

pub type Result<T> = std::result::Result<T, std::io::Error>;
