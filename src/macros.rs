#[macro_export]
macro_rules! error {
    ( $($args:tt)* ) => {
        {
            use $crate::Error;
            Error{ msg: format!($($args)*) }
        }
    }
}

#[macro_export]
macro_rules! define_metrics {
    (
        $({ $protocol:expr, $K:ident, $V:ident, $limit:expr },)*
    ) => {
        use std::mem;
        use $crate::{ error, Result };
        use $crate::map::{ NfpMap };
        use $crate::bpf::Any;

        pub fn open_nfp_map(protocol: &str) -> Result<NfpMap> {
            match protocol {
                $($protocol => NfpMap::open(
                    protocol,
                    mem::size_of::<$K>() as u32,
                    mem::size_of::<$V>() as u32,
                    $limit,
                ),)*
                _ => Err(error!("invalid protocol")),
            }
        }

        pub fn new_metric_key(protocol: &str) -> Result<Box<Any>> {
            match protocol {
                $($protocol => Ok(Box::new($K::default())),)*
                _ => Err(error!("invalid protocol")),
            }
        }

        pub fn new_metric_val(protocol: &str) -> Result<Box<Any>> {
            match protocol {
                $($protocol => Ok(Box::new($V::default())),)*
                _ => Err(error!("invalid protocol")),
            }
        }
    }
}

#[macro_export]
macro_rules! open_nfp_map {
    ( $protocol:expr ) => {{
        use $crate::metrics;

        metrics::open_nfp_map($protocol)
    }}
}

#[macro_export]
macro_rules! new_metric_key {
    ( $protocol:expr ) => {{
        use $crate::metrics;

        metrics::new_metric_key($protocol)
    }}
}

#[macro_export]
macro_rules! new_metric_val {
    ( $protocol:expr ) => {{
        use $crate::metrics;

        metrics::new_metric_val($protocol)
    }}
}
