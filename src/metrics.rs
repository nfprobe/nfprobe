// The metric types and constant values must be the same
// as those defined in bpf/metric_key.h

#[repr(C)]
#[derive(Default, Clone)]
pub struct phy_metric_key {
    ifindex:   u32,
    direction: u16,
    cpu:       u16,
}

#[repr(C)]
#[derive(Default, Clone)]
pub struct eth_metric_key {
    phy:      phy_metric_key,
    protocol: u32,
}

#[repr(C)]
#[derive(Default, Clone)]
pub struct ip_metric_key {
    eth:      eth_metric_key,
    saddr:    u32,
    daddr:    u32,
    protocol: u32,
}

#[repr(C)]
#[derive(Default, Clone)]
pub struct tcp_metric_key {
    ip:    ip_metric_key,
    sport: u16,
    dport: u16,
}

#[repr(C)]
#[derive(Default, Clone)]
pub struct udp_metric_key {
    ip:    ip_metric_key,
    sport: u16,
    dport: u16,
}

#[repr(C)]
#[derive(Default, Clone)]
pub struct eth_metric_val {
    packets: u64,
    bytes:   u64,
}

#[repr(C)]
#[derive(Default, Clone)]
pub struct ip_metric_val {
    packets:       u64,
    bytes:         u64,
    payload_bytes: u64,
}

#[repr(C)]
#[derive(Default, Clone)]
pub struct tcp_metric_val {
    packets:       u64,
    bytes:         u64,
    payload_bytes: u64,
    flags:         u64,
}

#[repr(C)]
#[derive(Default, Clone)]
pub struct udp_metric_val {
    packets:       u64,
    bytes:         u64,
    payload_bytes: u64,
}

pub const ETH_METRIC_MAP_LIMIT: u32 = 1024;
pub const IP_METRIC_MAP_LIMIT:  u32 = 1024;
pub const UDP_METRIC_MAP_LIMIT: u32 = 1024*1024;
pub const TCP_METRIC_MAP_LIMIT: u32 = 1024*1024;

define_metrics!{
    {"eth", eth_metric_key, eth_metric_val, ETH_METRIC_MAP_LIMIT},
    {"ip",  ip_metric_key,  ip_metric_val,  IP_METRIC_MAP_LIMIT},
    {"udp", udp_metric_key, udp_metric_val, UDP_METRIC_MAP_LIMIT},
    {"tcp", tcp_metric_key, tcp_metric_val, TCP_METRIC_MAP_LIMIT},
}
