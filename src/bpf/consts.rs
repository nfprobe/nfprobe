#![allow(dead_code)]

pub const LICENSE: &str = "GPL";

pub const BPF_INSN_BYTES: usize = 8;

pub const BPF_PSEUDO_MAP_FD: u8 = 1;

// cmd
pub const BPF_MAP_CREATE:          u32 = 0;
pub const BPF_MAP_LOOKUP_ELEM:     u32 = 1;
pub const BPF_MAP_UPDATE_ELEM:     u32 = 2;
pub const BPF_MAP_DELETE_ELEM:     u32 = 3;
pub const BPF_MAP_GET_NEXT_KEY:    u32 = 4;
pub const BPF_PROG_LOAD:           u32 = 5;
pub const BPF_OBJ_PIN:             u32 = 6;
pub const BPF_OBJ_GET:             u32 = 7;
pub const BPF_PROG_ATTACH:         u32 = 8;
pub const BPF_PROG_DETACH:         u32 = 9;
pub const BPF_PROG_TEST_RUN:       u32 = 10;
pub const BPF_PROG_GET_NEXT_ID:    u32 = 11;
pub const BPF_MAP_GET_NEXT_ID:     u32 = 12;
pub const BPF_PROG_GET_FD_BY_ID:   u32 = 13;
pub const BPF_MAP_GET_FD_BY_ID:    u32 = 14;
pub const BPF_OBJ_GET_INFO_BY_FD:  u32 = 15;
pub const BPF_PROG_QUERY:          u32 = 16;
pub const BPF_RAW_TRACEPOINT_OPEN: u32 = 17;

// map types
pub const BPF_MAP_TYPE_UNSPEC:           u32 = 0;
pub const BPF_MAP_TYPE_HASH:             u32 = 1;
pub const BPF_MAP_TYPE_ARRAY:            u32 = 2;
pub const BPF_MAP_TYPE_PROG_ARRAY:       u32 = 3;
pub const BPF_MAP_TYPE_PERF_EVENT_ARRAY: u32 = 4;
pub const BPF_MAP_TYPE_PERCPU_HASH:      u32 = 5;
pub const BPF_MAP_TYPE_PERCPU_ARRAY:     u32 = 6;
pub const BPF_MAP_TYPE_STACK_TRACE:      u32 = 7;
pub const BPF_MAP_TYPE_CGROUP_ARRAY:     u32 = 8;
pub const BPF_MAP_TYPE_LRU_HASH:         u32 = 9;
pub const BPF_MAP_TYPE_LRU_PERCPU_HASH:  u32 = 10;
pub const BPF_MAP_TYPE_LPM_TRIE:         u32 = 11;
pub const BPF_MAP_TYPE_ARRAY_OF_MAPS:    u32 = 12;
pub const BPF_MAP_TYPE_HASH_OF_MAPS:     u32 = 13;
pub const BPF_MAP_TYPE_DEVMAP:           u32 = 14;
pub const BPF_MAP_TYPE_SOCKMAP:          u32 = 15;
pub const BPF_MAP_TYPE_CPUMAP:           u32 = 16;
pub const BPF_MAP_TYPE_XSKMAP:           u32 = 17;
pub const BPF_MAP_TYPE_SOCKHASH:         u32 = 18;

// prog type
pub const BPF_PROG_TYPE_UNSPEC:           u32 = 0;
pub const BPF_PROG_TYPE_SOCKET_FILTER:    u32 = 1;
pub const BPF_PROG_TYPE_KPROBE:           u32 = 2;
pub const BPF_PROG_TYPE_SCHED_CLS:        u32 = 3;
pub const BPF_PROG_TYPE_SCHED_ACT:        u32 = 4;
pub const BPF_PROG_TYPE_TRACEPOINT:       u32 = 5;
pub const BPF_PROG_TYPE_XDP:              u32 = 6;
pub const BPF_PROG_TYPE_PERF_EVENT:       u32 = 8;
pub const BPF_PROG_TYPE_CGROUP_SKB:       u32 = 9;
pub const BPF_PROG_TYPE_CGROUP_SOCK:      u32 = 10;
pub const BPF_PROG_TYPE_LWT_IN:           u32 = 11;
pub const BPF_PROG_TYPE_LWT_OUT:          u32 = 12;
pub const BPF_PROG_TYPE_LWT_XMIT:         u32 = 13;
pub const BPF_PROG_TYPE_SOCK_OPS:         u32 = 14;
pub const BPF_PROG_TYPE_SK_SKB:           u32 = 15;
pub const BPF_PROG_TYPE_CGROUP_DEVICE:    u32 = 16;
pub const BPF_PROG_TYPE_SK_MSG:           u32 = 17;
pub const BPF_PROG_TYPE_RAW_TRACEPOINT:   u32 = 18;
pub const BPF_PROG_TYPE_CGROUP_SOCK_ADDR: u32 = 19;

// map update flag
pub const BPF_ANY:     u64 = 0;
pub const BPF_NOEXIST: u64 = 1;
pub const BPF_EXIST:   u64 = 2;
