#ifndef _METRIC_KEY_H
#define _METRIC_KEY_H

struct metric_key {
	u32	ifindex;
	u16	direction;
	u16	cpu;
	struct {
		u32	protocol;
	} eth;
	struct {
		u32	saddr;
		u32	daddr;
		u32	protocol;
	} ip;
	union {
		struct {
			u16	sport;
			u16	dport;
		} tcp;
		struct {
			u16	sport;
			u16	dport;
		} udp;
	};
};

struct eth_metric_val {
	u64	packets;
	u64	bytes;
};

struct ip_metric_val {
	u64	packets;
	u64	bytes;
	u64	payload_bytes;
};

struct tcp_metric_val {
	u64	packets;
	u64	bytes;
	u64	payload_bytes;
	u64	flags;
};

struct udp_metric_val {
	u64	packets;
	u64	bytes;
	u64	payload_bytes;
};

#define ETH_METRIC_KEY_SIZE	offsetofend(struct metric_key, eth)
#define IP_METRIC_KEY_SIZE	offsetofend(struct metric_key, ip)
#define TCP_METRIC_KEY_SIZE	offsetofend(struct metric_key, tcp)
#define UDP_METRIC_KEY_SIZE	offsetofend(struct metric_key, udp)

#define ETH_METRIC_MAP_LIMIT	1024
#define IP_METRIC_MAP_LIMIT	1024
#define TCP_METRIC_MAP_LIMIT	1024*1024
#define UDP_METRIC_MAP_LIMIT	1024*1024

#endif
