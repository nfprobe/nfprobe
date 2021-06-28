#ifndef _PROBE_IP_H
#define _PROBE_IP_H

#include <linux/ip.h>
#include "probe_tcp.h"
#include "probe_udp.h"

CREATE_MAPS(
	ip_buckets,
	ip_metrics,
	IP_METRIC_KEY_SIZE,
	sizeof(struct ip_metric_val),
	IP_METRIC_MAP_LIMIT
)

static inline
int probe_ip(struct __sk_buff *skb, u32 var_off, u32 const_off,
	     struct bucket_key *bucket_key, struct metric_key *metric_key)
{
	struct iphdr *ip4;
	u32 hdrlen;

	ensure_header(skb, var_off, const_off, ip4);

	hdrlen = ipv4_hdrlen(ip4);
	if (hdrlen < sizeof(*ip4)) {
		inc_status_counter(NFPROBE_STATUS_PACKET_ERROR);
		return TC_ACT_OK;
	}
	var_off += hdrlen;

	metric_key->ip.saddr = ip4->saddr;
	metric_key->ip.daddr = ip4->daddr;
	metric_key->ip.protocol = ip4->protocol;

	switch (ip4->protocol) {
	case IPPROTO_TCP:
		return probe_tcp(skb, var_off, const_off,
				 bucket_key, metric_key);
	case IPPROTO_UDP:
		return probe_udp(skb, var_off, const_off,
				 bucket_key, metric_key);
	}

	struct ip_metric_val *val, val0 = {
		.packets	= 1,
		.bytes		= skb->len,
		.payload_bytes	= skb->len - (var_off + const_off),
	};
	get_metric(val, &val0, &ip_buckets, bucket_key, metric_key);

	val->packets		+= 1;
	val->bytes		+= val0.bytes;
	val->payload_bytes	+= val0.payload_bytes;

	return TC_ACT_OK;
}

#endif
