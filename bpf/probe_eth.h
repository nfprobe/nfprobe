#ifndef _PROBE_ETH_H
#define _PROBE_ETH_H

#include <linux/if_ether.h>
#include "probe_ip.h"

CREATE_MAPS(
	eth_buckets,
	eth_metrics,
	ETH_METRIC_KEY_SIZE,
	sizeof(struct eth_metric_val),
	ETH_METRIC_MAP_LIMIT
)

static inline
int probe_eth(struct __sk_buff *skb, u32 var_off, u32 const_off,
	      struct bucket_key *bucket_key, struct metric_key *metric_key)
{
	struct ethhdr *eth;

	ensure_header(skb, var_off, const_off, eth);

	const_off += sizeof(*eth);
	metric_key->eth.protocol = eth->h_proto;

	switch (eth->h_proto) {
	case bpf_htons(0x0800):
		return probe_ip(skb, var_off, const_off,
				bucket_key, metric_key);
	}

	struct eth_metric_val *val, val0 = {
		.packets	= 1,
		.bytes		= skb->len,
	};
	get_metric(val, &val0, &eth_buckets, bucket_key, metric_key);

	val->packets	+= 1;
	val->bytes	+= val0.bytes;

	return TC_ACT_OK;
}

#endif
