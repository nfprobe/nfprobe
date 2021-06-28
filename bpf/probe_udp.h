#ifndef _PROBE_UDP_H
#define _PROBE_UDP_H

#include <linux/udp.h>

CREATE_MAPS(
	udp_buckets,
	udp_metrics,
	UDP_METRIC_KEY_SIZE,
	sizeof(struct udp_metric_val),
	UDP_METRIC_MAP_LIMIT
)

static inline
int probe_udp(struct __sk_buff *skb, u32 var_off, u32 const_off,
	      struct bucket_key *bucket_key, struct metric_key *metric_key)
{
	struct udphdr *udp;

	ensure_header(skb, var_off, const_off, udp);
	const_off += sizeof(*udp);

	metric_key->udp.sport = udp->source;
	metric_key->udp.dport = udp->dest;

	struct udp_metric_val *val, val0 = {
		.packets	= 1,
		.bytes		= skb->len,
		.payload_bytes	= skb->len - (var_off + const_off),
	};
	get_metric(val, &val0, &udp_buckets, bucket_key, metric_key);

	val->packets		+= 1;
	val->bytes		+= val0.bytes;
	val->payload_bytes	+= val0.payload_bytes;

	return TC_ACT_OK;
}

#endif
