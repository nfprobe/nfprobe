#ifndef _PROBE_TCP_H
#define _PROBE_TCP_H

#include <linux/tcp.h>

CREATE_MAPS(
	tcp_buckets,
	tcp_metrics,
	TCP_METRIC_KEY_SIZE,
	sizeof(struct tcp_metric_val),
	TCP_METRIC_MAP_LIMIT
)

static inline
int probe_tcp(struct __sk_buff *skb, u32 var_off, u32 const_off,
	      struct bucket_key *bucket_key, struct metric_key *metric_key)
{
	struct tcphdr *tcp;
	u32 hdrlen;

	ensure_header(skb, var_off, const_off, tcp);

	hdrlen = tcp_hdrlen(tcp);
	if (hdrlen < sizeof(*tcp)) {
		inc_status_counter(NFPROBE_STATUS_PACKET_ERROR);
		return TC_ACT_OK;
	}
	var_off += hdrlen;

	metric_key->tcp.sport = tcp->source;
	metric_key->tcp.dport = tcp->dest;

	struct tcp_metric_val *val, val0 = {
		.packets	= 1,
		.bytes		= skb->len,
		.payload_bytes	= skb->len - (var_off + const_off),
		.flags		= tcp->flags,
	};
	get_metric(val, &val0, &tcp_buckets, bucket_key, metric_key);

	val->packets		+= 1;
	val->bytes		+= val0.bytes;
	val->payload_bytes	+= val0.payload_bytes;
	val->flags		|= val0.flags;

	return TC_ACT_OK;
}

#endif
