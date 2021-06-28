#include <bpf/api.h>
#include "config.h"
#include "nfprobe.h"
#include "metrics.h"
#include "probe_eth.h"

#define round_down(val, mod) ((val) - (val) % (mod))

__section("main")
int probe_skb(struct __sk_buff *skb)
{
	struct bucket_key bucket_key;
	struct metric_key metric_key;

	inc_status_counter(NFPROBE_STATUS_TOTAL);

	u64 ts = ktime_get_ns();
	printk("ts = %ld\n", ts);
	bucket_key.start_ts = round_down(ktime_get_ns(), c_bucket_width);
	bucket_key.end_ts = bucket_key.start_ts + c_bucket_width;

	metric_key.cpu = get_smp_processor_id();
	metric_key.ifindex = c_ifindex;
	metric_key.direction = c_direction;

	return probe_eth(skb, 0, 0, &bucket_key, &metric_key);
}

BPF_LICENSE("GPL");
