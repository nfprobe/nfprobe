#ifndef _NFPROBE_H
#define _NFPROBE_H

enum nfprobe_config {
	MAX_NFPROBE_CONFIG = 100,
};

enum nfprobe_status {
	NFPROBE_STATUS_TOTAL = 0,
	NFPROBE_CONFIG_LOOKUP_ERROR,
	NFPROBE_STATUS_PACKET_ERROR,
	NFPROBE_STATUS_LOOKUP_ERROR,
	NFPROBE_STATUS_UPDATE_ERROR,
	MAX_NFPROBE_STATUS = 100,
};

__section_maps
struct bpf_elf_map nfprobe_config = {
	.type		= BPF_MAP_TYPE_ARRAY,
	.size_key	= sizeof(u32),
	.size_value	= sizeof(u64),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= MAX_NFPROBE_CONFIG,
};

__section_maps
struct bpf_elf_map nfprobe_status = {
	.type		= BPF_MAP_TYPE_PERCPU_ARRAY,
	.size_key	= sizeof(u32),
	.size_value	= sizeof(u64),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= MAX_NFPROBE_STATUS,
};

// FIXME: use perf event
#define report_error()							\
({									\
	printk("error\n");						\
	return TC_ACT_OK;						\
})

#define inc_status_counter(key)						\
({									\
	int *__val, __key = key;					\
	__val = map_lookup_elem(&nfprobe_status, &__key);		\
	if (__val == NULL)						\
		report_error();						\
	*__val += 1;							\
})

#define get_config(key, val)						\
({									\
	int __key = key;						\
	val = map_lookup_elem(&nfprobe_config, &__key);			\
	if (val == NULL) {						\
		inc_status_counter(NFPROBE_CONFIG_LOOKUP_ERROR);	\
		return TC_ACT_OK;					\
	}								\
})

struct bucket_key {
	u64	start_ts;
	u64	end_ts;
};

#define BUCKET_MAP_LIMIT	1024

#define CREATE_MAPS(buckets, metrics, key_size, val_size, limit)	\
__section_maps								\
struct bpf_elf_map metrics = {						\
	.type		= BPF_MAP_TYPE_HASH,				\
	.size_key	= key_size,					\
	.size_value	= val_size,					\
	.max_elem	= limit,					\
	.id		= __COUNTER__ + 1,				\
};									\
__section_maps								\
struct bpf_elf_map buckets = {						\
	.type		= BPF_MAP_TYPE_HASH_OF_MAPS,			\
	.size_key	= sizeof(struct bucket_key),			\
	.size_value	= sizeof(u32),					\
	.max_elem	= BUCKET_MAP_LIMIT,				\
	.pinning	= PIN_GLOBAL_NS,				\
	.inner_id	= __COUNTER__,					\
};

#define get_metric(val, val0, buckets, bucket_key, metric_key)		\
({									\
	void *metrics = map_lookup_elem(buckets, bucket_key);		\
	if (metrics == NULL) {						\
		inc_status_counter(NFPROBE_STATUS_LOOKUP_ERROR);	\
		return TC_ACT_OK;					\
	}								\
									\
	val = map_lookup_elem(metrics, metric_key);			\
	if (val == NULL) {						\
		if (map_update_elem(metrics, metric_key, val0, 0) != 0)	\
			inc_status_counter(NFPROBE_STATUS_UPDATE_ERROR);\
		return TC_ACT_OK;					\
	}								\
})

/*
 * 2 things are done here to make the verifier happy:
 *
 *   - split offset into var_off and const_off
 *   - perform the 2nd check regardless of the 1st check
 */
#define ensure_header(skb, var_off, const_off, hdr)			\
({									\
	u32 len = const_off + sizeof(*hdr);				\
	void *data = (void *)(long)skb->data + var_off;			\
	void *data_end = (void *)(long)skb->data_end;			\
									\
	if (data + len > data_end)					\
		skb_pull_data(skb, var_off + len);			\
									\
	data = (void *)(long)skb->data + var_off;			\
	data_end = (void *)(long)skb->data_end;				\
	if (data + len > data_end) {					\
		inc_status_counter(NFPROBE_STATUS_PACKET_ERROR);	\
		return TC_ACT_OK;					\
	}								\
									\
	hdr = (void *)(data + const_off);				\
})

#endif
