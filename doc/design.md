## Workflow

### Build time

Build userspace binary `nfprobe` and BPF object.

### Run time

- At start time, `nfprobe` creates all the maps.

- Then `nfprobe` periodically read metrics from metric maps, delete
  old maps and create new maps.

- To enable packet capture for an interface, use `nfprobe` to edits
  the BPF object file to resolve external variables like ifindex, and
  etc.  Then install the BPF program using `tc`.

## Tables:

### Global maps

The global maps are created by `nfprobe`.  They are pinned to global
namespace.

- *config map* stores runtime config.  Right now the only run time
  config is time offset, i.e. `epoch time - ktime`.  The time offset
  is used to align time buckets.

- *status map* stores misc metrics from BPF code.  This table is a
  `PERCPU_ARRAY`.  The metrics include, for example, total number of
  packets, number of map lookup errors, and etc.

### Netflow metrics maps

For each protocol, netflow metrics are stored in a 2 level maps.

The top level is a bucket map of type `HASH_OF_MAPS`.  The key of the
bucket map, `(start_ts, end_ts)`, specifies the time bucket.  The
value of the bucket map points to the 2nd level maps.

The bucket maps are created by `nfprobe`.  They are pinned to global
namespace.

The 2nd level maps are metric maps that store netflow metrics of a
bucket.  The key of a metric map contains the following:

    (cpu, ifindex, direction).(protocol keys)

The protocol keys are protocol specific.  For example, IP has metric
key `(saddr, daddr, protocol)`.  The value of the metric map stores
netflow metrics.

The metrics maps are created by `nfprobe`.  These maps need to be
created before `start_ts` of its time bucket, and deleted after all
metrics of the map are collected by `nfprobe`.

## Netflow Metric

Each netflow metric has an Unique ID for de-duplication.  The UID is:

   (hostname, start_ts, end_ts, metric_key)

Each packet is counted once.  For example, a TCP packet is counted in
TCP metrics, but not in IP metrics.

## Data Enrichment

Use sqlite to store enrichment data.

## Error handling

### BPF errors

BPF errors are counted in the global status map.  Perf events are also
generated for errors.  The perf events are rate limited to avoid too
many events.

## TODO

use perf event for panic, ref cilium

how map ref count is managed
-> bpf_map_put is called when
   1. file object is deleted (OBJ_PIN)
   2. when associated prog is deleted
    bpf_prog_put()
    ==> free_used_maps(aux)
