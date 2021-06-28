use nfprobe::{
    Result,
    NfpMapIter,
    time,
};
use super::{
    Config,
    invalid_cmd,
    invalid_cmd_args,
};

fn usage() -> Result<()> {
    println!("Usage: nfprobe bpf allocate-buckets PROTOCOL BUCKET_WIDTH COUNT");
    println!("       nfprobe bpf dump-metrics PROTOCOL");
    Ok(())
}

pub fn do_bpf(args: &[&str], cfg: &Config) -> Result<()> {
    if args.is_empty() {
        return usage();
    }

    match args[0] {
        "allocate-buckets" => do_allocate_buckets(&args[1..], cfg),
        "dump-metrics" => do_dump_metrics(&args[1..], cfg),
        "help" => usage(),
        _ => invalid_cmd("bpf", args[0]),
    }
}

fn do_allocate_buckets(args: &[&str], _cfg: &Config) -> Result<()> {
    if args.len() != 3 {
        return invalid_cmd_args("bpf", "allocate_buckets");
    }

    let protocol = args[0];
    let bucket_width = args[1].parse::<u64>()?;
    let count = args[2].parse::<u32>()?;

    let mut map = open_nfp_map!(protocol)?;
    let start_ts = time::get_ktime_rounded(bucket_width)?;
    let buckets = map.allocate(start_ts, bucket_width, count)?;

    println!("allocated {} buckets", buckets.len());
    Ok(())
}

fn do_dump_metrics(args: &[&str], _cfg: &Config) -> Result<()> {
    if args.len() != 1 {
        return invalid_cmd_args("bpf", "dump-metrics");
    }

    let protocol = args[0];
    let mut map = open_nfp_map!(protocol)?;
    let now = time::get_ktime()?;
    let (buckets, maps) = map.get_metric_maps(now)?;
    let mut iter = NfpMapIter::new(&maps);

    let mut key = new_metric_key!(protocol)?;
    let mut val = new_metric_val!(protocol)?;

    while iter.next(&mut key, &mut val)? {
        println!("{:?} {:?}", key, val);
    }

    map.deallocate(buckets)?;
    Ok(())
}
