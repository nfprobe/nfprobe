use std::mem;
use super::{
    bpf::{
        self,
        Any,
        BpfMap,
        BpfMapIter,
    },
    consts,
    Result,
};

pub struct NfpMapIter<'a> {
    iters: Vec<BpfMapIter<'a>>,
}

impl<'a> NfpMapIter<'a> {
    pub fn new(metric_maps: &'a [BpfMap]) -> Self {
        let iters: Vec<BpfMapIter> = metric_maps.iter()
            .map(|m| BpfMapIter::new(m))
            .collect();
        NfpMapIter { iters }
    }

    pub fn next(&mut self, key: &mut Any, val: &mut Any) -> Result<bool> {
        while !self.iters.is_empty() {
            let iter = &mut self.iters[0];

            let exists = iter.next(key)?;
            if !exists {
                self.iters.pop();
                continue;
            }

            let exists = iter.map.lookup(key, val)?;
            if !exists {
                return Err(error!("missing in metric map"));
            }
            return Ok(true);
        }
        Ok(false)
    }
}

// struct bucket_key in bpf/nfprobe.h
#[repr(C)]
#[derive(Default, Clone)]
pub struct Bucket {
    start_ts: u64,
    end_ts:   u64,
}

pub struct NfpMap {
    pub bucket_map: BpfMap,
    key_size:       u32,
    val_size:       u32,
    max_entries:    u32
}

impl NfpMap {
    pub fn open(
        protocol: &str, key_size: u32, val_size: u32, max_entries: u32
    ) -> Result<Self> {
        let metric_map = BpfMap::new(
            bpf::BPF_MAP_TYPE_HASH,
            key_size, val_size,
            max_entries, 0, 0
        )?;

        let mut path = String::from(consts::BPF_MAP_ROOT);
        path.push_str("/buckets_");
        path.push_str(protocol);

        let bucket_map = BpfMap::open(
            &path, bpf::BPF_MAP_TYPE_HASH_OF_MAPS,
            mem::size_of::<Bucket>() as u32, mem::size_of::<u32>() as u32,
            consts::BUCKET_MAP_LIMIT, 0, metric_map.fd
        )?;

        Ok(NfpMap { bucket_map, key_size, val_size, max_entries })
    }

    pub fn get_metric_maps(
        &self, ts: u64
    ) -> Result<(Vec<Bucket>, Vec<BpfMap>)> {
        let mut bucket = Bucket::default();
        let mut buckets = Vec::<Bucket>::new();
        let mut iter = BpfMapIter::new(&self.bucket_map);

        loop {
            let exists = iter.next(&mut bucket)?;
            if !exists {
                break;
            }

            // only get closed buckets
            if bucket.end_ts < ts {
                buckets.push(bucket.clone());
            }
        }

        buckets.sort_by_key(|x| x.end_ts);
        let maps = buckets.iter()
            .map(|b| self.get_metric_map(b))
            .collect::<Result<Vec<BpfMap>>>()?;

        Ok((buckets, maps))
    }

    pub fn get_metric_map(&self, bucket: &Bucket) -> Result<BpfMap> {
        let mut id :u32 = 0;
        let exists = self.bucket_map.lookup(bucket, &mut id)?;
        if !exists {
            return Err(error!("missing in bucket map"));
        }
        BpfMap::from_id(id, 0).map_err(|e| e.into())
    }

    pub fn allocate(
        &mut self, start_ts: u64, bucket_width: u64, count: u32
    ) -> Result<Vec<Bucket>> {
        let mut bucket = Bucket::default();
        let mut buckets = Vec::<Bucket>::new();
        let mut ts = start_ts;

        for _ in 0..count {
            let metric_map = BpfMap::new(
                bpf::BPF_MAP_TYPE_HASH,
                self.key_size, self.val_size,
                self.max_entries, 0, 0)?;

            bucket.start_ts = ts;
            bucket.end_ts = ts + bucket_width;
            buckets.push(bucket.clone());

            ts = bucket.end_ts;

            if false == self.bucket_map.update(
                &bucket, &metric_map.fd, bpf::BPF_ANY)? {
                break
            }
        }

        Ok(buckets)
    }

    pub fn deallocate(&mut self, buckets: Vec<Bucket>) -> Result<Vec<bool>> {
        buckets.iter()
            .map(|b| self.bucket_map.delete(b).map_err(|e| e.into()))
            .collect()
    }
}
