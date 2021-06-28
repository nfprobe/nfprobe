use std::any;
use std::io::Error;
use std::path::Path;
use libc;
use super::sys;
use super::consts::*;
use super::Result;

pub type Any = dyn any::Any;

pub struct BpfMapIter<'a> {
    pub map: &'a BpfMap,
    count:   u64,
}

impl<'a> BpfMapIter<'a> {
    pub fn new(map: &'a BpfMap) -> Self {
        BpfMapIter {
            map,
            count: 0,
        }
    }

    // We are not implementing Iterator trait becasue next() uses a
    // stream iterator. More info in 1598-generic_associated_types.
    pub fn next(&mut self, key: &mut Any) -> Result<bool> {
        #[repr(C)]
        struct Attr {
            fd:       u32,
            key:      u64,
            next_key: u64,
        }

        let key_ptr = sys::ref_to_u64(key);
        let attr;

        if self.count == 0 {
            attr = Attr {
                fd:       self.map.fd,
                key:      0,
                next_key: key_ptr,
            };
        } else {
            attr = Attr {
                fd:       self.map.fd,
                key:      key_ptr,
                next_key: key_ptr,
            };
        }
        self.count += 1;

        match sys::bpf(BPF_MAP_GET_NEXT_KEY, &attr) {
            (0, _) => Ok(true),
            (-1, libc::ENOENT) => Ok(false),
            (_, e) => Err(Error::from_raw_os_error(e)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BpfMap {
    pub fd: u32,
    // FIXME: add and validate the following
    // map_type: u32,
    // key_size: u32,
    // val_size: u32,
    // max_entries: u32,
}

impl BpfMap {
    pub fn from_fd(fd: u32) -> Result<BpfMap> {
        Ok(BpfMap { fd: fd })
    }

    pub fn from_id(id: u32, open_flags: u32) -> Result<BpfMap> {
        #[repr(C)]
        struct Attr {
            map_id:     u32,
            next_id:    u32,
            open_flags: u32,
        }

        let attr = Attr {
            map_id:     id,
            next_id:    0,
            open_flags: open_flags,
        };

        match sys::bpf(BPF_MAP_GET_FD_BY_ID, &attr) {
            (-1, e) => Err(Error::from_raw_os_error(e)),
            (fd, _) => BpfMap::from_fd(fd as u32),
        }
    }

    pub fn from_path(path: &str) -> Result<BpfMap> {
        #[repr(C)]
        struct Attr {
            path_ptr: u64,
        }

        let attr = Attr {
            path_ptr: path.as_ptr() as u64,
        };

        match sys::bpf(BPF_OBJ_GET, &attr) {
            (-1, e) => Err(Error::from_raw_os_error(e)),
            (fd, _) => BpfMap::from_fd(fd as u32),
        }
    }

    pub fn open(
        path: &str, map_type: u32, key_size: u32, val_size: u32,
        max_entries: u32, map_flags: u32, inner_map_fd: u32
    ) -> Result<BpfMap> {

        if Path::new(path).exists() {
            let map = BpfMap::from_path(path)?;
            return Ok(map);
        }

        let mut map = BpfMap::new(
            map_type, key_size, val_size,
            max_entries, map_flags, inner_map_fd)?;
        map.pin(path)?;

        Ok(map)
    }

    pub fn new(
        map_type: u32, key_size: u32, val_size: u32,
        max_entries: u32, map_flags: u32, inner_map_fd: u32
    ) -> Result<BpfMap> {
        #[repr(C)]
        struct Attr {
            map_type:     u32,
            key_size:     u32,
            val_size:     u32,
            max_entries:  u32,
            map_flags:    u32,
            inner_map_fd: u32,
        }

        let attr = Attr {
            map_type,
            key_size,
            val_size,
            max_entries,
            map_flags,
            inner_map_fd,
        };

        match sys::bpf(BPF_MAP_CREATE, &attr) {
            (-1, e) => Err(Error::from_raw_os_error(e)),
            (fd, _) => BpfMap::from_fd(fd as u32),
        }
    }

    pub fn lookup(&self, key: &Any, val: &mut Any) -> Result<bool> {
        #[repr(C)]
        struct Attr {
            fd:  u32,
            key: u64,
            val: u64,
        }

        let attr = Attr {
            fd:  self.fd,
            key: sys::ref_to_u64(key),
            val: sys::ref_to_u64(val),
        };

        match sys::bpf(BPF_MAP_LOOKUP_ELEM, &attr) {
            (0, _) => Ok(true),
            (-1, libc::ENOENT) => Ok(false),
            (_, e) => Err(Error::from_raw_os_error(e)),
        }
    }

    pub fn update(&mut self, key: &Any, val: &Any, flags: u64) -> Result<bool> {
        #[repr(C)]
        struct Attr {
            fd:    u32,
            key:   u64,
            val:   u64,
            flags: u64,
        }

        let attr = Attr {
            fd:    self.fd,
            key:   sys::ref_to_u64(key),
            val:   sys::ref_to_u64(val),
            flags: flags,
        };

        match (flags, sys::bpf(BPF_MAP_UPDATE_ELEM, &attr)) {
            (_, (0, _)) => Ok(true),
            (BPF_ANY, (-1, libc::E2BIG)) => Ok(false),
            (BPF_EXIST, (-1, libc::ENOENT)) => Ok(false),
            (BPF_NOEXIST, (-1, libc::EEXIST)) => Ok(false),
            (_, (_, e)) => Err(Error::from_raw_os_error(e)),
        }
    }

    pub fn delete(&mut self, key: &Any) -> Result<bool> {
        #[repr(C)]
        struct Attr {
            fd:  u32,
            key: u64,
        }

        let attr = Attr {
            fd:  self.fd,
            key: sys::ref_to_u64(key),
        };

        match sys::bpf(BPF_MAP_DELETE_ELEM, &attr) {
            (0, _) => Ok(true),
            (-1, libc::ENOENT) => Ok(false),
            (_, e) => Err(Error::from_raw_os_error(e)),
        }
    }

    pub fn pin(&mut self, path: &str) -> Result<()> {
        #[repr(C)]
        struct Attr {
            path_ptr: u64,
            fd:       u32,
        }

        let attr = Attr {
            path_ptr: path.as_ptr() as u64,
            fd:       self.fd,
        };

        match sys::bpf(BPF_OBJ_PIN, &attr) {
            (0, _) => Ok(()),
            (_, e) => Err(Error::from_raw_os_error(e)),
        }
    }
}

impl Drop for BpfMap {
    fn drop(&mut self) {
        match sys::close(self.fd) {
            (0, _) => (),
            // FIXME: do not panic
            x => panic!("close: {:?}", x),
        }
    }
}
