use elf_rs::{
    Elf,
    Elf64,
    GenElf,
    SectionHeader64,
};
use std::{
    collections::HashMap,
    fs::{
        self,
        File,
        OpenOptions,
    },
    io::{
        Seek,
        SeekFrom,
        Write,
    },
    mem,
    slice,
    str,
};
use super::Result;

const ELF_ENDIAN_LITTLE: u8 = 1;
const ELF_MACHINE_BPF: u16 = 247;
const SHT_PROGBITS: u32 = 0x1;
const SHN_UNDEF: u16 = 0;

#[repr(C)]
struct Sym64 {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
}

#[repr(C)]
struct Rel64 {
    r_offset: u64,
    r_info: u64,
}

impl Rel64 {
    fn sym_idx(&self) -> usize {
        (self.r_info >> 32) as usize
    }
}

#[repr(C)]
pub struct Insn {
    opcode: u8,
    srcdst: u8,
    offset: u16,
    imm: u32,
}

fn get_elems<'a, T>(elf: &'a Elf64, header: &SectionHeader64) -> &'a [T] {
    let off = header.sh_offset as isize;
    let num = header.sh_size as usize / mem::size_of::<T>();
    let ptr = elf.as_bytes() as *const _ as *const u8;
    unsafe { slice::from_raw_parts(ptr.offset(off) as *const T, num) }
}

fn get_str(strtab: &[u8], start: usize) -> &str {
    let len = strtab[start..].iter().position(|&x| x == b'\0').unwrap();
    unsafe { str::from_utf8_unchecked(&strtab[start..start + len]) }
}

fn get_section_name<'a>(elf: &'a Elf64, header: &SectionHeader64) -> &'a str {
    let strtab = elf.shstr_section();
    let start = header.sh_name as usize;
    get_str(strtab, start)
}

#[derive(Debug)]
pub struct RelSym {
    pub insn_idx: usize,
    pub file_off: u64,
    pub value: u64,
    pub name: String,
}

fn get_relsym(
    rel: &Rel64, sym: &Sym64, strtab: &[u8], insns: &[Insn], insns_off: usize
) -> RelSym {
    let idx = rel.r_offset as usize / mem::size_of::<Insn>();
    let val = u64::from(insns[idx + 1].imm) << 32 | u64::from(insns[idx].imm);
    RelSym {
        insn_idx: idx,
        file_off: insns_off as u64 + rel.r_offset,
        value: val,
        name: String::from(get_str(strtab, sym.st_name as usize)),
    }
}

pub fn get_relsyms(path: &str, sec_name: &str) -> Result<Vec<RelSym>> {
    let content = fs::read(path)?;
    let elf: Elf64 = match Elf::from_bytes(&content)? {
        Elf::Elf64(e) => e,
        _ => return Err(error!("invalid elf type")),
    };

    let elf_header = elf.header();
    if elf_header.endianness != ELF_ENDIAN_LITTLE {
        return Err(error!("invalid elf endianness"));
    }
    if elf_header.machine != ELF_MACHINE_BPF {
        return Err(error!("invalid elf machine"));
    }

    let section_headers = elf.section_headers();

    let (prog_index, prog_sec) = section_headers
        .iter()
        .enumerate()
        .find(|(_, s)| {
            s.sh_type == SHT_PROGBITS && get_section_name(&elf, s) == sec_name
        })
        .ok_or_else(|| error!("section {} not found", sec_name))?;

    let rel_sec = section_headers
        .iter()
        .find(|s| s.sh_info == prog_index as u32)
        .ok_or_else(|| error!("rel section for {} not found", sec_name))?;
    let sym_sec = &elf.section_headers()[rel_sec.sh_link as usize];
    let str_sec = &elf.section_headers()[sym_sec.sh_link as usize];

    let insns = get_elems::<Insn>(&elf, prog_sec);
    let rels = get_elems::<Rel64>(&elf, rel_sec);
    let syms = get_elems::<Sym64>(&elf, sym_sec);
    let strs = get_elems::<u8>(&elf, str_sec);

    let relsyms = rels
        .iter()
        .map(|r| (r, &syms[r.sym_idx()]))
        .filter(|(_, s)| s.st_shndx == SHN_UNDEF)
        .map(|(r, s)| {
            get_relsym(r, s, strs, insns, prog_sec.sh_offset as usize)
        })
        .collect();

    Ok(relsyms)
}

fn resolv_relsym(
    mut f: &File, s: &RelSym, sym_vals: &HashMap<&str, u64>
) -> Result<()> {
    let val = sym_vals
        .get(s.name.as_str())
        .ok_or_else(|| error!("sym {} not fount", s.name))?
        .to_le_bytes();

    f.seek(SeekFrom::Start(s.file_off + 4))?;
    f.write_all(&val[..4])?;
    f.seek(SeekFrom::Start(s.file_off + 12))?;
    f.write_all(&val[4..])?;

    Ok(())
}

pub fn resolve_relsyms(
    path: &str, sec_name: &str, sym_vals: HashMap<&str, u64>
) -> Result<Vec<RelSym>> {
    let f = OpenOptions::new().write(true).open(path)?;
    for s in get_relsyms(path, sec_name)? {
        resolv_relsym(&f, &s, &sym_vals)?;
    }
    get_relsyms(path, sec_name)
}
