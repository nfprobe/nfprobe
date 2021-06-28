use std::collections::HashMap;
use nfprobe::{
    elf,
    Result,
};
use super::{
    Config,
    invalid_cmd,
    invalid_cmd_args,
};

fn usage() -> Result<()> {
    println!("Usage: nfprobe elf list-syms file sec");
    println!("       nfprobe elf resolve-syms file sec sym=val [sym=val]...");
    Ok(())
}

pub fn do_elf(args: &[&str], cfg: &Config) -> Result<()> {
    if args.is_empty() {
        return usage();
    }

    match args[0] {
        "list-syms" => do_list_syms(&args[1..], cfg),
        "resolve-syms" => do_resolve_syms(&args[1..], cfg),
        "help" => usage(),
        _ => invalid_cmd("elf", args[0]),
    }
}

fn print_syms(syms: Vec<elf::RelSym>) {
    if syms.is_empty() {
        println!("no template symbol found");
    } else {
        println!("{:5} {:5} {:18} {:<}", "offset", "idx", "value", "name");
        for sym in syms {
            println!(
                "{:06x} {:<5} 0x{:016x} {:<}",
                sym.file_off, sym.insn_idx, sym.value, sym.name
            );
        }
    }
}

fn do_list_syms(args: &[&str], _cfg: &Config) -> Result<()> {
    if args.len() != 2 {
        return invalid_cmd_args("elf", "list-sym");
    }

    let syms = elf::get_relsyms(args[0], args[1])?;
    print_syms(syms);

    Ok(())
}

fn do_resolve_syms(args: &[&str], _cfg: &Config) -> Result<()> {
    let invalid_args = invalid_cmd_args("elf", "resolve-syms");

    if args.len() <= 2 {
        return invalid_args;
    }

    let mut sym_vals: HashMap<&str, u64> = HashMap::new();
    for sym_val in args[2..].iter() {
        let parts: Vec<&str> = sym_val.split('=').collect();
        if parts.len() != 2 {
            return invalid_args;
        }

        let sym = parts[0];
        let val = parts[1].parse::<u64>()?;

        if sym_vals.insert(parts[0], val).is_some() {
            return Err(error!("canot have duplicated sym \"{}\"", sym));
        }
    }

    let syms = elf::resolve_relsyms(args[0], args[1], sym_vals)?;
    print_syms(syms);

    Ok(())
}
