#[macro_use]
extern crate nfprobe;

mod elf;
mod bpf;

use std::env;
use nfprobe::Result;

pub fn invalid_cmd(obj: &str, cmd: &str) -> Result<()> {
    Err(error!(
        "Command \"{}\" is unknown, try \"nfprobe {} help\".",
        cmd, obj
    ))
}

pub fn invalid_cmd_args(obj: &str, cmd: &str) -> Result<()> {
    Err(error!(
        "Invalid args for command \"{}\", try \"nfprobe {} help\".",
        cmd, obj
    ))
}

#[derive(Debug, Default)]
pub struct Config {
    pub json: bool,
}

fn usage() -> Result<()> {
    println!("Usage: nfprobe [ OPTIONS ] OBJECT {{ COMMAND | help }}");
    println!("where  OBJECT := {{ elf | bpf | stats | metrics }}");
    println!("       OPTIONS := {{ -V[ersion] | -j[son] }}");
    Ok(())
}

fn do_cmd(args: &[&str], cfg: &Config) -> Result<()> {
    match args[0] {
        "elf" => elf::do_elf(&args[1..], cfg),
        "bpf" => bpf::do_bpf(&args[1..], cfg),
        "help" => usage(),
        _ => Err(error!(
            "Object \"{}\" is unknown, try \"nfprobe help\".", args[0]
        )),
    }
}

fn _main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut cfg: Config = Default::default();
    let mut i = 1;

    while i < args.len() {
        let arg = args[i];

        if !arg.starts_with('-') {
            return do_cmd(&args[i..], &cfg);
        }

        if "-Version".starts_with(arg) {
            println!("nfprobe-{}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }

        if "-json".starts_with(arg) {
            cfg.json = true;
        } else {
            return Err(error!(
                "Option \"{}\" is unknown, try \"nfprobe help\".", arg
            ))
        }

        i += 1;
    }

    usage()
}

fn main() {
    let ret = match _main() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{}", e.msg);
            -1
        }
    };
    std::process::exit(ret);
}
