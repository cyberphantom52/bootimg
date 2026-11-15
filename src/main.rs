mod avb;
mod bootimg;
mod compress;
mod cpio;
mod dtb;
mod dtbo;
mod dtc;
mod ramdisk;
mod util;

use clap::{Parser, Subcommand};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "bootimgctl",
    version,
    about = "Unpack, edit and repack Android boot, vendor_boot, vbmeta, dtbo and dtb images"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the bundled device tree compiler
    #[command(disable_help_flag = true)]
    Dtc {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Dtc { args } => ExitCode::from(dtc_native::main(&args) as u8),
    }
}
