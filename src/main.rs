/// `println!` that exits quietly when stdout is closed, e.g. by `| head`.
macro_rules! say {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        if writeln!(std::io::stdout(), $($arg)*).is_err() {
            std::process::exit(0);
        }
    }};
}

mod avb;
mod bootimg;
mod compress;
mod cpio;
mod dtb;
mod dtbo;
mod dtc;
mod info;
mod ramdisk;
mod util;

use clap::{Parser, Subcommand};
use std::{path::PathBuf, process::ExitCode};

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
    /// Show an image's layout and verify its AVB metadata
    Info { image: PathBuf },
    /// Run the bundled device tree compiler
    #[command(disable_help_flag = true)]
    Dtc {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Info { image } => info::show(&image),
        Command::Dtc { args } => return ExitCode::from(dtc_native::main(&args) as u8),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}
