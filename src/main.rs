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
mod workspace;

use clap::{Parser, Subcommand};
use std::{path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(
    name = "bootimgctl",
    version,
    about = "Unpack, edit and repack Android boot, vendor_boot, vbmeta, dtbo and dtb images",
    after_help = "Typical use:\n  bootimgctl unpack boot.img\n  (edit files in boot/)\n  bootimgctl pack boot\n\n\
        Edited images are re-signed with the original AVB parameters, using the AOSP test key \
        of the original key size unless --key is given."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Unpack an image into an editable workspace directory
    Unpack {
        image: PathBuf,
        /// Workspace directory (default: the image name without its extension)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Replace an existing workspace
        #[arg(short, long)]
        force: bool,
    },
    /// Repack a workspace, rebuilding and re-signing what was edited
    Pack {
        workspace: PathBuf,
        /// Output image (default: <original name>.signed in the current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// RSA private key (PEM or DER) to sign with instead of the AOSP test key
        #[arg(long)]
        key: Option<PathBuf>,
        /// Also update this partition's hash in a vbmeta image, writing <vbmeta>.signed
        #[arg(long)]
        vbmeta: Option<PathBuf>,
    },
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
        Command::Unpack {
            image,
            output,
            force,
        } => {
            let output = output.unwrap_or_else(|| {
                let stem = image.file_stem().unwrap_or(image.as_os_str());
                PathBuf::from(stem)
            });
            workspace::unpack(&image, &output, force)
        }
        Command::Pack {
            workspace,
            output,
            key,
            vbmeta,
        } => workspace::pack(
            &workspace,
            &workspace::PackOptions {
                output: output.as_deref(),
                key: key.as_deref(),
                vbmeta: vbmeta.as_deref(),
            },
        ),
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
