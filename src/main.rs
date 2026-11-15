use clap::Parser;

#[derive(Parser)]
#[command(
    name = "bootimgctl",
    version,
    about = "Unpack, edit and repack Android boot, vendor_boot, vbmeta, dtbo and dtb images"
)]
struct Cli {}

fn main() {
    Cli::parse();
}
