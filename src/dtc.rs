//! Device tree (de)compilation through the bundled dtc, which runs in a child
//! process of this executable (`bootimgctl dtc ...`) because it exits on errors.

use anyhow::{Context, Result, bail};
use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

fn run(args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>> {
    let exe = std::env::current_exe().context("locating the bootimgctl executable")?;
    let mut child = Command::new(exe)
        .arg("dtc")
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("starting dtc")?;
    if let Some(input) = stdin {
        let mut pipe = child.stdin.take().unwrap();
        let input = input.to_vec();
        std::thread::spawn(move || pipe.write_all(&input));
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "dtc failed:\n{}",
            String::from_utf8_lossy(&output.stderr).trim_end()
        );
    }
    Ok(output.stdout)
}

pub fn decompile(dtb: &[u8]) -> Result<String> {
    let dts = run(&["-q", "-I", "dtb", "-O", "dts", "-"], Some(dtb))?;
    Ok(String::from_utf8(dts)?)
}

pub fn compile(dts: &Path) -> Result<Vec<u8>> {
    let path = dts.to_str().context("DTS path is not UTF-8")?;
    run(&["-q", "-I", "dts", "-O", "dtb", path], None)
        .with_context(|| format!("compiling {}", dts.display()))
}
