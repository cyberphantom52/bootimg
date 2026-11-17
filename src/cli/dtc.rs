//! Device tree (de)compilation through the bundled dtc, which runs in a child
//! process of this executable (`bootimgctl dtc ...`) because it exits on errors.

use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

use crate::cli::{Error, Result};

fn run(args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>> {
    let exe = std::env::current_exe().map_err(Error::RunDtc)?;
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
        .map_err(Error::RunDtc)?;
    if let Some(input) = stdin {
        let mut pipe = child.stdin.take().unwrap();
        let input = input.to_vec();
        std::thread::spawn(move || pipe.write_all(&input));
    }
    let output = child.wait_with_output().map_err(Error::RunDtc)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Dtc(stderr.trim_end().to_string()));
    }
    Ok(output.stdout)
}

pub fn decompile(dtb: &[u8]) -> Result<String> {
    let dts = run(&["-q", "-I", "dtb", "-O", "dts", "-"], Some(dtb))?;
    Ok(String::from_utf8_lossy(&dts).into_owned())
}

pub fn compile(dts: &Path) -> Result<Vec<u8>> {
    let path = dts
        .to_str()
        .ok_or_else(|| Error::NonUtf8Path(dts.to_path_buf()))?;
    run(&["-q", "-I", "dts", "-O", "dtb", path], None)
}
