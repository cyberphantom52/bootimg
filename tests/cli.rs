//! End-to-end tests against images made by mkbootimg, avbtool and mkdtboimg
//! (see tests/data/generate.sh).

use serde_json::Value;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

const IMAGES: [&str; 3] = ["boot-v2.img", "boot-v4.img", "vendor_boot.img"];

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name)
}

fn run(args: &[&Path]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_bootimgctl"))
        .args(args)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout).into_owned()
        + &String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "bootimgctl {args:?} failed:\n{text}"
    );
    text
}

fn p(text: &str) -> &Path {
    Path::new(text)
}

/// Unpacks `image` into `<tmp>/ws` and returns the workspace path.
fn unpack(tmp: &Path, image: &Path) -> PathBuf {
    let ws = tmp.join("ws");
    run(&[p("unpack"), image, p("-o"), &ws]);
    ws
}

fn pack(ws: &Path, output: &Path, extra: &[&Path]) -> String {
    let mut args = vec![p("pack"), ws, p("-o"), output];
    args.extend_from_slice(extra);
    run(&args)
}

fn json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn entry<'a>(metadata: &'a Value, path: &str) -> Option<&'a Value> {
    metadata["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["path"] == path)
}

#[test]
fn untouched_workspaces_repack_to_the_original_bytes() {
    for name in IMAGES {
        let tmp = tempfile::tempdir().unwrap();
        let ws = unpack(tmp.path(), &fixture(name));
        let output = tmp.path().join("out.img");
        assert!(pack(&ws, &output, &[]).contains("No changes"));
        assert_eq!(
            fs::read(&output).unwrap(),
            fs::read(fixture(name)).unwrap(),
            "{name}"
        );
    }
}

#[test]
fn rebuilding_reproduces_the_reference_tools_output() {
    // Re-saving the metadata forces a full rebuild and re-sign from the
    // workspace; with the test keys the fixtures were made with, the result must
    // match the reference tools exactly.
    for name in IMAGES {
        let tmp = tempfile::tempdir().unwrap();
        let ws = unpack(tmp.path(), &fixture(name));
        let metadata = "image.json";
        let mut text = fs::read_to_string(ws.join(metadata)).unwrap();
        text.push('\n');
        fs::write(ws.join(metadata), &text).unwrap();
        let output = tmp.path().join("out.img");
        assert!(pack(&ws, &output, &[]).contains(&format!("Changed: {metadata}")));
        assert_eq!(
            fs::read(&output).unwrap(),
            fs::read(fixture(name)).unwrap(),
            "{name}"
        );
    }
}

#[test]
fn header_edits_and_component_replacements_are_applied() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = unpack(tmp.path(), &fixture("boot-v2.img"));
    let mut image = json(&ws.join("image.json"));
    image["header"]["cmdline"] = "console=null ".repeat(60).into(); // spills into extra_cmdline
    image["header"]["os_patch_level"] = "2025-01".into();
    fs::write(ws.join("image.json"), image.to_string()).unwrap();
    fs::write(ws.join("kernel"), vec![0x42; 30000]).unwrap();
    let key = Path::new(env!("CARGO_MANIFEST_DIR")).join("keys/testkey_rsa4096.pem");

    let output = tmp.path().join("boot.img");
    pack(&ws, &output, &[p("--key"), &key]);
    let info = run(&[p("info"), &output]);
    assert!(info.contains("patch level 2025-01"), "{info}");
    assert!(
        info.contains("SHA256_RSA4096, valid signature by AOSP testkey_rsa4096"),
        "{info}"
    );
    assert!(info.contains("boot hash: matches the image"), "{info}");
    assert!(
        info.contains("com.android.build.boot.os_version = 11"),
        "{info}"
    );

    let check = tmp.path().join("check");
    run(&[p("unpack"), &output, p("-o"), &check]);
    assert_eq!(
        json(&check.join("image.json"))["header"]["cmdline"],
        image["header"]["cmdline"]
    );
    assert_eq!(fs::read(check.join("kernel")).unwrap(), vec![0x42; 30000]);
    assert_eq!(
        fs::read(check.join("dtb")).unwrap(),
        fs::read(ws.join("dtb")).unwrap()
    );
}

#[test]
fn ramdisk_edits_keep_archive_metadata_and_are_re_signed() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = unpack(tmp.path(), &fixture("boot-v2.img"));
    let root = ws.join("ramdisk");
    assert_eq!(
        fs::read_link(root.join("system/bin/sh")).unwrap(),
        p("/system/bin/toybox")
    );
    fs::write(root.join("init.rc"), "on boot\n    start custom\n").unwrap();
    fs::write(root.join("custom.sh"), "#!/bin/sh\n").unwrap();
    fs::set_permissions(root.join("custom.sh"), fs::Permissions::from_mode(0o775)).unwrap();
    fs::create_dir(root.join("data")).unwrap();
    fs::remove_dir(root.join("sbin")).unwrap();

    let output = tmp.path().join("boot.img");
    let log = pack(&ws, &output, &[]);
    assert!(
        log.contains("Signed SHA256_RSA2048 with AOSP test key testkey_rsa2048"),
        "{log}"
    );
    let info = run(&[p("info"), &output]);
    assert!(
        info.contains("valid signature by AOSP testkey_rsa2048"),
        "{info}"
    );
    assert!(info.contains("boot hash: matches the image"), "{info}");

    let check = tmp.path().join("check");
    run(&[p("unpack"), &output, p("-o"), &check]);
    assert_eq!(
        fs::read_to_string(check.join("ramdisk/init.rc")).unwrap(),
        "on boot\n    start custom\n"
    );
    let metadata = json(&check.join("ramdisk.cpio.json"));
    assert_eq!(metadata["compression"], "gzip");
    let mode = |path| entry(&metadata, path).map(|e| e["mode"].as_str().unwrap().to_string());
    assert_eq!(mode("init").as_deref(), Some("100750"));
    assert_eq!(mode("custom.sh").as_deref(), Some("100755"));
    assert_eq!(mode("data").as_deref(), Some("40755"));
    assert_eq!(mode("system/bin/sh").as_deref(), Some("120777"));
    assert_eq!(mode("sbin"), None);
    assert_eq!(
        entry(&metadata, "dev/console").unwrap()["rdev"],
        serde_json::json!([5, 1])
    );
    assert_eq!(entry(&metadata, "system/bin").unwrap()["gid"], 2000);
}

#[test]
fn vendor_ramdisks_keep_their_compression_and_table_rows() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = unpack(tmp.path(), &fixture("vendor_boot.img"));
    let modules = ws.join("vendor_ramdisk.0/lib/modules");
    assert_eq!(
        fs::read(modules.join("a.ko")).unwrap(),
        fs::read(modules.join("b.ko")).unwrap()
    );
    fs::write(modules.join("c.ko"), "new module").unwrap();

    let output = tmp.path().join("vendor_boot.img");
    pack(&ws, &output, &[]);
    assert!(run(&[p("info"), &output]).contains("vendor_boot hash: matches the image"));

    let check = tmp.path().join("check");
    run(&[p("unpack"), &output, p("-o"), &check]);
    let metadata = json(&check.join("vendor_ramdisk.0.cpio.json"));
    assert_eq!(
        metadata["compression"],
        serde_json::json!({"xz": {"check": "crc32"}})
    );
    assert!(entry(&metadata, "lib/modules/c.ko").is_some());
    assert_eq!(
        fs::read(check.join("vendor_ramdisk.1.img")).unwrap(),
        fs::read(ws.join("vendor_ramdisk.1.img")).unwrap(),
        "the untouched ramdisk keeps its original bytes"
    );
    let rows = &json(&check.join("image.json"))["header"]["ramdisks"];
    assert_eq!(rows[1]["name"], "dlkm");
    assert_eq!(rows[1]["ramdisk_type"], 3);
    assert_eq!(rows[1]["board_id"][0], 0x1234);
}
