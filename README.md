# bootimgctl

Unpack, edit and repack Android boot images: a single self-contained binary in
the spirit of [Android_boot_image_editor](https://github.com/cfig/Android_boot_image_editor),
with no Java, Python or external tools needed at runtime.

```console
$ bootimgctl unpack boot.img          # creates boot/
$ $EDITOR boot/ramdisk/init.rc        # edit files, headers, device trees...
$ bootimgctl pack boot                # writes boot.img.signed
```

## Supported images

| Image | Detected by | Editable |
|---|---|---|
| boot, init_boot, recovery (header v0–v4) | `ANDROID!` | header, kernel, ramdisk tree, second, recovery DTBO, DTB |
| vendor_boot, vendor_kernel_boot (v3–v4) | `VNDRBOOT` | header, ramdisk table and trees, DTB, bootconfig |
| vbmeta, vbmeta_system, ... | `AVB0` | all vbmeta fields and descriptors |
| dtbo | DTBO table magic | table entries, one DTS per overlay |
| dtb | FDT magic | one DTS per tree |

Images are recognized by their contents, not their names. AVB hash footers are
handled on all of them.

## The workspace

`unpack` writes everything editable into a directory:

- `image.json`: header fields such as `cmdline`, `os_version`, `os_patch_level`,
  load addresses and the vendor ramdisk table.
- `avb.json`: AVB metadata from the footer or vbmeta image. This includes flags
  (set `flags` to 2 to disable verification), rollback index, properties and
  descriptors.
- Raw components: `kernel`, `second`, `dtb`, `bootconfig`, ...
- Ramdisks:
  - `ramdisk.img`: the original compressed ramdisk.
  - `ramdisk/`: the extracted tree.
  - `ramdisk.cpio.json`: compression and per-entry mode, owner and device numbers.
  - Vendor ramdisks are named `vendor_ramdisk.N`.
- Device trees: `dtb.dts` (or `dtb.N.dts` for multi-tree blobs) and
  `dtbo.N.dts`, decompiled with the bundled dtc.

`pack` rebuilds only what you changed. Detection is by comparing against what
`unpack` wrote. An untouched workspace packs back to the identical image.

- **Ramdisks:** edit the tree, or replace `ramdisk.img`, but not both.
  - Entries keep their recorded mode and ownership unless you `chmod` them.
  - New files are owned by root with mode 0644, or 0755 if executable. To set
    other values, add their entry to `ramdisk.cpio.json`.
  - The ramdisk is recompressed in its original format, keeping the xz check
    type and using lz4 legacy HC.
- **Device trees:** edit the `.dts`, or replace the blob, but not both.
- **Vendor ramdisk table:** add, remove or reorder rows in `image.json`. Each
  row names its ramdisk.

## Signing

An edited image keeps its AVB footer parameters: partition size, salt, flags,
rollback index, properties and release string. It is re-signed with the AOSP
test key of the original key size, matching `avbtool`'s output byte for byte.
Footers using algorithm NONE stay unsigned. Use `--key` to sign with your own
RSA key instead.

Boot v4 GKI boot signatures are regenerated the same way.

When the partition's hash lives in a vbmeta image, pass that image with
`--vbmeta`. pack then writes an updated, re-signed copy next to the output:

```console
$ bootimgctl pack vendor_boot --vbmeta vbmeta.img   # vendor_boot.img.signed, vbmeta.img.signed
```

Test-key signatures are only accepted by unlocked bootloaders.

`bootimgctl info IMAGE` shows an image's layout, AVB descriptors, and whether
signatures and hashes verify.

## Building

```console
$ git clone --recursive ...
$ cargo build --release
```

A C compiler is needed for the bundled [dtc](https://git.kernel.org/pub/scm/utils/dtc/dtc.git)
(`crates/dtc-native`) and the compression libraries.

## Testing

The test images in `tests/data` are made with the AOSP reference tools
(`mkbootimg`, `avbtool`, `mkdtboimg`) by `tests/data/generate.sh`. The tests
check that rebuilding them reproduces those tools' output exactly.

## License

GPL-3.0-or-later. The bundled dtc is GPL-2.0-or-later. `keys/` holds the
public AOSP AVB test keys (Apache-2.0).
