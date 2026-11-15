#!/usr/bin/env bash
# Regenerates the test images with the AOSP reference tools, so the tests can
# check that bootimgctl reproduces their output byte for byte.
#
# Usage: AOSP=<dir with system/tools/mkbootimg, avb, system/libufdt> tests/data/generate.sh
# Needs python3, lz4, xz and a built bootimgctl (for its bundled dtc).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
mkbootimg="python3 $AOSP/system/tools/mkbootimg/mkbootimg.py"
avbtool="python3 $AOSP/avb/avbtool.v1.2.py"
mkdtboimg="python3 $AOSP/system/libufdt/utils/src/mkdtboimg.py"
dtc="$root/target/debug/bootimgctl dtc"
keys="$root/keys"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

# A newc archive with root ownership, odd modes, a symlink, a hardlink pair and
# a device node: things an unprivileged host tree can't hold.
python3 - <<'EOF'
import struct
def entry(name, mode, data=b"", ino=0, nlink=1, rdev=(0, 0), uid=0, gid=0):
    fields = [ino, mode, uid, gid, nlink, 0, len(data), 0, 0, rdev[0], rdev[1], len(name) + 1, 0]
    out = b"070701" + b"".join(b"%08x" % f for f in fields) + name.encode() + b"\0"
    out += b"\0" * (-len(out) % 4) + data
    return out + b"\0" * (-len(out) % 4)
def archive(entries):
    data = b"".join(entry(*e[:3], **{"ino": i + 1, **(e[3] if len(e) > 3 else {})})
                    for i, e in enumerate(entries))
    return data + entry("TRAILER!!!", 0, nlink=1)
first = archive([
    ("dev", 0o40755),
    ("dev/console", 0o20600, b"", {"rdev": (5, 1)}),
    ("init", 0o100750, b"#!/bin/sh\necho init\n"),
    ("init.rc", 0o100644, b"on boot\n    start adbd\n"),
    ("system", 0o40755),
    ("system/bin", 0o40751, b"", {"gid": 2000}),
    ("system/bin/sh", 0o120777, b"/system/bin/toybox"),
    ("sbin", 0o40750),
])
open("ramdisk.cpio", "wb").write(first)
open("vendor0.cpio", "wb").write(archive([
    ("lib", 0o40755),
    ("lib/modules", 0o40755),
    ("lib/modules/a.ko", 0o100644, b"", {"ino": 50, "nlink": 2}),
    ("lib/modules/b.ko", 0o100644, b"module data" * 20, {"ino": 50, "nlink": 2}),
]))
open("vendor1.cpio", "wb").write(archive([("fstab", 0o100640, b"/dev/block/by-name/system /system ext4 ro\n")]))
import random
random.seed(1)
open("kernel", "wb").write(bytes(random.getrandbits(8) for _ in range(9000)))
open("second", "wb").write(b"second stage" * 50)
EOF
gzip -9 -n -c ramdisk.cpio > ramdisk.gz
lz4 -l -12 -q -c ramdisk.cpio > ramdisk.lz4
xz --check=crc32 -c vendor0.cpio > vendor0.xz
lz4 -l -12 -q -c vendor1.cpio > vendor1.lz4

cat > board.dts <<'EOF'
/dts-v1/;
/ { model = "Test board"; compatible = "test,board"; #address-cells = <1>; #size-cells = <1>;
    memory@80000000 { device_type = "memory"; reg = <0x80000000 0x10000000>; }; };
EOF
cat > overlay.dts <<'EOF'
/dts-v1/;
/plugin/;
&{/} { overlay-property = "enabled"; };
EOF
$dtc -q -I dts -O dtb -o board.dtb board.dts
$dtc -q -I dts -O dtb -o overlay.dtb overlay.dts
cat board.dtb board.dtb > dtb.bundle

# Boot v2, 2048-byte pages, with every legacy component and a signed AVB footer.
$mkbootimg --header_version 2 --pagesize 2048 --kernel kernel --ramdisk ramdisk.gz \
    --second second --recovery_dtbo overlay.dtb --dtb dtb.bundle --board testboard \
    --cmdline "console=ttyMSM0 androidboot.hardware=test" --os_version 11.0.0 \
    --os_patch_level 2021-06 --base 0x80000000 --output "$here/boot-v2.img"
$avbtool add_hash_footer --image "$here/boot-v2.img" --partition_size 196608 \
    --partition_name boot --algorithm SHA256_RSA2048 --key "$keys/testkey_rsa2048.pem" \
    --salt 00112233 --prop com.android.build.boot.os_version:11

# Boot v4 with an lz4 ramdisk and an unsigned footer, as GKI devices ship init_boot.
$mkbootimg --header_version 4 --kernel kernel --ramdisk ramdisk.lz4 \
    --cmdline "androidboot.selinux=permissive" --os_version 14.0.0 \
    --os_patch_level 2024-05 --output "$here/boot-v4.img"
$avbtool add_hash_footer --image "$here/boot-v4.img" --partition_size 196608 \
    --partition_name boot --salt 44556677

# Vendor boot v4 with two table entries, a DTB and bootconfig, signed with SHA512.
printf 'androidboot.hardware=test\n' > bootconfig
$mkbootimg --header_version 4 --pagesize 4096 --vendor_cmdline "loglevel=4" \
    --board vendor --dtb board.dtb --vendor_bootconfig bootconfig \
    --ramdisk_type platform --ramdisk_name "" --vendor_ramdisk_fragment vendor0.xz \
    --ramdisk_type dlkm --ramdisk_name dlkm --board_id0 0x1234 \
    --vendor_ramdisk_fragment vendor1.lz4 --vendor_boot "$here/vendor_boot.img"
$avbtool add_hash_footer --image "$here/vendor_boot.img" --partition_size 262144 \
    --partition_name vendor_boot --algorithm SHA512_RSA4096 \
    --key "$keys/testkey_rsa4096.pem" --salt 8899aabb

# Top-level vbmeta holding the vendor_boot hash and a chain to boot.
$avbtool extract_public_key --key "$keys/testkey_rsa2048.pem" --output boot.avbpubkey
$avbtool make_vbmeta_image --output "$here/vbmeta.img" --algorithm SHA256_RSA4096 \
    --key "$keys/testkey_rsa4096.pem" --rollback_index 7 \
    --include_descriptors_from_image "$here/vendor_boot.img" \
    --chain_partition boot:1:boot.avbpubkey --padding_size 4096

# DTBO (version 1) with a duplicated entry and a zlib-compressed one.
$mkdtboimg create "$here/dtbo.img" --version=1 --page_size=4096 \
    overlay.dtb --id=0x10 --rev=0x1 \
    overlay.dtb --id=0x11 \
    board.dtb --id=0x12 --flags=1

cp dtb.bundle "$here/board.dtb"
