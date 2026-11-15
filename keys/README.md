The AOSP AVB test keys, from `external/avb/test/data` (Apache-2.0).

They are public, so anything signed with them is only accepted by unlocked
bootloaders. bootimgctl uses them to re-sign edited images when no `--key`
is given.
