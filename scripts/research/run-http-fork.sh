#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
kernel=$(realpath "${1:?Usage: run-http-fork.sh KERNEL [OUTPUT_DIRECTORY]}")
output=${2:-$(mktemp -d /tmp/ch-http-fork.XXXXXX)}
mkdir -p "$output/root"
output=$(realpath "$output")
cc -std=c11 -O2 -static -Wall -Wextra -Werror -DFORK_SERIAL_CONTROL \
    "$repo/scripts/research/linux-fork-init.c" -o "$output/root/init"
(cd "$output/root" && printf 'init\n' | cpio --quiet -o -H newc) > "$output/initramfs.cpio"
cargo build --manifest-path "$repo/Cargo.toml" -p cloud-hypervisor
python3 "$repo/scripts/research/test-http-fork.py" \
    "$repo/target/debug/cloud-hypervisor" "$kernel" "$output/initramfs.cpio" "$output"
