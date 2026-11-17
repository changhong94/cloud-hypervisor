#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
kernel=$(realpath "${1:?Usage: run-linux-fork.sh KERNEL [OUTPUT_DIRECTORY]}")
output=${2:-$(mktemp -d /tmp/ch-linux-fork.XXXXXX)}
mkdir -p "$output/root"
output=$(realpath "$output")
cc -std=c11 -O2 -static -Wall -Wextra -Werror     "$repo/scripts/research/linux-fork-init.c" -o "$output/root/init"
(cd "$output/root" && printf 'init\n' | cpio --quiet -o -H newc) > "$output/initramfs.cpio"
cargo build --manifest-path "$repo/Cargo.toml" -p vmm --features kvm --example linux_fork
timeout 150s "$repo/target/debug/examples/linux_fork" "$kernel" "$output/initramfs.cpio" "$output" | tee "$output/results.log"
