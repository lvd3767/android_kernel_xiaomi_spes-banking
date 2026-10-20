#!/bin/bash
set -e
export PATH="$HOME/Bureau/workinprogress/Frozen_Kernel/clang-r596125-toolchain/bin:$PATH"
M="make O=out ARCH=arm64 LLVM=1 LLVM_IAS=1"

$M vendor/bengal-perf_defconfig
./scripts/kconfig/merge_config.sh -m -O out out/.config \
    arch/arm64/configs/vendor/xiaomi/spes.config \
    arch/arm64/configs/asano.config \
    arch/arm64/configs/vendor/asano.config \
    arch/arm64/configs/frozen-opts.config >/dev/null
$M olddefconfig >/dev/null

echo "SUSFS : $(grep -c '^CONFIG_KSU_SUSFS' out/.config) options (attendu : 10)"
grep -E "CONFIG_(KSU_SUSFS=|DEFAULT_IOSCHED|PSI=)" out/.config
