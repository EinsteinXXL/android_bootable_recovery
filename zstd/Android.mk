# zstd for TWRP -- vendored upstream source, built ONLY as the in-process static
# library libzstd_twrp (below).
#
# The standalone `zstd` CLI binary is deliberately NOT built: the pipeline, the
# image (/super dd) paths and the persistent log all compress in-process via
# libzstd_twrp, so nothing in recovery forks a zstd process. Leaving the binary
# out saves ~768 KB of ramdisk. The vendored programs/ sources stay in the tree
# (untouched by update_zstd.sh, and the CLI can be reinstated by adding a
# BUILD_EXECUTABLE block) -- they are simply not compiled.
#
# The pinned upstream version + verified source SHA-256 live in VERSION (see
# README.md). Refresh both with:  Tools/update_zstd.sh
#
# Source lists use all-c-files-under so a version bump via update_zstd.sh needs
# no edit here. lib/legacy and lib/dll are stripped by the updater (never built).
#
# SIMD / NEON: zstd auto-enables its ARM NEON paths whenever __ARM_NEON is defined,
# which the AOSP clang does for every aarch64 target (NEON is mandatory in AArch64)
# -- no opt-in flag is needed and none exists. -DZSTD_DISABLE_ASM below gates ONLY
# the x86_64 BMI2 .S assembly, NOT NEON (see lib/common/portability_macros.h); we do
# not set ZSTD_NO_INTRINSICS, so NEON stays compiled in. Caveat: the NEON row match
# finder (lib/compress/zstd_lazy.c) is only exercised at compression level >= ~5; the
# default backup level is 1 (ZSTD_fast, scalar -> NEON built in but cold on the hot
# path). Raising tw_zstd_level trades throughput for ratio (and would warm NEON).

LOCAL_PATH := $(call my-dir)

# ---------------------------------------------------------------------------
# Full in-process zstd static lib (libzstd_twrp) -- compress AND decompress.
# THE single zstd implementation in this build. Serves (a) the pipeline engine
# (stage_engine.cpp: run_zstd_compress/decompress), (b) the image paths via
# ZstdStream (/super backup + demo restore), (c) the persistent log (Copy_Log) and
# (d) the self-describing-backup peek (BackupHeaderManager: ZSTD_decompressStream).
# -DZSTD_MULTITHREAD is REQUIRED: the compress stage sets ZSTD_c_nbWorkers from the
# thread budget (compute_compressor_threads), the in-process equivalent of zstd's
# -T<n> flag. Static -> links into the recovery binary + twrpTar (NO .so -> no
# ramdisk-restage trap, unlike libtar).
# ---------------------------------------------------------------------------
include $(CLEAR_VARS)

LOCAL_MODULE := libzstd_twrp
LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    $(call all-c-files-under,lib/common) \
    $(call all-c-files-under,lib/compress) \
    $(call all-c-files-under,lib/decompress)

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/lib \
    $(LOCAL_PATH)/lib/common \
    $(LOCAL_PATH)/lib/compress \
    $(LOCAL_PATH)/lib/decompress

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/lib

LOCAL_CFLAGS := \
    -O3 \
    -DZSTD_MULTITHREAD \
    -DZSTD_LEGACY_SUPPORT=0 \
    -DZSTD_DISABLE_ASM=1 \
    -DXXH_NAMESPACE=ZSTD_ \
    -Wno-unused-function \
    -Wno-unused-parameter

include $(BUILD_STATIC_LIBRARY)
