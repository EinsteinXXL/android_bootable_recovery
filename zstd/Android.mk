# zstd CLI -- built IN-TREE from vendored upstream source (BUILD_EXECUTABLE),
# mirroring the sibling pigz module. Replaces the former prebuilt blob.
#
# The pinned upstream version + verified source SHA-256 live in VERSION (see
# README.md). Refresh both with:  Tools/update_zstd.sh
#
# Build notes (each define matters):
#   -DZSTD_MULTITHREAD       REQUIRED. The backup/restore pipeline drives zstd
#                            with -T<N>; without this the CLI silently ignores -T.
#   -DZSTD_LEGACY_SUPPORT=0  No legacy (<= v0.7) decoder -- matches the old blob.
#   -DBACKTRACE_ENABLE=0     Bionic has no <execinfo.h>/backtrace(); programs/
#                            fileio.c would otherwise enable it under clang and
#                            fail the build. The guards key off !defined(...), so
#                            pre-defining 0 disables them cleanly.
#   -DZSTD_DISABLE_ASM=1     huf_decompress_amd64.S is x86_64-only and is NOT
#                            listed (all-c-files-under matches *.c only); keep the
#                            portable C decoder path on arm/arm64.
#   -DXXH_NAMESPACE=ZSTD_    Namespace xxhash symbols, consistent with upstream.
#
# Source lists use all-c-files-under so a version bump via update_zstd.sh needs
# no edit here. lib/legacy and lib/dll are stripped by the updater (never built).
#
# SIMD / NEON: zstd auto-enables its ARM NEON paths whenever __ARM_NEON is defined,
# which the AOSP clang does for every aarch64 target (NEON is mandatory in AArch64)
# -- no opt-in flag is needed and none exists. -DZSTD_DISABLE_ASM above gates ONLY
# the x86_64 BMI2 .S assembly, NOT NEON (see lib/common/portability_macros.h); we do
# not set ZSTD_NO_INTRINSICS, so NEON stays compiled in. Caveat: the NEON row match
# finder (lib/compress/zstd_lazy.c) is only exercised at compression level >= ~5; the
# default backup level is 1 (ZSTD_fast, scalar -> NEON built in but cold on the hot
# path). Raising tw_zstd_level trades throughput for ratio (and would warm NEON).

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := zstd
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := RECOVERY_EXECUTABLES
LOCAL_MODULE_PATH := $(TARGET_RECOVERY_ROOT_OUT)/system/bin

LOCAL_SRC_FILES := \
    $(call all-c-files-under,lib/common) \
    $(call all-c-files-under,lib/compress) \
    $(call all-c-files-under,lib/decompress) \
    $(call all-c-files-under,lib/dictBuilder) \
    $(call all-c-files-under,lib/deprecated) \
    $(call all-c-files-under,programs)

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/lib \
    $(LOCAL_PATH)/lib/common \
    $(LOCAL_PATH)/lib/compress \
    $(LOCAL_PATH)/lib/decompress \
    $(LOCAL_PATH)/lib/dictBuilder \
    $(LOCAL_PATH)/programs

LOCAL_CFLAGS := \
    -O3 \
    -DZSTD_MULTITHREAD \
    -DZSTD_LEGACY_SUPPORT=0 \
    -DBACKTRACE_ENABLE=0 \
    -DZSTD_DISABLE_ASM=1 \
    -DXXH_NAMESPACE=ZSTD_ \
    -Wno-unused-function \
    -Wno-unused-parameter

LOCAL_SHARED_LIBRARIES := libc

include $(BUILD_EXECUTABLE)

# ---------------------------------------------------------------------------
# Decode-only static lib (libzstddec_twrp) -- in-process zstd decompression for
# the self-describing-backup ead peek (P3). ONLY lib/common + lib/decompress; NO
# lib/compress and therefore NO -DZSTD_MULTITHREAD (zstd decode is single-threaded
# -- there is no MT decode, -T applies only to compress). Static -> links into the
# recovery binary (NO .so -> no ramdisk-restage trap, unlike libtar). The zstd
# binary above stays untouched (own sources, separate link unit -> no symbol
# collision; XXH_NAMESPACE consistent).
# ---------------------------------------------------------------------------
include $(CLEAR_VARS)

LOCAL_MODULE := libzstddec_twrp
LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    $(call all-c-files-under,lib/common) \
    $(call all-c-files-under,lib/decompress)

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/lib \
    $(LOCAL_PATH)/lib/common \
    $(LOCAL_PATH)/lib/decompress

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/lib

LOCAL_CFLAGS := \
    -O3 \
    -DZSTD_LEGACY_SUPPORT=0 \
    -DZSTD_DISABLE_ASM=1 \
    -DXXH_NAMESPACE=ZSTD_ \
    -Wno-unused-function \
    -Wno-unused-parameter

include $(BUILD_STATIC_LIBRARY)
