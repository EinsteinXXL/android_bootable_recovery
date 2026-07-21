LOCAL_PATH:= $(call my-dir)

# Build static binary
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	twrpTarMain.cpp \
	../twrp-functions.cpp \
	../twrpTar.cpp \
	../backupheadermanager.cpp \
	../pipe_operation.cpp \
	../tarWrite.c \
	../exclude.cpp \
	../progresstracking.cpp \
	../gui/twmsg.cpp
LOCAL_CFLAGS:= -g -c -W -DBUILD_TWRPTAR_MAIN -DUSE_FSCRYPT -Wno-unused-parameter -Wno-unused-function -Wno-error

LOCAL_C_INCLUDES += bionic
# twrpTarMain core: the engine sources (twrpTar/twrp-functions/pipe_operation) pull
# headers from the recovery tree + prebuilts since the multi-pipe/crypto rework.
# Recovery root (tw_atomic.hpp/partitions.hpp), android-base, ziparchive (gui/pages.hpp),
# boringssl (BAES detection) -- like the main recovery module, ONLY the header paths.
LOCAL_C_INCLUDES += \
    $(LOCAL_PATH)/.. \
    $(LOCAL_PATH)/../gui/include \
    $(LOCAL_PATH)/../recovery_ui/include \
    $(LOCAL_PATH)/../otautil/include \
    $(LOCAL_PATH)/../install/include \
    $(LOCAL_PATH)/../fuse_sideload/include \
    $(LOCAL_PATH)/../twrpinstall/include \
    $(LOCAL_PATH)/../recovery_utils/include \
    $(LOCAL_PATH)/../libpixelflinger/include \
    $(LOCAL_PATH)/../minuitwrp/include \
    $(LOCAL_PATH)/../twinstall/include \
    system/core/base/include \
    system/core/libziparchive/include \
    external/boringssl/include \
    $(LOCAL_PATH)/../crypto/fscrypt \
    system/core/libcutils/include

# BackupHeaderManager: the dual-compiled class does in-process zstd decode
# (decode_head -> ZSTD_decompressStream) -> libzstddec_twrp (decode-only static lib,
# bootable/recovery/zstd; exports <zstd.h>). libcrypto_static = BAES detection (already there).
LOCAL_STATIC_LIBRARIES := libc libtar_static libz libcrypto_static libzstddec_twrp
ifeq ($(shell test $(PLATFORM_SDK_VERSION) -lt 23; echo $$?),0)
    LOCAL_C_INCLUDES += external/stlport/stlport bionic/libstdc++/include
    LOCAL_STATIC_LIBRARIES += libstlport_static
endif
# libstdc++ removed: it collides with libc++ (the default STL) on std::nothrow (duplicate symbol
# at the StaticExecutable link, new.cpp libstdc++ vs libc++).
# Crypto: twrpTar_static links libcrypto_static (NON-FIPS static BoringSSL) -> the full
# EVP/BAES path in twrp-functions.cpp (no more hardcoded -DTW_EXCLUDE_ENCRYPTED_BACKUPS).
# For that, //bootable/recovery/twrpTarMain was added to libcrypto_static.visibility
# (external/boringssl/Android.bp); the shared FIPS libcrypto (libcrypto.so, recovery) stays untouched.
# AES itself = the tw_bssl_aes subprocess (like shared); libcrypto_static is only for in-process detection.
# The board-gated exclude block below (TW_EXCLUDE_ENCRYPTED_BACKUPS=true) is kept as an opt-out.

LOCAL_C_INCLUDES += external/libselinux/include
LOCAL_STATIC_LIBRARIES += libselinux

ifneq ($(RECOVERY_SDCARD_ON_DATA),)
	LOCAL_CFLAGS += -DRECOVERY_SDCARD_ON_DATA
endif
ifeq ($(TW_EXCLUDE_ENCRYPTED_BACKUPS), true)
    LOCAL_CFLAGS += -DTW_EXCLUDE_ENCRYPTED_BACKUPS
endif
# OpenAES removed. Standalone twrpTar = UTILITY_EXECUTABLES (not in recovery.img, dormant):
# with crypto active the BAES path in twrp-functions.cpp would need libcrypto -- deliberately
# NOT wired here (the utility is not shipped/tested).

LOCAL_MODULE:= twrpTar_static
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_TAGS:= optional
LOCAL_MODULE_CLASS := UTILITY_EXECUTABLES
LOCAL_MODULE_PATH := $(PRODUCT_OUT)/utilities
include $(BUILD_EXECUTABLE)


# Build shared binary
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	twrpTarMain.cpp \
	../twrp-functions.cpp \
	../twrpTar.cpp \
	../backupheadermanager.cpp \
	../pipe_operation.cpp \
	../tarWrite.c \
	../exclude.cpp \
	../progresstracking.cpp \
	../gui/twmsg.cpp
LOCAL_CFLAGS:= -g -c -W -DBUILD_TWRPTAR_MAIN -DUSE_FSCRYPT -Wno-unused-parameter -Wno-unused-function -Wno-error

LOCAL_C_INCLUDES += bionic
# twrpTarMain core: the engine sources (twrpTar/twrp-functions/pipe_operation) pull
# headers from the recovery tree + prebuilts since the multi-pipe/crypto rework.
# Recovery root (tw_atomic.hpp/partitions.hpp), android-base, ziparchive (gui/pages.hpp),
# boringssl (BAES detection) -- like the main recovery module, ONLY the header paths.
LOCAL_C_INCLUDES += \
    $(LOCAL_PATH)/.. \
    $(LOCAL_PATH)/../gui/include \
    $(LOCAL_PATH)/../recovery_ui/include \
    $(LOCAL_PATH)/../otautil/include \
    $(LOCAL_PATH)/../install/include \
    $(LOCAL_PATH)/../fuse_sideload/include \
    $(LOCAL_PATH)/../twrpinstall/include \
    $(LOCAL_PATH)/../recovery_utils/include \
    $(LOCAL_PATH)/../libpixelflinger/include \
    $(LOCAL_PATH)/../minuitwrp/include \
    $(LOCAL_PATH)/../twinstall/include \
    system/core/base/include \
    system/core/libziparchive/include \
    external/boringssl/include \
    $(LOCAL_PATH)/../crypto/fscrypt \
    system/core/libcutils/include
LOCAL_SHARED_LIBRARIES := libc libtar libz
ifeq ($(shell test $(PLATFORM_SDK_VERSION) -lt 23; echo $$?),0)
    LOCAL_C_INCLUDES += external/stlport/stlport bionic/libstdc++/include
    LOCAL_SHARED_LIBRARIES += libstlport_static
endif
# libstdc++ removed (libc++ = default STL, else a std::nothrow duplicate); libcrypto = BAES detection.
LOCAL_SHARED_LIBRARIES += libcrypto
# BackupHeaderManager: in-process zstd decode (decode_head) -> libzstddec_twrp
# (decode-only static lib, bootable/recovery/zstd; exports <zstd.h>).
LOCAL_STATIC_LIBRARIES += libzstddec_twrp

LOCAL_C_INCLUDES += external/libselinux/include
LOCAL_SHARED_LIBRARIES += libselinux

ifneq ($(RECOVERY_SDCARD_ON_DATA),)
	LOCAL_CFLAGS += -DRECOVERY_SDCARD_ON_DATA
endif
ifeq ($(TW_EXCLUDE_ENCRYPTED_BACKUPS), true)
    LOCAL_CFLAGS += -DTW_EXCLUDE_ENCRYPTED_BACKUPS
endif
# OpenAES removed (see above). With crypto active twrpTar would need libcrypto;
# deliberately not wired (UTILITY, dormant, not shipped).

LOCAL_MODULE:= twrpTar
LOCAL_MODULE_TAGS:= optional
LOCAL_MODULE_CLASS := UTILITY_EXECUTABLES
LOCAL_MODULE_PATH := $(PRODUCT_OUT)/utilities
include $(BUILD_EXECUTABLE)
