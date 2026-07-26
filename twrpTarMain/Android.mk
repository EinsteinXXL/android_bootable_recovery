LOCAL_PATH:= $(call my-dir)

# Build static binary
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	twrpTarMain.cpp \
	../twrp-functions.cpp \
	../twrpTar.cpp \
	../backupheadermanager.cpp \
	../pipe_operation.cpp \
	../stage_engine.cpp \
	../stage_ring.cpp \
	../stage_io.c \
	../tw_bssl_aes/baes_stream.c \
	../tarWrite.c \
	../exclude.cpp \
	../progresstracking.cpp \
	../gui/twmsg.cpp
LOCAL_CFLAGS:= -g -c -W -DBUILD_TWRPTAR_MAIN -DUSE_FSCRYPT -Wno-unused-parameter -Wno-unused-function -Wno-error

LOCAL_C_INCLUDES += bionic
# twrpTarMain core: the engine sources (twrpTar/twrp-functions/pipe_operation) pull
# headers from the recovery tree + prebuilts.
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

# Full in-process zstd (compress + decompress): BackupHeaderManager decode
# (decode_head -> ZSTD_decompressStream) AND the pipeline engine
# (stage_engine.cpp: run_zstd_*) -> libzstd_twrp (bootable/recovery/zstd; exports
# <zstd.h>). libcrypto_static = BAES detection + baes_stream.c AEAD (already there).
LOCAL_STATIC_LIBRARIES := libc libtar_static libz libcrypto_static libzstd_twrp
ifeq ($(shell test $(PLATFORM_SDK_VERSION) -lt 23; echo $$?),0)
    LOCAL_C_INCLUDES += external/stlport/stlport bionic/libstdc++/include
    LOCAL_STATIC_LIBRARIES += libstlport_static
endif
# libstdc++ is NOT linked: it collides with libc++ (the default STL) on std::nothrow
# (duplicate symbol at the StaticExecutable link, new.cpp libstdc++ vs libc++).
# Crypto: twrpTar_static links libcrypto_static (NON-FIPS static BoringSSL) -> the full
# EVP/BAES path in twrp-functions.cpp (TW_EXCLUDE_ENCRYPTED_BACKUPS is board-gated
# below, not hardcoded).
# For that, //bootable/recovery/twrpTarMain was added to libcrypto_static.visibility
# (external/boringssl/Android.bp); the shared FIPS libcrypto (libcrypto.so, recovery) stays untouched.
# AES itself runs IN-PROCESS here too (baes_stream.c on a StageThread, no subprocess);
# libcrypto_static therefore serves both the detection AND the actual crypto.
# The board-gated exclude block below (TW_EXCLUDE_ENCRYPTED_BACKUPS=true) is kept as an opt-out.

LOCAL_C_INCLUDES += external/libselinux/include
LOCAL_STATIC_LIBRARIES += libselinux

ifneq ($(RECOVERY_SDCARD_ON_DATA),)
	LOCAL_CFLAGS += -DRECOVERY_SDCARD_ON_DATA
endif
ifeq ($(TW_EXCLUDE_ENCRYPTED_BACKUPS), true)
    LOCAL_CFLAGS += -DTW_EXCLUDE_ENCRYPTED_BACKUPS
endif
# Standalone twrpTar_static is a UTILITY_EXECUTABLE: not part of recovery.img, not
# shipped or tested as a product. Crypto IS wired (libcrypto_static above).

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
	../stage_engine.cpp \
	../stage_ring.cpp \
	../stage_io.c \
	../tw_bssl_aes/baes_stream.c \
	../tarWrite.c \
	../exclude.cpp \
	../progresstracking.cpp \
	../gui/twmsg.cpp
LOCAL_CFLAGS:= -g -c -W -DBUILD_TWRPTAR_MAIN -DUSE_FSCRYPT -Wno-unused-parameter -Wno-unused-function -Wno-error

LOCAL_C_INCLUDES += bionic
# twrpTarMain core: the engine sources (twrpTar/twrp-functions/pipe_operation) pull
# headers from the recovery tree + prebuilts.
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
# libstdc++ is NOT linked (libc++ = default STL, else a std::nothrow duplicate).
# libcrypto provides both the BAES detection and the actual AEAD implementation
# (baes_stream.c is in LOCAL_SRC_FILES above).
LOCAL_SHARED_LIBRARIES += libcrypto
# Full in-process zstd (compress + decompress): BackupHeaderManager decode
# (decode_head) + the pipeline engine (stage_engine.cpp) -> libzstd_twrp
# (bootable/recovery/zstd; exports <zstd.h>).
LOCAL_STATIC_LIBRARIES += libzstd_twrp

LOCAL_C_INCLUDES += external/libselinux/include
LOCAL_SHARED_LIBRARIES += libselinux

ifneq ($(RECOVERY_SDCARD_ON_DATA),)
	LOCAL_CFLAGS += -DRECOVERY_SDCARD_ON_DATA
endif
ifeq ($(TW_EXCLUDE_ENCRYPTED_BACKUPS), true)
    LOCAL_CFLAGS += -DTW_EXCLUDE_ENCRYPTED_BACKUPS
endif
# Standalone twrpTar (shared) is a UTILITY_EXECUTABLE: not part of recovery.img,
# not shipped or tested as a product. Crypto IS wired (libcrypto above).

LOCAL_MODULE:= twrpTar
LOCAL_MODULE_TAGS:= optional
LOCAL_MODULE_CLASS := UTILITY_EXECUTABLES
LOCAL_MODULE_PATH := $(PRODUCT_OUT)/utilities
include $(BUILD_EXECUTABLE)
