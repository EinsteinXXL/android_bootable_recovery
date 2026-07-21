LOCAL_PATH := $(call my-dir)

# Build libtwrpmtp library

include $(CLEAR_VARS)
LOCAL_MODULE := libtwrpmtp-ffs
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS = -D_FILE_OFFSET_BITS=64 -DMTP_DEVICE -DMTP_HOST -fno-strict-aliasing \
    -Wno-unused-variable -Wno-format -Wno-unused-parameter -Wno-unused-private-field \
    -Wno-implicit-fallthrough
LOCAL_C_INCLUDES += $(LOCAL_PATH) bionic \
    frameworks/base/include \
    system/core/include \
    bionic/libc/private/ \
    bootable/recovery/twrplibusbhost/include \
    bootable/recovery/twrpinstall/include

LOCAL_SHARED_LIBRARIES += libc++
LOCAL_STATIC_LIBRARIES += libtwrpinstall

LOCAL_SRC_FILES = \
    MtpDataPacket.cpp \
    MtpDebug.cpp \
    MtpDevice.cpp \
    MtpDevHandle.cpp \
    MtpDeviceInfo.cpp \
    MtpEventPacket.cpp \
    MtpObjectInfo.cpp \
    MtpPacket.cpp \
    MtpProperty.cpp \
    MtpRequestPacket.cpp \
    MtpResponsePacket.cpp \
    MtpServer.cpp \
    MtpStorage.cpp \
    MtpStorageInfo.cpp \
    MtpStringBuffer.cpp \
    MtpUtils.cpp \
    mtp_MtpServer.cpp \
    btree.cpp \
    twrpMtp.cpp \
    mtp_MtpDatabase.cpp \
    node.cpp

ifeq ($(shell test $(PLATFORM_SDK_VERSION) -gt 25; echo $$?),0)
    LOCAL_CFLAGS += -D_FFS_DEVICE
    LOCAL_SHARED_LIBRARIES += libasyncio
    LOCAL_SRC_FILES += \
        MtpDescriptors.cpp \
        MtpFfsHandle.cpp \
        MtpFfsCompatHandle.cpp \
        PosixAsyncIO.cpp
endif

LOCAL_SHARED_LIBRARIES += libz \
                          libc \
                          libusbhost \
                          libstdc++ \
                          libdl \
                          libcutils \
                          libutils \
                          libselinux \
                          libbase \
                          liblog

LOCAL_C_INCLUDES += bootable/recovery/twrplibusbhost/include

ifneq ($(TW_MTP_DEVICE),)
	LOCAL_CFLAGS += -DUSB_MTP_DEVICE=$(TW_MTP_DEVICE)
endif

# TWRP CPU affinity (only the two flags the MTP module reads).
# TW_USE_CPU_AFFINITY: bool flag, compile-time eval like the main Android.mk
# (true/1/yes/on -> -DFLAG=1, false/0/no/off -> no define, else a warning).
ifneq ($(TW_USE_CPU_AFFINITY),)
    _tw_mtp_use_cpu_affinity_lc := $(shell echo "$(TW_USE_CPU_AFFINITY)" | tr '[:upper:]' '[:lower:]')
    ifneq ($(filter true 1 yes on,$(_tw_mtp_use_cpu_affinity_lc)),)
        LOCAL_CFLAGS += -DTW_USE_CPU_AFFINITY=1
    else
        ifeq ($(filter false 0 no off,$(_tw_mtp_use_cpu_affinity_lc)),)
            $(warning TW_USE_CPU_AFFINITY="$(TW_USE_CPU_AFFINITY)" not recognized (expected true/1/yes/on or false/0/no/off) -- treated as false)
        endif
    endif
endif
ifneq ($(TW_AFFINITY_MTP_CORE),)
    LOCAL_CFLAGS += -DTW_AFFINITY_MTP_CORE=$(TW_AFFINITY_MTP_CORE)
endif
ifeq ($(shell test $(PLATFORM_SDK_VERSION) -gt 25; echo $$?),0)
    LOCAL_CFLAGS += -DHAS_USBHOST_TIMEOUT
endif

include $(BUILD_SHARED_LIBRARY)
