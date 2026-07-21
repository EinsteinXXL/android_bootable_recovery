LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := hash_files.c
LOCAL_CFLAGS := -O2 -Wall -Wextra
LOCAL_MODULE := hash_files
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := RECOVERY_EXECUTABLES
LOCAL_MODULE_PATH := $(TARGET_RECOVERY_ROOT_OUT)/
LOCAL_PACK_MODULE_RELOCATIONS := false

LOCAL_SHARED_LIBRARIES := libcrypto

# Match listxattr linker handling so recovery executables resolve correctly.
ifneq ($(TARGET_ARCH), arm64)
    ifneq ($(TARGET_ARCH), x86_64)
        LOCAL_LDFLAGS += -Wl,-dynamic-linker,/system/bin/linker
    else
        LOCAL_LDFLAGS += -Wl,-dynamic-linker,/system/bin/linker64
    endif
else
    LOCAL_LDFLAGS += -Wl,-dynamic-linker,/system/bin/linker64
endif

include $(BUILD_EXECUTABLE)
