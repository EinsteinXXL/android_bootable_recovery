LOCAL_PATH:= $(call my-dir)

# tw_bssl_aes -- BoringSSL AEAD encrypt/decrypt filter (AES-256-GCM / ChaCha20-Poly1305).
# OpenAES has been removed entirely (old OpenAES backups are hard-rejected via
# REJECT_OPENAES, no decrypt).
#
# Built UNLESS TW_EXCLUDE_ENCRYPTED_BACKUPS := true (= backup encryption off).
# Empty/false/any other value => crypto ON (default).
ifneq ($(TW_EXCLUDE_ENCRYPTED_BACKUPS), true)
	include $(CLEAR_VARS)
	LOCAL_MODULE := tw_bssl_aes
	LOCAL_MODULE_PATH := $(TARGET_RECOVERY_ROOT_OUT)/system/bin
	LOCAL_MODULE_TAGS := optional
	LOCAL_SRC_FILES := tw_bssl_aes.c
	LOCAL_C_INCLUDES := external/boringssl/src/include
	LOCAL_SHARED_LIBRARIES := libcrypto libc
	LOCAL_CFLAGS := -Wall -Wextra -O2
	include $(BUILD_EXECUTABLE)
endif
