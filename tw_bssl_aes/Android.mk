LOCAL_PATH:= $(call my-dir)

# tw_bssl_aes -- BoringSSL AEAD crypto (AES-256-GCM / ChaCha20-Poly1305).
# OpenAES is not supported: such backups are hard-rejected via REJECT_OPENAES and
# never decrypted.
#
# NO MODULE IS BUILT HERE.
#
# The streaming AEAD core lives in baes_stream.c and is compiled straight into the
# recovery binary and twrpTar (see the LOCAL_SRC_FILES lists in ../Android.mk and
# ../twrpTarMain/Android.mk: "tw_bssl_aes/baes_stream.c"), where stage_engine.cpp
# drives it in-process on a StageThread. A standalone filter binary would cost one
# process per encrypted pipeline and ~20 KB of ramdisk for no gain, so none is
# built.
#
# This file is pulled in by ../Android.mk's include chain and defines no module,
# which is harmless -- it keeps one obvious place to add a module for this
# directory from.
