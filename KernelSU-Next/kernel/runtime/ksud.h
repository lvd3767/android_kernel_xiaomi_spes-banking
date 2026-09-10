#ifndef __KSU_H_KSUD
#define __KSU_H_KSUD

#include <linux/types.h>

#define KSUD_PATH "/data/adb/ksud"

void ksu_ksud_init();
void ksu_ksud_exit();

extern bool ksu_execveat_hook __read_mostly;

// Return-side handlers for fd-based fstat, used to spoof init.rc's reported
// size so init actually reads the appended KernelSU rc content. Implemented
// in ksud_integration.c, but previously never wired up anywhere in
// tracepoint-based (manual) hook mode.
struct stat;
struct stat64;
void ksu_handle_newfstat_ret(unsigned int *fd, struct stat __user **statbuf_ptr);
#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
void ksu_handle_fstat64_ret(unsigned long *fd, struct stat64 __user **statbuf_ptr);
#endif

#endif
