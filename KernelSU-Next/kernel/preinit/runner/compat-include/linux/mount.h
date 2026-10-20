/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Minimal shim for <linux/mount.h>, pulled in transitively by nolibc's
 * sys/mount.h (nolibc.h includes every sys/*.h unconditionally) even though
 * the preinit runner (runner.c) never actually calls mount(). This vendor
 * 4.19 kernel does not export a UAPI linux/mount.h at all (it predates the
 * new mount API / fsopen() headers upstream started shipping it for), so
 * there is nothing to -I in instead -- these MS_* flag values are the
 * original mount(2) ABI, unchanged since Linux 2.4, and are only here to
 * satisfy the #include, not because the runner uses any of them.
 */
#ifndef _LINUX_MOUNT_H
#define _LINUX_MOUNT_H

#define MS_RDONLY       1
#define MS_NOSUID       2
#define MS_NODEV        4
#define MS_NOEXEC       8
#define MS_SYNCHRONOUS  16
#define MS_REMOUNT      32
#define MS_MANDLOCK     64
#define MS_DIRSYNC      128
#define MS_NOATIME      1024
#define MS_NODIRATIME   2048
#define MS_BIND         4096
#define MS_MOVE         8192
#define MS_REC          16384
#define MS_SILENT       32768
#define MS_POSIXACL     (1<<16)
#define MS_UNBINDABLE   (1<<17)
#define MS_PRIVATE      (1<<18)
#define MS_SLAVE        (1<<19)
#define MS_SHARED       (1<<20)
#define MS_RELATIME     (1<<21)
#define MS_KERNMOUNT    (1<<22)
#define MS_I_VERSION    (1<<23)
#define MS_STRICTATIME  (1<<24)
#define MS_LAZYTIME     (1<<25)
#define MS_ACTIVE       (1<<30)
#define MS_NOUSER       (1<<31)

#endif /* _LINUX_MOUNT_H */
