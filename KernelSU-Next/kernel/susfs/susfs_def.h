#ifndef _SUSFS_DEF_H
#define _SUSFS_DEF_H

#include <linux/types.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/jump_label.h>
#include <linux/cred.h>
#include <linux/thread_info.h>
#include <linux/bits.h>

#define SUSFS_MAGIC 0xFAFAFAFA

#define CMD_SUSFS_ADD_SUS_PATH              0x55550
#define CMD_SUSFS_ADD_SUS_PATH_LOOP         0x55553
#define CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS 0x55561
#define CMD_SUSFS_ADD_SUS_KSTAT             0x55570
#define CMD_SUSFS_UPDATE_SUS_KSTAT          0x55571
#define CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY  0x55572
#define CMD_SUSFS_ADD_TRY_UMOUNT            0x55580
#define CMD_SUSFS_SET_UNAME                 0x55590
#define CMD_SUSFS_ENABLE_LOG                0x555a0
#define CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG 0x555b0
#define CMD_SUSFS_ADD_OPEN_REDIRECT         0x555c0
#define CMD_SUSFS_SHOW_VERSION              0x555e1
#define CMD_SUSFS_SHOW_ENABLED_FEATURES     0x555e2
#define CMD_SUSFS_SHOW_VARIANT              0x555e3
#define CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING   0x60010
#define CMD_SUSFS_ADD_SUS_MAP               0x60020

#define SUSFS_MAX_LEN_PATHNAME 256
#define SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE 8192
#define SUSFS_ENABLED_FEATURES_SIZE 8192
#define SUSFS_MAX_VERSION_BUFSIZE 16
#define SUSFS_MAX_VARIANT_BUFSIZE 16

#define VFSMOUNT_MNT_FLAGS_KSU_UNSHARED_MNT 0x80000000
#define DEFAULT_KSU_MNT_ID 2000000000
#define DEFAULT_KSU_MNT_GROUP_ID 200000

#ifndef FUSE_SUPER_MAGIC
#define FUSE_SUPER_MAGIC 0x65735546
#endif

#define TIF_PROC_UMOUNTED 33

#define AS_FLAGS_SUS_PATH 33
#define AS_FLAGS_SUS_MOUNT 34
#define AS_FLAGS_SUS_KSTAT 35
#define AS_FLAGS_OPEN_REDIRECT 36
#define AS_FLAGS_SUS_MAP 39

#define ND_STATE_LOOKUP_LAST 32
#define ND_STATE_OPEN_LAST 64
#define ND_FLAGS_LOOKUP_LAST 0x2000000

static inline bool susfs_starts_with(const char *str, const char *prefix)
{
	while (*prefix)
		if (*str++ != *prefix++)
			return false;
	return true;
}

static inline bool susfs_is_current_proc_umounted(void)
{
	return unlikely(test_thread_flag(TIF_PROC_UMOUNTED));
}

static inline void susfs_set_current_proc_umounted(void)
{
	set_thread_flag(TIF_PROC_UMOUNTED);
}

static inline bool susfs_is_current_proc_umounted_app(void)
{
	return unlikely(test_thread_flag(TIF_PROC_UMOUNTED)) &&
		__kuid_val(current_uid()) >= 10000;
}

#define SUSFS_IS_INODE_SUS_MAP(inode) \
	inode && inode->i_mapping && \
	unlikely(test_bit(AS_FLAGS_SUS_MAP, &inode->i_state)) && \
	susfs_is_current_proc_umounted_app()

#define SUSFS_IS_INODE_OPEN_REDIRECT_WITHOUT_UID_CHECK(inode) \
	inode && inode->i_mapping && \
	unlikely(test_bit(AS_FLAGS_OPEN_REDIRECT, &inode->i_state))

#define SUSFS_IS_INODE_OPEN_REDIRECT(inode) \
	inode && inode->i_mapping && \
	unlikely(test_bit(AS_FLAGS_OPEN_REDIRECT, &inode->i_state)) && \
	susfs_is_current_proc_umounted_app()

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
#define SUSFS_DECL_FSNOTIFY_OPS(name) \
int name(struct fsnotify_mark *mark, u32 mask, struct inode *inode, \
struct inode *dir, const struct qstr *file_name, u32 cookie)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
#define SUSFS_DECL_FSNOTIFY_OPS(name) \
int name(struct fsnotify_group *group, struct inode *inode, u32 mask, \
const void *data, int data_type, const struct qstr *file_name, \
u32 cookie, struct fsnotify_iter_info *iter_info)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
#define SUSFS_DECL_FSNOTIFY_OPS(name) \
int name(struct fsnotify_group *group, struct inode *inode, u32 mask, \
const void *data, int data_type, const struct qstr *file_name, \
u32 cookie, struct fsnotify_iter_info *iter_info)
#else
#define SUSFS_DECL_FSNOTIFY_OPS(name) \
int name(struct fsnotify_group *group, struct inode *inode, \
struct fsnotify_mark *inode_mark, \
struct fsnotify_mark *vfsmount_mark, u32 mask, void *data, \
int data_type, const unsigned char *file_name, u32 cookie)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
typedef const struct qstr *susfs_fname_t;
#define susfs_fname_len(f) ((f)->len)
#define susfs_fname_arg(f) ((f)->name)
#else
typedef const unsigned char *susfs_fname_t;
#define susfs_fname_len(f) (strlen(f))
#define susfs_fname_arg(f) (f)
#endif

#endif /* _SUSFS_DEF_H */
