#ifndef _SUSFS_H
#define _SUSFS_H

#include <linux/version.h>
#include <linux/types.h>
#include <linux/utsname.h>
#include <linux/hashtable.h>
#include <linux/path.h>
#include <linux/statfs.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include "susfs_def.h"

struct mount;

#define SUSFS_VERSION "v2.2.0"
#define SUSFS_VARIANT "Standalone"

enum UID_SCHEME {
	UID_NON_APP_PROC = 0,
	UID_ROOT_PROC_EXCEPT_SU_PROC,
	UID_NON_SU_PROC,
	UID_UMOUNTED_APP_PROC,
	UID_UMOUNTED_PROC,
};

#ifdef CONFIG_KSU_SUSFS_SUS_PATH
struct st_susfs_sus_path {
	char  target_pathname[SUSFS_MAX_LEN_PATHNAME];
	int   err;
};

struct st_susfs_sus_path_list {
	struct list_head         list;
	struct st_susfs_sus_path info;
	char                     target_pathname[SUSFS_MAX_LEN_PATHNAME];
};
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
struct st_susfs_hide_sus_mnts_for_non_su_procs {
	bool enabled;
	int  err;
};
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
#define KSTAT_SPOOF_INO        (1 << 0)
#define KSTAT_SPOOF_DEV        (1 << 1)
#define KSTAT_SPOOF_NLINK      (1 << 2)
#define KSTAT_SPOOF_SIZE       (1 << 3)
#define KSTAT_SPOOF_ATIME_TV_SEC  (1 << 4)
#define KSTAT_SPOOF_ATIME_TV_NSEC (1 << 5)
#define KSTAT_SPOOF_MTIME_TV_SEC  (1 << 6)
#define KSTAT_SPOOF_MTIME_TV_NSEC (1 << 7)
#define KSTAT_SPOOF_CTIME_TV_SEC  (1 << 8)
#define KSTAT_SPOOF_CTIME_TV_NSEC (1 << 9)
#define KSTAT_SPOOF_BLOCKS     (1 << 10)
#define KSTAT_SPOOF_BLKSIZE    (1 << 11)

struct st_susfs_sus_kstat {
	int            is_statically;
	unsigned long  target_ino;
	char           target_pathname[SUSFS_MAX_LEN_PATHNAME];
	unsigned long  spoofed_ino;
	unsigned long  spoofed_dev;
	unsigned int   spoofed_nlink;
	long long      spoofed_size;
	long           spoofed_atime_tv_sec;
	unsigned long  spoofed_atime_tv_nsec;
	long           spoofed_mtime_tv_sec;
	unsigned long  spoofed_mtime_tv_nsec;
	long           spoofed_ctime_tv_sec;
	unsigned long  spoofed_ctime_tv_nsec;
	long long      spoofed_blocks;
	long           spoofed_blksize;
	int            flags;
	int            err;
};

struct st_susfs_sus_kstat_hlist {
	unsigned long              target_ino;
	unsigned long              target_dev;
	bool                       is_fuse;
	struct st_susfs_sus_kstat  info;
	struct hlist_node          node;
};
#endif

#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
struct st_susfs_uname {
	char release[__NEW_UTS_LEN + 1];
	char version[__NEW_UTS_LEN + 1];
	int  err;
};
#endif

#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
struct st_susfs_log {
	bool enabled;
	int  err;
};
#endif

#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
struct st_susfs_spoof_cmdline_or_bootconfig {
	char fake_cmdline_or_bootconfig[SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE];
	int  err;
};
#endif

#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
struct st_susfs_open_redirect {
	char target_pathname[SUSFS_MAX_LEN_PATHNAME];
	char redirected_pathname[SUSFS_MAX_LEN_PATHNAME];
	int  uid_scheme;
	int  err;
};

struct st_susfs_open_redirect_hlist {
	unsigned long                target_ino;
	unsigned long                target_dev;
	unsigned long                redirected_ino;
	unsigned long                redirected_dev;
	int                          spoofed_mnt_id;
	struct kstatfs               spoofed_kstatfs;
	struct st_susfs_open_redirect info;
	bool                         reversed_lookup_only;
	struct hlist_node            node;
};
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_MAP
struct st_susfs_sus_map {
	char target_pathname[SUSFS_MAX_LEN_PATHNAME];
	int  err;
};
#endif

struct st_susfs_avc_log_spoofing {
	bool enabled;
	int  err;
};

struct st_susfs_enabled_features {
	char enabled_features[SUSFS_ENABLED_FEATURES_SIZE];
	int  err;
};

struct st_susfs_variant {
	char susfs_variant[16];
	int  err;
};

struct st_susfs_version {
	char susfs_version[16];
	int  err;
};

#ifdef CONFIG_KSU_SUSFS_SUS_PATH
void susfs_add_sus_path(void __user **user_info);
void susfs_add_sus_path_loop(void __user **user_info);
bool susfs_is_inode_sus_path(struct inode *inode);
int susfs_get_data_path(struct path *path);
extern const struct qstr susfs_fake_qstr_name;
void susfs_run_sus_path_loop(void);
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
void susfs_set_hide_sus_mnts_for_non_su_procs(void __user **user_info);
int susfs_get_non_sus_mnt_id_from_mnt(struct mount *orig_mnt);
struct vfsmount *susfs_get_non_sus_vfsmnt_from_vfsmnt(struct vfsmount *vfsmnt);
extern struct static_key_true susfs_is_sdcard_android_data_not_decrypted;
extern struct static_key_false susfs_is_hide_sus_mnts_for_non_su_procs_enabled;
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
void susfs_add_sus_kstat(void __user **user_info);
void susfs_update_sus_kstat(void __user **user_info);
void susfs_sus_kstat_spoof_generic_fillattr(struct inode *inode, struct kstat *stat);
void susfs_sus_kstat_spoof_show_map_vma(struct inode *inode, dev_t *out_dev, unsigned long *out_ino);
#endif

#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
void susfs_set_uname(void __user **user_info);
void susfs_spoof_uname(struct new_utsname *tmp);
extern struct static_key_false susfs_is_uname_spoof_buffer_set;
#endif

#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
void susfs_enable_log(void __user **user_info);
#endif

#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
void susfs_set_cmdline_or_bootconfig(void __user **user_info);
void susfs_spoof_cmdline_or_bootconfig(struct seq_file *m);
extern struct static_key_false susfs_is_fake_cmdline_or_bootconfig_buffer_set;
#endif

#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
void susfs_add_open_redirect(void __user **user_info);
struct filename *susfs_open_redirect_spoof_do_sys_openat(struct inode *inode);
int susfs_open_redirect_spoof_vfs_readlink(struct inode *inode, char __user *buffer, int buflen);
int susfs_open_redirect_spoof_do_proc_readlink(struct inode *inode, char *tmp_buf, int buflen);
int susfs_open_redirect_spoof_vfs_statfs(struct inode *inode, struct kstatfs *buf);
int susfs_open_redirect_spoof_seq_show(struct inode *inode, int *out_mnt_id, unsigned long *out_ino);
int susfs_open_redirect_spoof_show_map_vma(struct inode *inode, unsigned long *out_ino, dev_t *out_dev, char *spoofed_name);
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_MAP
void susfs_add_sus_map(void __user **user_info);
#endif

void susfs_set_avc_log_spoofing(void __user **user_info);
void susfs_get_enabled_features(void __user **user_info);
void susfs_show_variant(void __user **user_info);
void susfs_show_version(void __user **user_info);
void susfs_start_sdcard_monitor_fn(void);
void susfs_init(void);

extern struct static_key_false susfs_is_avc_log_spoofing_enabled;

#endif /* _SUSFS_H */
