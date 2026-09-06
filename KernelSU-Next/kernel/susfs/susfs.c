#include <linux/version.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/printk.h>
#include <linux/namei.h>
#include <linux/list.h>
#include <linux/init_task.h>
#include <linux/mutex.h>
#include <linux/seqlock.h>
#include <linux/stat.h>
#include <linux/uaccess.h>
#include <linux/fdtable.h>
#include <linux/statfs.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <linux/fsnotify_backend.h>
#include <linux/jump_label.h>
#include <linux/mount.h>
#include <mount.h>
#include <linux/dcache.h>
#include <linux/hashtable.h>
#include <linux/srcu.h>

#include "susfs.h"

extern bool susfs_is_current_ksu_domain(void);
extern void setup_selinux(const char *domain, struct cred *cred);
extern struct cred *ksu_cred;
extern void susfs_set_ksu_sid(void);
extern void susfs_set_zygote_sid(void);
extern void susfs_set_init_sid(void);
extern void susfs_set_priv_app_sid(void);

void susfs_setup_sids(void);

#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
DEFINE_STATIC_KEY_TRUE(susfs_is_log_enabled);
#define SUSFS_LOGI(fmt, ...) \
	if (static_branch_likely(&susfs_is_log_enabled)) \
		pr_info("susfs:[%u][%d][%s] " fmt, \
			__kuid_val(current_uid()), current->pid, __func__, ##__VA_ARGS__)
#define SUSFS_LOGE(fmt, ...) \
	if (static_branch_likely(&susfs_is_log_enabled)) \
		pr_err("susfs:[%u][%d][%s] " fmt, \
			__kuid_val(current_uid()), current->pid, __func__, ##__VA_ARGS__)
#else
#define SUSFS_LOGI(fmt, ...)
#define SUSFS_LOGE(fmt, ...)
#endif

/* ----------------------------------------------------------------- */
/*  SUS_PATH                                                         */
/* ----------------------------------------------------------------- */
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
DEFINE_STATIC_SRCU(susfs_srcu_sus_path_loop);
static DEFINE_MUTEX(susfs_mutex_lock_sus_path);
static LIST_HEAD(LH_SUS_PATH_LOOP);
const struct qstr susfs_fake_qstr_name = QSTR_INIT("..5.u.S", 7);

void susfs_add_sus_path(void __user **user_info)
{
	struct st_susfs_sus_path info = {0};
	struct path path;
	struct inode *inode = NULL;

	if (copy_from_user(&info,
	    (struct st_susfs_sus_path __user *)*user_info, sizeof(info))) {
		info.err = -EFAULT;
		goto out_copy_to_user;
	}

	info.err = kern_path(info.target_pathname, LOOKUP_FOLLOW, &path);
	if (info.err) {
		SUSFS_LOGE("failed opening file '%s'\n", info.target_pathname);
		goto out_copy_to_user;
	}

	inode = d_backing_inode(path.dentry);
	if (!inode || !inode->i_mapping) {
		info.err = -ENOENT;
		goto out_path_put;
	}

	set_bit(AS_FLAGS_SUS_PATH, &inode->i_state);
	SUSFS_LOGI("flagged AS_FLAGS_SUS_PATH on '%s', ino: %lu\n",
		   info.target_pathname, inode->i_ino);
	info.err = 0;

out_path_put:
	path_put(&path);
out_copy_to_user:
	if (copy_to_user(&((struct st_susfs_sus_path __user *)*user_info)->err,
	    &info.err, sizeof(info.err)))
		info.err = -EFAULT;
}

void susfs_add_sus_path_loop(void __user **user_info)
{
	struct st_susfs_sus_path_list *new_list = NULL;
	struct st_susfs_sus_path info = {0};

	if (copy_from_user(&info,
	    (struct st_susfs_sus_path __user *)*user_info, sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}

	if (*info.target_pathname == '\0') {
		info.err = -EINVAL;
		goto out;
	}

	new_list = kzalloc(sizeof(*new_list), GFP_KERNEL);
	if (!new_list) {
		info.err = -ENOMEM;
		goto out;
	}
	strscpy(new_list->info.target_pathname, info.target_pathname,
		SUSFS_MAX_LEN_PATHNAME - 1);
	strscpy(new_list->target_pathname, info.target_pathname,
		SUSFS_MAX_LEN_PATHNAME - 1);
	INIT_LIST_HEAD(&new_list->list);
	mutex_lock(&susfs_mutex_lock_sus_path);
	list_add_tail_rcu(&new_list->list, &LH_SUS_PATH_LOOP);
	mutex_unlock(&susfs_mutex_lock_sus_path);
	info.err = 0;
out:
	if (copy_to_user(&((struct st_susfs_sus_path __user *)*user_info)->err,
	    &info.err, sizeof(info.err)))
		info.err = -EFAULT;
}

void susfs_run_sus_path_loop(void)
{
	struct st_susfs_sus_path_list *cursor = NULL;
	struct path path;
	struct inode *inode;
	const struct cred *saved = override_creds(ksu_cred);
	int srcu_idx;

	srcu_idx = srcu_read_lock(&susfs_srcu_sus_path_loop);
	list_for_each_entry_rcu(cursor, &LH_SUS_PATH_LOOP, list) {
		if (!kern_path(cursor->target_pathname, 0, &path)) {
			inode = d_backing_inode(path.dentry);
			if (inode && inode->i_mapping) {
				set_bit(AS_FLAGS_SUS_PATH, &inode->i_state);
				SUSFS_LOGI("re-flag on '%s', ino: %lu\n",
					   cursor->target_pathname, inode->i_ino);
			}
			path_put(&path);
		}
	}
	srcu_read_unlock(&susfs_srcu_sus_path_loop, srcu_idx);
	revert_creds(saved);
}

static inline bool is_i_uid_not_allowed(uid_t i_uid)
{
	return __kuid_val(current_uid()) != i_uid;
}

bool susfs_is_inode_sus_path(struct inode *inode)
{
	if (!susfs_is_current_proc_umounted_app())
		return false;
	if (!inode || !inode->i_mapping)
		return false;

	if (unlikely(test_bit(AS_FLAGS_SUS_PATH, &inode->i_state) &&
	    is_i_uid_not_allowed(inode->i_uid.val))) {
		SUSFS_LOGI("hiding path with ino '%lu'\n", inode->i_ino);
		return true;
	}
	return false;
}

int susfs_get_data_path(struct path *path)
{
	return kern_path("/data", LOOKUP_FOLLOW, path);
}
#endif /* CONFIG_KSU_SUSFS_SUS_PATH */

/* ----------------------------------------------------------------- */
/*  SUS_MOUNT                                                        */
/* ----------------------------------------------------------------- */
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
DEFINE_STATIC_KEY_FALSE(susfs_is_hide_sus_mnts_for_non_su_procs_enabled);

void susfs_set_hide_sus_mnts_for_non_su_procs(void __user **user_info)
{
	struct st_susfs_hide_sus_mnts_for_non_su_procs info = {0};

	if (copy_from_user(&info,
	    (struct st_susfs_hide_sus_mnts_for_non_su_procs __user *)*user_info,
	    sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}

	if (info.enabled)
		static_branch_enable(&susfs_is_hide_sus_mnts_for_non_su_procs_enabled);
	else
		static_branch_disable(&susfs_is_hide_sus_mnts_for_non_su_procs_enabled);

	info.err = 0;
out:
	if (copy_to_user(
	    &((struct st_susfs_hide_sus_mnts_for_non_su_procs __user *)*user_info)->err,
	    &info.err, sizeof(info.err)))
		info.err = -EFAULT;
}
#endif /* CONFIG_KSU_SUSFS_SUS_MOUNT */

/* ----------------------------------------------------------------- */
/*  SUS_KSTAT                                                        */
/* ----------------------------------------------------------------- */
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
static DEFINE_MUTEX(susfs_mutex_lock_sus_kstat);
static DEFINE_HASHTABLE(SUS_KSTAT_HLIST, 10);

static int susfs_mark_inode_sus_kstat(char *target_pathname,
				      struct st_susfs_sus_kstat_hlist *new_entry)
{
	struct path path;
	struct inode *inode = NULL;
	int err;

	err = kern_path(target_pathname, 0, &path);
	if (err) {
		SUSFS_LOGE("failed opening file '%s'\n", target_pathname);
		return err;
	}

	inode = d_backing_inode(path.dentry);
	if (!inode || !inode->i_mapping) {
		err = -ENOENT;
		goto out;
	}

	set_bit(AS_FLAGS_SUS_KSTAT, &inode->i_state);
	new_entry->target_dev = inode->i_sb->s_dev;
	SUSFS_LOGI("flagged AS_FLAGS_SUS_KSTAT on '%s', dev: %u, ino: %lu\n",
		   target_pathname, new_entry->target_dev, inode->i_ino);
out:
	path_put(&path);
	return err;
}

void susfs_add_sus_kstat(void __user **user_info)
{
	struct st_susfs_sus_kstat info = {0};
	struct st_susfs_sus_kstat_hlist *new_entry, *tmp_entry;
	struct hlist_node *tmp_hlist_node;

	if (copy_from_user(&info,
	    (struct st_susfs_sus_kstat __user *)*user_info, sizeof(info))) {
		info.err = -EFAULT;
		goto out_copy_to_user;
	}

	if (*info.target_pathname == '\0') {
		info.err = -EINVAL;
		goto out_copy_to_user;
	}

	new_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);
	if (!new_entry) {
		info.err = -ENOMEM;
		goto out_copy_to_user;
	}

	new_entry->target_ino = info.target_ino;
	memcpy(&new_entry->info, &info, sizeof(info));

	mutex_lock(&susfs_mutex_lock_sus_kstat);
	hash_for_each_possible_safe(SUS_KSTAT_HLIST, tmp_entry,
				    tmp_hlist_node, node, info.target_ino) {
		if (!strcmp(tmp_entry->info.target_pathname,
			    info.target_pathname)) {
			info.err = susfs_mark_inode_sus_kstat(
				new_entry->info.target_pathname, new_entry);
			if (info.err) {
				mutex_unlock(&susfs_mutex_lock_sus_kstat);
				kfree(new_entry);
				goto out_copy_to_user;
			}
			hash_del_rcu(&tmp_entry->node);
			hash_add_rcu(SUS_KSTAT_HLIST, &new_entry->node,
				     info.target_ino);
			mutex_unlock(&susfs_mutex_lock_sus_kstat);
			synchronize_rcu();
			kfree(tmp_entry);
			info.err = 0;
			goto out_copy_to_user;
		}
	}

	info.err = susfs_mark_inode_sus_kstat(new_entry->info.target_pathname,
					      new_entry);
	if (info.err) {
		mutex_unlock(&susfs_mutex_lock_sus_kstat);
		kfree(new_entry);
		goto out_copy_to_user;
	}

	hash_add_rcu(SUS_KSTAT_HLIST, &new_entry->node, info.target_ino);
	mutex_unlock(&susfs_mutex_lock_sus_kstat);
	info.err = 0;

out_copy_to_user:
	if (copy_to_user(&((struct st_susfs_sus_kstat __user *)*user_info)->err,
	    &info.err, sizeof(info.err)))
		info.err = -EFAULT;
}

void susfs_update_sus_kstat(void __user **user_info)
{
	struct st_susfs_sus_kstat info = {0};
	struct st_susfs_sus_kstat_hlist *new_entry, *tmp_entry;
	struct hlist_node *tmp_hlist_node;
	int bkt;

	if (copy_from_user(&info,
	    (struct st_susfs_sus_kstat __user *)*user_info, sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}

	new_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);
	if (!new_entry) {
		info.err = -ENOMEM;
		goto out;
	}

	mutex_lock(&susfs_mutex_lock_sus_kstat);
	hash_for_each_safe(SUS_KSTAT_HLIST, bkt, tmp_hlist_node,
			   tmp_entry, node) {
		if (!strcmp(tmp_entry->info.target_pathname,
			    info.target_pathname)) {
			memcpy(&new_entry->info, &tmp_entry->info,
			       sizeof(tmp_entry->info));
			new_entry->target_ino = info.target_ino;
			new_entry->target_dev = tmp_entry->target_dev;
			new_entry->is_fuse = false;
			new_entry->info.target_ino = info.target_ino;
			info.err = susfs_mark_inode_sus_kstat(
				new_entry->info.target_pathname, new_entry);
			if (info.err) {
				mutex_unlock(&susfs_mutex_lock_sus_kstat);
				kfree(new_entry);
				goto out;
			}
			hash_del_rcu(&tmp_entry->node);
			hash_add_rcu(SUS_KSTAT_HLIST, &new_entry->node,
				     info.target_ino);
			mutex_unlock(&susfs_mutex_lock_sus_kstat);
			synchronize_rcu();
			kfree(tmp_entry);
			info.err = 0;
			goto out;
		}
	}
	mutex_unlock(&susfs_mutex_lock_sus_kstat);
	info.err = -ENOENT;
out:
	if (copy_to_user(&((struct st_susfs_sus_kstat __user *)*user_info)->err,
	    &info.err, sizeof(info.err)))
		info.err = -EFAULT;
}

void susfs_sus_kstat_spoof_generic_fillattr(struct inode *inode,
					    struct kstat *stat)
{
	struct st_susfs_sus_kstat_hlist *entry = NULL;
	unsigned long target_ino;

	if (!inode || !inode->i_mapping)
		return;

	if (!test_bit(AS_FLAGS_SUS_KSTAT, &inode->i_state) ||
	    !susfs_is_current_proc_umounted_app())
		return;

	target_ino = inode->i_ino;

	rcu_read_lock();
	hash_for_each_possible_rcu(SUS_KSTAT_HLIST, entry, node, target_ino) {
		if (entry->target_dev == inode->i_sb->s_dev) {
			if (entry->info.flags & KSTAT_SPOOF_INO)
				stat->ino = entry->info.spoofed_ino;
			if (entry->info.flags & KSTAT_SPOOF_DEV)
				stat->dev = entry->info.spoofed_dev;
			if (entry->info.flags & KSTAT_SPOOF_NLINK)
				stat->nlink = entry->info.spoofed_nlink;
			if (entry->info.flags & KSTAT_SPOOF_SIZE)
				stat->size = entry->info.spoofed_size;
			if (entry->info.flags & KSTAT_SPOOF_ATIME_TV_SEC)
				stat->atime.tv_sec = entry->info.spoofed_atime_tv_sec;
			if (entry->info.flags & KSTAT_SPOOF_ATIME_TV_NSEC)
				stat->atime.tv_nsec = entry->info.spoofed_atime_tv_nsec;
			if (entry->info.flags & KSTAT_SPOOF_MTIME_TV_SEC)
				stat->mtime.tv_sec = entry->info.spoofed_mtime_tv_sec;
			if (entry->info.flags & KSTAT_SPOOF_MTIME_TV_NSEC)
				stat->mtime.tv_nsec = entry->info.spoofed_mtime_tv_nsec;
			if (entry->info.flags & KSTAT_SPOOF_CTIME_TV_SEC)
				stat->ctime.tv_sec = entry->info.spoofed_ctime_tv_sec;
			if (entry->info.flags & KSTAT_SPOOF_CTIME_TV_NSEC)
				stat->ctime.tv_nsec = entry->info.spoofed_ctime_tv_nsec;
			if (entry->info.flags & KSTAT_SPOOF_BLKSIZE)
				stat->blksize = entry->info.spoofed_blksize;
			if (entry->info.flags & KSTAT_SPOOF_BLOCKS)
				stat->blocks = entry->info.spoofed_blocks;
			rcu_read_unlock();
			return;
		}
	}
	rcu_read_unlock();
}

void susfs_sus_kstat_spoof_show_map_vma(struct inode *inode, dev_t *out_dev,
					unsigned long *out_ino)
{
	struct st_susfs_sus_kstat_hlist *entry = NULL;
	unsigned long target_ino;

	if (!inode || !inode->i_mapping)
		return;

	if (!test_bit(AS_FLAGS_SUS_KSTAT, &inode->i_state) ||
	    !susfs_is_current_proc_umounted_app())
		return;

	target_ino = inode->i_ino;

	rcu_read_lock();
	hash_for_each_possible_rcu(SUS_KSTAT_HLIST, entry, node, target_ino) {
		if (entry->target_dev == inode->i_sb->s_dev) {
			*out_dev = entry->info.spoofed_dev;
			*out_ino = entry->info.spoofed_ino;
			rcu_read_unlock();
			return;
		}
	}
	rcu_read_unlock();
}
#endif /* CONFIG_KSU_SUSFS_SUS_KSTAT */

/* ----------------------------------------------------------------- */
/*  SPOOF_UNAME                                                      */
/* ----------------------------------------------------------------- */
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
static struct st_susfs_uname my_uname = {0};
DEFINE_STATIC_KEY_FALSE(susfs_is_uname_spoof_buffer_set);
static DEFINE_SEQLOCK(susfs_uname_seqlock);

void susfs_set_uname(void __user **user_info)
{
	struct st_susfs_uname info = {0};

	if (copy_from_user(&info,
	    (struct st_susfs_uname __user *)*user_info, sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}

	if (*info.release == '\0' || *info.version == '\0') {
		info.err = -EFAULT;
		goto out;
	}

	write_seqlock(&susfs_uname_seqlock);
	if (!strcmp(info.release, "default"))
		strscpy(my_uname.release, utsname()->release, __NEW_UTS_LEN);
	else
		strscpy(my_uname.release, info.release, __NEW_UTS_LEN);

	if (!strcmp(info.version, "default"))
		strscpy(my_uname.version, utsname()->version, __NEW_UTS_LEN);
	else
		strscpy(my_uname.version, info.version, __NEW_UTS_LEN);
	write_sequnlock(&susfs_uname_seqlock);

	if (!static_key_enabled(&susfs_is_uname_spoof_buffer_set))
		static_branch_enable(&susfs_is_uname_spoof_buffer_set);

	info.err = 0;
out:
	if (copy_to_user(&((struct st_susfs_uname __user *)*user_info)->err,
	    &info.err, sizeof(info.err)))
		info.err = -EFAULT;
}

void susfs_spoof_uname(struct new_utsname *tmp)
{
	unsigned seq;

	do {
		seq = read_seqbegin(&susfs_uname_seqlock);
		strscpy(tmp->release, my_uname.release, __NEW_UTS_LEN);
		strscpy(tmp->version, my_uname.version, __NEW_UTS_LEN);
	} while (read_seqretry(&susfs_uname_seqlock, seq));
}
#endif /* CONFIG_KSU_SUSFS_SPOOF_UNAME */

/* ----------------------------------------------------------------- */
/*  ENABLE_LOG                                                       */
/* ----------------------------------------------------------------- */
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
void susfs_enable_log(void __user **user_info)
{
	struct st_susfs_log info = {0};

	if (copy_from_user(&info,
	    (struct st_susfs_log __user *)*user_info, sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}

	if (info.enabled) {
		static_branch_enable(&susfs_is_log_enabled);
		pr_info("susfs: enable logging\n");
	} else {
		static_branch_disable(&susfs_is_log_enabled);
		pr_info("susfs: disable logging\n");
	}
	info.err = 0;
out:
	if (copy_to_user(&((struct st_susfs_log __user *)*user_info)->err,
	    &info.err, sizeof(info.err)))
		info.err = -EFAULT;
}
#endif

/* ----------------------------------------------------------------- */
/*  SPOOF_CMDLINE_OR_BOOTCONFIG                                      */
/* ----------------------------------------------------------------- */
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
static char *fake_cmdline_or_bootconfig;
static DEFINE_SEQLOCK(susfs_fake_cmdline_or_bootconfig_seqlock);
DEFINE_STATIC_KEY_FALSE(susfs_is_fake_cmdline_or_bootconfig_buffer_set);

void susfs_set_cmdline_or_bootconfig(void __user **user_info)
{
	struct st_susfs_spoof_cmdline_or_bootconfig *info;
	int err = 0;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		err = -ENOMEM;
		if (copy_to_user(
		    &((struct st_susfs_spoof_cmdline_or_bootconfig __user *)*user_info)->err,
		    &err, sizeof(err)))
			err = -EFAULT;
		return;
	}

	if (copy_from_user(info,
	    (struct st_susfs_spoof_cmdline_or_bootconfig __user *)*user_info,
	    sizeof(*info))) {
		info->err = -EFAULT;
		goto out;
	}

	if (*info->fake_cmdline_or_bootconfig == '\0') {
		info->err = -EINVAL;
		goto out;
	}

	if (!fake_cmdline_or_bootconfig) {
		fake_cmdline_or_bootconfig = kzalloc(
			SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE, GFP_KERNEL);
		if (!fake_cmdline_or_bootconfig) {
			info->err = -ENOMEM;
			goto out;
		}
	}

	write_seqlock(&susfs_fake_cmdline_or_bootconfig_seqlock);
	strscpy(fake_cmdline_or_bootconfig,
		info->fake_cmdline_or_bootconfig,
		SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE - 1);
	write_sequnlock(&susfs_fake_cmdline_or_bootconfig_seqlock);

	if (!static_key_enabled(&susfs_is_fake_cmdline_or_bootconfig_buffer_set))
		static_branch_enable(&susfs_is_fake_cmdline_or_bootconfig_buffer_set);

	info->err = 0;
out:
	if (copy_to_user(
	    &((struct st_susfs_spoof_cmdline_or_bootconfig __user *)*user_info)->err,
	    &info->err, sizeof(info->err)))
		info->err = -EFAULT;
	kfree(info);
}

void susfs_spoof_cmdline_or_bootconfig(struct seq_file *m)
{
	unsigned seq;

	do {
		seq = read_seqbegin(&susfs_fake_cmdline_or_bootconfig_seqlock);
		seq_puts(m, fake_cmdline_or_bootconfig);
	} while (read_seqretry(&susfs_fake_cmdline_or_bootconfig_seqlock, seq));
}
#endif

/* ----------------------------------------------------------------- */
/*  OPEN_REDIRECT                                                    */
/* ----------------------------------------------------------------- */
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
static DEFINE_MUTEX(susfs_mutex_lock_open_redirect);
static DEFINE_HASHTABLE(OPEN_REDIRECT_HLIST, 10);
DEFINE_STATIC_SRCU(susfs_srcu_open_redirect);

void susfs_add_open_redirect(void __user **user_info)
{
	struct st_susfs_open_redirect info = {0};
	struct st_susfs_open_redirect_hlist *new_entry_target;
	struct st_susfs_open_redirect_hlist *new_entry_redirected;
	struct st_susfs_open_redirect_hlist *tmp_entry_target;
	struct st_susfs_open_redirect_hlist *tmp_entry_redirected;
	struct hlist_node *tmp_hlist_node;
	struct path target_path, redirected_path;
	struct inode *target_inode, *redirected_inode;
	bool is_first_dup_found = false;
	bool is_second_dup_found = false;

	if (copy_from_user(&info,
	    (struct st_susfs_open_redirect __user *)*user_info,
	    sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}

	if (*info.target_pathname == '\0') {
		info.err = -EINVAL;
		goto out;
	}

	if (info.uid_scheme < UID_NON_APP_PROC ||
	    info.uid_scheme > UID_UMOUNTED_PROC) {
		info.err = -EINVAL;
		goto out;
	}

	info.err = kern_path(info.redirected_pathname, 0, &redirected_path);
	if (info.err)
		goto out;

	info.err = kern_path(info.target_pathname, 0, &target_path);
	if (info.err) {
		path_put(&redirected_path);
		goto out;
	}

	redirected_inode = d_backing_inode(redirected_path.dentry);
	target_inode = d_backing_inode(target_path.dentry);
	if (!redirected_inode || !redirected_inode->i_mapping ||
	    !target_inode || !target_inode->i_mapping) {
		info.err = -ENOENT;
		path_put(&target_path);
		path_put(&redirected_path);
		goto out;
	}

	new_entry_target = kzalloc(sizeof(*new_entry_target), GFP_KERNEL);
	new_entry_redirected = kzalloc(sizeof(*new_entry_redirected), GFP_KERNEL);
	if (!new_entry_target || !new_entry_redirected) {
		kfree(new_entry_target);
		kfree(new_entry_redirected);
		info.err = -ENOMEM;
		path_put(&target_path);
		path_put(&redirected_path);
		goto out;
	}

	new_entry_target->target_ino = target_inode->i_ino;
	new_entry_target->target_dev = target_inode->i_sb->s_dev;
	new_entry_target->redirected_ino = redirected_inode->i_ino;
	new_entry_target->redirected_dev = redirected_inode->i_sb->s_dev;
	new_entry_target->info.uid_scheme = info.uid_scheme;
	new_entry_target->reversed_lookup_only = false;
	new_entry_target->spoofed_mnt_id = real_mount(target_path.mnt)->mnt_id;
	vfs_statfs(&target_path, &new_entry_target->spoofed_kstatfs);
	memcpy(&new_entry_target->info, &info, sizeof(info));

	new_entry_redirected->target_ino = redirected_inode->i_ino;
	new_entry_redirected->target_dev = redirected_inode->i_sb->s_dev;
	new_entry_redirected->redirected_ino = target_inode->i_ino;
	new_entry_redirected->redirected_dev = target_inode->i_sb->s_dev;
	new_entry_redirected->info.uid_scheme = info.uid_scheme;
	new_entry_redirected->reversed_lookup_only = true;
	new_entry_redirected->spoofed_mnt_id = real_mount(target_path.mnt)->mnt_id;
	memcpy(&new_entry_redirected->spoofed_kstatfs,
	       &new_entry_target->spoofed_kstatfs, sizeof(struct kstatfs));
	strscpy(new_entry_redirected->info.target_pathname,
		info.redirected_pathname, SUSFS_MAX_LEN_PATHNAME - 1);
	strscpy(new_entry_redirected->info.redirected_pathname,
		info.target_pathname, SUSFS_MAX_LEN_PATHNAME - 1);

	mutex_lock(&susfs_mutex_lock_open_redirect);
	hash_for_each_possible_safe(OPEN_REDIRECT_HLIST, tmp_entry_target,
				    tmp_hlist_node, node,
				    target_inode->i_ino) {
		if (!strcmp(tmp_entry_target->info.target_pathname,
			    info.target_pathname)) {
			if (tmp_entry_target->reversed_lookup_only) {
				mutex_unlock(&susfs_mutex_lock_open_redirect);
				info.err = -EINVAL;
				kfree(new_entry_redirected);
				kfree(new_entry_target);
				path_put(&target_path);
				path_put(&redirected_path);
				goto out;
			}
			is_first_dup_found = true;
			hash_del_rcu(&tmp_entry_target->node);
			break;
		}
	}

	if (is_first_dup_found) {
		hash_for_each_possible_safe(OPEN_REDIRECT_HLIST,
					    tmp_entry_redirected,
					    tmp_hlist_node, node,
					    redirected_inode->i_ino) {
			if (!strcmp(tmp_entry_redirected->info.target_pathname,
				    info.redirected_pathname)) {
				is_second_dup_found = true;
				hash_del_rcu(&tmp_entry_redirected->node);
				break;
			}
		}
		hash_add_rcu(OPEN_REDIRECT_HLIST, &new_entry_target->node,
			     new_entry_target->target_ino);
		hash_add_rcu(OPEN_REDIRECT_HLIST, &new_entry_redirected->node,
			     new_entry_redirected->target_ino);
		set_bit(AS_FLAGS_OPEN_REDIRECT, &redirected_inode->i_state);
		set_bit(AS_FLAGS_OPEN_REDIRECT, &target_inode->i_state);
		mutex_unlock(&susfs_mutex_lock_open_redirect);
		synchronize_rcu();
		if (is_second_dup_found)
			kfree(tmp_entry_redirected);
		kfree(tmp_entry_target);
		info.err = 0;
		path_put(&target_path);
		path_put(&redirected_path);
		goto out;
	}

	hash_add_rcu(OPEN_REDIRECT_HLIST, &new_entry_target->node,
		     new_entry_target->target_ino);
	hash_add_rcu(OPEN_REDIRECT_HLIST, &new_entry_redirected->node,
		     new_entry_redirected->target_ino);
	set_bit(AS_FLAGS_OPEN_REDIRECT, &redirected_inode->i_state);
	set_bit(AS_FLAGS_OPEN_REDIRECT, &target_inode->i_state);
	mutex_unlock(&susfs_mutex_lock_open_redirect);
	info.err = 0;
	path_put(&target_path);
	path_put(&redirected_path);
out:
	if (copy_to_user(
	    &((struct st_susfs_open_redirect __user *)*user_info)->err,
	    &info.err, sizeof(info.err)))
		info.err = -EFAULT;
}

struct filename *susfs_open_redirect_spoof_do_sys_openat(struct inode *inode)
{
	struct st_susfs_open_redirect_hlist *entry = NULL;
	struct filename *new_filename = NULL;
	int srcu_idx;

	srcu_idx = srcu_read_lock(&susfs_srcu_open_redirect);
	hash_for_each_possible_rcu(OPEN_REDIRECT_HLIST, entry, node,
				   inode->i_ino) {
		if (!entry->reversed_lookup_only &&
		    entry->target_dev == inode->i_sb->s_dev) {
			switch (entry->info.uid_scheme) {
			case UID_NON_APP_PROC:
				if (__kuid_val(current_uid()) % 100000 < 10000)
					break;
				goto unlock;
			case UID_ROOT_PROC_EXCEPT_SU_PROC:
				if (__kuid_val(current_uid()) == 0 &&
				    !susfs_is_current_ksu_domain())
					break;
				goto unlock;
			case UID_NON_SU_PROC:
				if (!susfs_is_current_ksu_domain())
					break;
				goto unlock;
			case UID_UMOUNTED_APP_PROC:
				if (susfs_is_current_proc_umounted_app())
					break;
				goto unlock;
			case UID_UMOUNTED_PROC:
				if (susfs_is_current_proc_umounted())
					break;
				goto unlock;
			default:
				goto unlock;
			}
			new_filename = getname_kernel(
				entry->info.redirected_pathname);
			srcu_read_unlock(&susfs_srcu_open_redirect, srcu_idx);
			return new_filename;
		}
	}
unlock:
	srcu_read_unlock(&susfs_srcu_open_redirect, srcu_idx);
	return new_filename;
}

int susfs_open_redirect_spoof_vfs_readlink(struct inode *inode,
					   char __user *buffer, int buflen)
{
	struct st_susfs_open_redirect_hlist *entry = NULL;
	int srcu_idx;

	srcu_idx = srcu_read_lock(&susfs_srcu_open_redirect);
	hash_for_each_possible_rcu(OPEN_REDIRECT_HLIST, entry, node,
				   inode->i_ino) {
		if (entry->reversed_lookup_only &&
		    entry->target_dev == inode->i_sb->s_dev) {
			if (strlen(entry->info.redirected_pathname) >=
			    (unsigned long)buflen) {
				srcu_read_unlock(&susfs_srcu_open_redirect,
						 srcu_idx);
				return -ENAMETOOLONG;
			}
			if (copy_to_user(buffer,
					 entry->info.redirected_pathname,
					 strlen(entry->info.redirected_pathname))) {
				srcu_read_unlock(&susfs_srcu_open_redirect,
						 srcu_idx);
				return -EFAULT;
			}
			srcu_read_unlock(&susfs_srcu_open_redirect, srcu_idx);
			return 0;
		}
	}
	srcu_read_unlock(&susfs_srcu_open_redirect, srcu_idx);
	return -ENOENT;
}

int susfs_open_redirect_spoof_do_proc_readlink(struct inode *inode,
					       char *tmp_buf, int buflen)
{
	struct st_susfs_open_redirect_hlist *entry = NULL;
	int srcu_idx;

	srcu_idx = srcu_read_lock(&susfs_srcu_open_redirect);
	hash_for_each_possible_rcu(OPEN_REDIRECT_HLIST, entry, node,
				   inode->i_ino) {
		if (entry->reversed_lookup_only &&
		    entry->target_dev == inode->i_sb->s_dev) {
			if (strlen(entry->info.redirected_pathname) >=
			    (unsigned long)buflen) {
				srcu_read_unlock(&susfs_srcu_open_redirect,
						 srcu_idx);
				return -ENAMETOOLONG;
			}
			strscpy(tmp_buf, entry->info.redirected_pathname,
				SUSFS_MAX_LEN_PATHNAME - 1);
			srcu_read_unlock(&susfs_srcu_open_redirect, srcu_idx);
			return 0;
		}
	}
	srcu_read_unlock(&susfs_srcu_open_redirect, srcu_idx);
	return -ENOENT;
}

int susfs_open_redirect_spoof_vfs_statfs(struct inode *inode,
					 struct kstatfs *buf)
{
	struct st_susfs_open_redirect_hlist *entry = NULL;
	int srcu_idx;

	srcu_idx = srcu_read_lock(&susfs_srcu_open_redirect);
	hash_for_each_possible_rcu(OPEN_REDIRECT_HLIST, entry, node,
				   inode->i_ino) {
		if (entry->reversed_lookup_only &&
		    entry->target_dev == inode->i_sb->s_dev) {
			memcpy(buf, &entry->spoofed_kstatfs,
			       sizeof(struct kstatfs));
			srcu_read_unlock(&susfs_srcu_open_redirect, srcu_idx);
			return 0;
		}
	}
	srcu_read_unlock(&susfs_srcu_open_redirect, srcu_idx);
	return -EINVAL;
}

int susfs_open_redirect_spoof_seq_show(struct inode *inode, int *out_mnt_id,
				       unsigned long *out_ino)
{
	struct st_susfs_open_redirect_hlist *entry = NULL;
	int srcu_idx;

	srcu_idx = srcu_read_lock(&susfs_srcu_open_redirect);
	hash_for_each_possible_rcu(OPEN_REDIRECT_HLIST, entry, node,
				   inode->i_ino) {
		if (entry->reversed_lookup_only &&
		    entry->target_dev == inode->i_sb->s_dev) {
			*out_mnt_id = entry->spoofed_mnt_id;
			*out_ino = entry->redirected_ino;
			srcu_read_unlock(&susfs_srcu_open_redirect, srcu_idx);
			return 0;
		}
	}
	srcu_read_unlock(&susfs_srcu_open_redirect, srcu_idx);
	return -EINVAL;
}

int susfs_open_redirect_spoof_show_map_vma(struct inode *inode,
					   unsigned long *out_ino,
					   dev_t *out_dev,
					   char *spoofed_name)
{
	struct st_susfs_open_redirect_hlist *entry = NULL;
	int srcu_idx;

	if (spoofed_name)
		return -EINVAL;

	srcu_idx = srcu_read_lock(&susfs_srcu_open_redirect);
	hash_for_each_possible_rcu(OPEN_REDIRECT_HLIST, entry, node,
				   inode->i_ino) {
		if (entry->reversed_lookup_only &&
		    entry->target_dev == inode->i_sb->s_dev) {
			spoofed_name = kzalloc(SUSFS_MAX_LEN_PATHNAME,
					       GFP_KERNEL);
			if (!spoofed_name) {
				srcu_read_unlock(&susfs_srcu_open_redirect,
						 srcu_idx);
				return -ENOMEM;
			}
			*out_ino = entry->redirected_ino;
			*out_dev = entry->redirected_dev;
			strscpy(spoofed_name,
				entry->info.redirected_pathname,
				SUSFS_MAX_LEN_PATHNAME - 1);
			srcu_read_unlock(&susfs_srcu_open_redirect, srcu_idx);
			return 0;
		}
	}
	srcu_read_unlock(&susfs_srcu_open_redirect, srcu_idx);
	return -EINVAL;
}
#endif /* CONFIG_KSU_SUSFS_OPEN_REDIRECT */

/* ----------------------------------------------------------------- */
/*  SUS_MAP                                                          */
/* ----------------------------------------------------------------- */
#ifdef CONFIG_KSU_SUSFS_SUS_MAP
void susfs_add_sus_map(void __user **user_info)
{
	struct st_susfs_sus_map info = {0};
	struct path path;
	struct inode *inode = NULL;

	if (copy_from_user(&info,
	    (struct st_susfs_sus_map __user *)*user_info, sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}

	info.err = kern_path(info.target_pathname, LOOKUP_FOLLOW, &path);
	if (info.err)
		goto out;

	inode = d_backing_inode(path.dentry);
	if (!inode || !inode->i_mapping) {
		info.err = -ENOENT;
		path_put(&path);
		goto out;
	}
	set_bit(AS_FLAGS_SUS_MAP, &inode->i_state);
	path_put(&path);
	info.err = 0;
out:
	if (copy_to_user(&((struct st_susfs_sus_map __user *)*user_info)->err,
	    &info.err, sizeof(info.err)))
		info.err = -EFAULT;
}
#endif

/* ----------------------------------------------------------------- */
/*  AVC LOG SPOOFING                                                 */
/* ----------------------------------------------------------------- */
DEFINE_STATIC_KEY_FALSE(susfs_is_avc_log_spoofing_enabled);

void susfs_set_avc_log_spoofing(void __user **user_info)
{
	struct st_susfs_avc_log_spoofing info = {0};

	if (copy_from_user(&info,
	    (struct st_susfs_avc_log_spoofing __user *)*user_info,
	    sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}

	if (info.enabled)
		static_branch_enable(&susfs_is_avc_log_spoofing_enabled);
	else
		static_branch_disable(&susfs_is_avc_log_spoofing_enabled);

	info.err = 0;
out:
	if (copy_to_user(
	    &((struct st_susfs_avc_log_spoofing __user *)*user_info)->err,
	    &info.err, sizeof(info.err)))
		info.err = -EFAULT;
}

/* ----------------------------------------------------------------- */
/*  GET ENABLED FEATURES                                             */
/* ----------------------------------------------------------------- */
static int copy_feature_str(const char *str, char *buf, size_t *copied,
			    size_t bufsize)
{
	size_t len = strlen(str);
	*copied += len;
	if (*copied >= bufsize)
		return -EINVAL;
	memcpy(buf, str, len);
	return 0;
}

void susfs_get_enabled_features(void __user **user_info)
{
	struct st_susfs_enabled_features *info;
	char *buf;
	size_t copied = 0;
	int ret;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return;

	if (copy_from_user(info,
	    (struct st_susfs_enabled_features __user *)*user_info,
	    sizeof(*info))) {
		info->err = -EFAULT;
		goto out;
	}

	buf = info->enabled_features;

#ifdef CONFIG_KSU_SUSFS_SUS_PATH
	ret = copy_feature_str("CONFIG_KSU_SUSFS_SUS_PATH\n", buf, &copied,
			       SUSFS_ENABLED_FEATURES_SIZE);
	if (ret) { info->err = ret; goto out; }
	buf = info->enabled_features + copied;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	ret = copy_feature_str("CONFIG_KSU_SUSFS_SUS_MOUNT\n", buf, &copied,
			       SUSFS_ENABLED_FEATURES_SIZE);
	if (ret) { info->err = ret; goto out; }
	buf = info->enabled_features + copied;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
	ret = copy_feature_str("CONFIG_KSU_SUSFS_SUS_KSTAT\n", buf, &copied,
			       SUSFS_ENABLED_FEATURES_SIZE);
	if (ret) { info->err = ret; goto out; }
	buf = info->enabled_features + copied;
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
	ret = copy_feature_str("CONFIG_KSU_SUSFS_SPOOF_UNAME\n", buf, &copied,
			       SUSFS_ENABLED_FEATURES_SIZE);
	if (ret) { info->err = ret; goto out; }
	buf = info->enabled_features + copied;
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
	ret = copy_feature_str("CONFIG_KSU_SUSFS_ENABLE_LOG\n", buf, &copied,
			       SUSFS_ENABLED_FEATURES_SIZE);
	if (ret) { info->err = ret; goto out; }
	buf = info->enabled_features + copied;
#endif
#ifdef CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS
	ret = copy_feature_str("CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS\n",
			       buf, &copied, SUSFS_ENABLED_FEATURES_SIZE);
	if (ret) { info->err = ret; goto out; }
	buf = info->enabled_features + copied;
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
	ret = copy_feature_str("CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG\n",
			       buf, &copied, SUSFS_ENABLED_FEATURES_SIZE);
	if (ret) { info->err = ret; goto out; }
	buf = info->enabled_features + copied;
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
	ret = copy_feature_str("CONFIG_KSU_SUSFS_OPEN_REDIRECT\n",
			       buf, &copied, SUSFS_ENABLED_FEATURES_SIZE);
	if (ret) { info->err = ret; goto out; }
	buf = info->enabled_features + copied;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MAP
	ret = copy_feature_str("CONFIG_KSU_SUSFS_SUS_MAP\n",
			       buf, &copied, SUSFS_ENABLED_FEATURES_SIZE);
	if (ret) { info->err = ret; goto out; }
	buf = info->enabled_features + copied;
#endif
	info->err = 0;
out:
	if (copy_to_user(
	    (struct st_susfs_enabled_features __user *)*user_info,
	    info, sizeof(*info)))
		info->err = -EFAULT;
	kfree(info);
}

/* ----------------------------------------------------------------- */
/*  SHOW VARIANT                                                     */
/* ----------------------------------------------------------------- */
void susfs_show_variant(void __user **user_info)
{
	struct st_susfs_variant info = {0};

	if (copy_from_user(&info,
	    (struct st_susfs_variant __user *)*user_info, sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}

	strscpy(info.susfs_variant, SUSFS_VARIANT,
		SUSFS_MAX_VARIANT_BUFSIZE - 1);
	info.err = 0;
out:
	if (copy_to_user((struct st_susfs_variant __user *)*user_info,
	    &info, sizeof(info)))
		info.err = -EFAULT;
}

/* ----------------------------------------------------------------- */
/*  SHOW VERSION                                                     */
/* ----------------------------------------------------------------- */
void susfs_show_version(void __user **user_info)
{
	struct st_susfs_version info = {0};

	if (copy_from_user(&info,
	    (struct st_susfs_version __user *)*user_info, sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}

	strscpy(info.susfs_version, SUSFS_VERSION,
		SUSFS_MAX_VERSION_BUFSIZE - 1);
	info.err = 0;
out:
	if (copy_to_user((struct st_susfs_version __user *)*user_info,
	    &info, sizeof(info)))
		info.err = -EFAULT;
}

/* ----------------------------------------------------------------- */
/*  SDCARD MONITOR                                                   */
/* ----------------------------------------------------------------- */
#define SDCARD_ANDROID_PATH "/data/media/0/Android"
DEFINE_STATIC_KEY_TRUE(susfs_is_sdcard_android_data_not_decrypted);

struct watch_dir {
	const char *path;
	u32 mask;
	struct path kpath;
	struct inode *inode;
	struct fsnotify_mark *mark;
};

static struct fsnotify_group *g;
static struct watch_dir g_watch = {
	.path = "/data/media/0",
	.mask = (FS_EVENT_ON_CHILD | FS_ISDIR | FS_OPEN_PERM),
};

static unsigned long sdcard_cleanup_scheduled;
static struct delayed_work sdcard_cleanup_dwork;

static void susfs_sdcard_cleanup_fn(struct work_struct *work)
{
	struct fsnotify_group *grp;
	struct inode *inode;

	if (static_key_enabled(&susfs_is_sdcard_android_data_not_decrypted))
		static_branch_disable(&susfs_is_sdcard_android_data_not_decrypted);
	SUSFS_LOGI("/sdcard is decrypted\n");

	grp = xchg(&g, NULL);
	if (grp)
		fsnotify_destroy_group(grp);

	g_watch.mark = NULL;

	inode = xchg(&g_watch.inode, NULL);
	if (inode)
		iput(inode);

	if (g_watch.kpath.mnt) {
		path_put(&g_watch.kpath);
		memset(&g_watch.kpath, 0, sizeof(g_watch.kpath));
	}
}

static int watch_one_dir(struct watch_dir *wd)
{
	struct fsnotify_mark *mark;
	int ret = kern_path(wd->path, LOOKUP_FOLLOW, &wd->kpath);
	if (ret) {
		SUSFS_LOGI("path not ready: %s (%d)\n", wd->path, ret);
		return ret;
	}
	wd->inode = d_backing_inode(wd->kpath.dentry);
	if (!wd->inode) {
		path_put(&wd->kpath);
		return -ENOENT;
	}
	ihold(wd->inode);

	mark = wd->mark;
	if (!mark) {
		SUSFS_LOGE("mark is NULL for '%s'\n", wd->path);
		iput(wd->inode);
		wd->inode = NULL;
		path_put(&wd->kpath);
		return -EINVAL;
	}

	ret = fsnotify_add_inode_mark(mark, wd->inode, 0);
	if (ret) {
		iput(wd->inode);
		wd->inode = NULL;
		path_put(&wd->kpath);
		return ret;
	}
	return 0;
}

static int susfs_handle_sdcard_inode_event(struct fsnotify_group *group,
					   struct inode *inode, u32 mask,
					   const void *data, int data_type,
					   susfs_fname_t file_name, u32 cookie,
					   struct fsnotify_iter_info *iter_info)
{
	if (!file_name || susfs_fname_len(file_name) != 7 ||
	    memcmp(susfs_fname_arg(file_name), "Android", 7))
		return 0;

	if (test_and_set_bit(0, &sdcard_cleanup_scheduled))
		return 0;

	SUSFS_LOGI("Android dir detected, deferring cleanup 5s\n");
	queue_delayed_work(system_unbound_wq, &sdcard_cleanup_dwork, 5 * HZ);
	return 0;
}

static void susfs_free_fsnotify_mark(struct fsnotify_mark *mark)
{
	kfree(mark);
}

static const struct fsnotify_ops fsnotify_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
	.handle_inode_event = susfs_handle_sdcard_inode_event,
#else
	.handle_event = susfs_handle_sdcard_inode_event,
#endif
	.free_mark = susfs_free_fsnotify_mark,
};

static int susfs_sdcard_monitor_fn(void *data)
{
	struct cred *cred;
	int ret;

	cred = prepare_creds();
	if (!cred)
		return -ENOMEM;
	setup_selinux("u:r:ksu:s0", cred);
	commit_creds(cred);

	susfs_setup_sids();

	if (!susfs_is_current_ksu_domain())
		return -EINVAL;

	INIT_DELAYED_WORK(&sdcard_cleanup_dwork, susfs_sdcard_cleanup_fn);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	g = fsnotify_alloc_group(&fsnotify_ops, 0);
#else
	g = fsnotify_alloc_group(&fsnotify_ops);
#endif
	if (IS_ERR(g))
		return PTR_ERR(g);

	g_watch.mark = kzalloc(sizeof(struct fsnotify_mark), GFP_KERNEL);
	if (!g_watch.mark) {
		fsnotify_destroy_group(g);
		g = NULL;
		return -ENOMEM;
	}
	fsnotify_init_mark(g_watch.mark, g);

	ret = watch_one_dir(&g_watch);
	if (ret) {
		SUSFS_LOGI("sdcard monitor start failed: %d\n", ret);
		fsnotify_put_mark(g_watch.mark);
		g_watch.mark = NULL;
		fsnotify_destroy_group(g);
		g = NULL;
		return ret;
	}
	SUSFS_LOGI("sdcard monitor started\n");
	return 0;
}

void susfs_start_sdcard_monitor_fn(void)
{
	if (IS_ERR(kthread_run(susfs_sdcard_monitor_fn, NULL,
			       "susfs_sdcard_monitor"))) {
		SUSFS_LOGE("failed to create sdcard monitor thread\n");
		if (static_key_enabled(&susfs_is_sdcard_android_data_not_decrypted))
			static_branch_disable(&susfs_is_sdcard_android_data_not_decrypted);
	}
}

/* ----------------------------------------------------------------- */
/*  INIT                                                             */
/* ----------------------------------------------------------------- */
struct work_struct susfs_extra_works;

static void susfs_run_extra_works(struct work_struct *work)
{
	if (!ksu_cred)
		return;
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
	susfs_run_sus_path_loop();
#endif
}

void susfs_setup_sids(void)
{
	susfs_set_ksu_sid();
	susfs_set_zygote_sid();
	susfs_set_init_sid();
	susfs_set_priv_app_sid();
}

/* ----------------------------------------------------------------- */
/*  Kernel hook registration                                         */
/*  Defined here so the symbol exists regardless of Kbuild sed        */
/*  patching. Kbuild injects call sites into fs/stat.c and            */
/*  kernel/sys.c that reference these.                                */
/* ----------------------------------------------------------------- */
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
void (*susfs_kstat_hook)(struct inode *inode, struct kstat *stat) = NULL;
static int __init susfs_register_kstat_hook(void)
{
	susfs_kstat_hook = susfs_sus_kstat_spoof_generic_fillattr;
	return 0;
}
#else
static int __init susfs_register_kstat_hook(void) { return 0; }
#endif

#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
void (*susfs_uname_hook)(struct new_utsname *tmp) = NULL;
static int __init susfs_register_uname_hook(void)
{
	write_seqlock(&susfs_uname_seqlock);
	strscpy(my_uname.release, utsname()->release, __NEW_UTS_LEN);
	strscpy(my_uname.version, utsname()->version, __NEW_UTS_LEN);
	write_sequnlock(&susfs_uname_seqlock);
	susfs_uname_hook = susfs_spoof_uname;
	return 0;
}
#else
static int __init susfs_register_uname_hook(void) { return 0; }
#endif

#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
void (*susfs_cmdline_hook)(struct seq_file *m) = NULL;
static int __init susfs_register_cmdline_hook(void)
{
	susfs_cmdline_hook = susfs_spoof_cmdline_or_bootconfig;
	return 0;
}
#else
static int __init susfs_register_cmdline_hook(void) { return 0; }
#endif

void susfs_init(void)
{
	SUSFS_LOGI("Initializing susfs_extra_works\n");
	INIT_WORK(&susfs_extra_works, susfs_run_extra_works);
	susfs_register_kstat_hook();
	susfs_register_uname_hook();
	susfs_register_cmdline_hook();
	/* Best-effort SID initialization; may fail until SELinux policy is loaded */
	susfs_setup_sids();
	SUSFS_LOGI("susfs initialized! version: " SUSFS_VERSION "\n");
}
