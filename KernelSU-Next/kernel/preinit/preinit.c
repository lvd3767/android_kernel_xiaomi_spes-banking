#include <linux/err.h>
#include <linux/fcntl.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/moduleparam.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/shmem_fs.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/compat.h>

#include "klog.h" // IWYU pragma: keep
#include "preinit/preinit.h"
// Full definition needed here (preinit.h only forward-declares it): unlike
// runtime/ksud_integration.c, this file has no local copy of its own.
#include "runtime/user_arg_ptr.h"

#define INIT_PATH "/system/bin/init"
#define OLD_INIT_PATH "/init"

// The runner is a static ELF embedded into .init.rodata by preinit/blob.S.
extern const char ksu_preinit_runner_start[];
extern const char ksu_preinit_runner_end[];

static bool ksu_preinit_enabled = true;
module_param_named(preinit, ksu_preinit_enabled, bool, 0);

// Owned here until PID 1 executes it; the init section holding the blob is
// gone by then, so it lives in an unlinked shmem file.
static struct file *ksu_preinit_file;

void __init ksu_preinit_init(void)
{
	size_t size = ksu_preinit_runner_end - ksu_preinit_runner_start;
	struct file *file;
	loff_t pos = 0;
	ssize_t written;

	if (!ksu_preinit_enabled) {
		pr_info("preinit: disabled\n");
		return;
	}

	file = shmem_file_setup("ksu_preinit", size, 0);
	if (IS_ERR(file)) {
		pr_err("preinit: shmem_file_setup failed: %ld\n", PTR_ERR(file));
		return;
	}

	written = kernel_write(file, ksu_preinit_runner_start, size, &pos);
	if (written != size) {
		pr_err("preinit: write runner failed: %zd\n", written);
		fput(file);
		return;
	}

	ksu_preinit_file = file;
	pr_info("preinit: runner staged (%zu bytes)\n", size);
}

bool ksu_preinit_enabled_param(void)
{
	return ksu_preinit_enabled;
}

void ksu_preinit_release(void)
{
	struct file *file = xchg(&ksu_preinit_file, NULL);

	if (file) {
		pr_info("preinit: selinux_setup not seen, dropping runner\n");
		fput(file);
	}
}

void ksu_preinit_exit(void)
{
	ksu_preinit_release();
}

// Duplicated locally rather than reused from runtime/ksud_integration.c:
// that copy is `static`, and sulog/event.c already keeps its own copy
// under a different name for the same reason (see
// ksu_sulog_get_user_arg_ptr) -- this follows that existing house pattern
// instead of changing the visibility of code outside preinit/'s scope.
static const char __user *preinit_get_user_arg_ptr(struct user_arg_ptr argv, int nr)
{
	const char __user *native;

#ifdef CONFIG_COMPAT
	if (unlikely(argv.is_compat)) {
		compat_uptr_t compat;

		if (get_user(compat, argv.ptr.compat + nr))
			return ERR_PTR(-EFAULT);

		return compat_ptr(compat);
	}
#endif

	if (get_user(native, argv.ptr.native + nr))
		return ERR_PTR(-EFAULT);

	return native;
}

static inline void preinit_close_fd(int fd)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
	close_fd(fd);
#else
	__close_fd(current->files, fd);
#endif
}

// NOTE on manual-hook adaptation: unlike upstream KernelSU-Next (which
// hooks at the syscall-table level and re-invokes
// ksu_syscall_table[orig_nr](regs) on the mutated pt_regs), this tree uses
// CONFIG_KSU_MANUAL_HOOK: the hook runs *inside* do_execveat_common(),
// before the real exec happens, and communicates the substitution purely
// by mutating *filename_ptr. The normal exec path then picks up whatever
// struct filename we leave behind and calls putname() on it itself once
// done (see fs/exec.c: do_execveat_common / __do_execve_file's out_ret
// path). So instead of swapping the raw user pointer with a userspace
// stack buffer (upstream's approach, meant for a pt_regs re-entry), we
// allocate a fresh struct filename with getname_kernel() and swap the
// pointer.
//
// This also deliberately does NOT reuse feature/sucompat.c's in-place
// memcpy-into-filename->name trick: that only works because SU_PATH /
// KSUD_PATH are fixed, known-safe lengths relative to the original
// allocation. "/proc/self/fd/<fd>" has a variable length (the fd number is
// unbounded in principle) and could exceed the buffer the kernel allocated
// for "/system/bin/init", so memcpy-in-place here would risk a heap
// overflow. A fresh allocation via getname_kernel()/putname() sidesteps
// that entirely.
static bool is_selinux_setup(struct user_arg_ptr *argv)
{
	static const char expected[] = "selinux_setup";
	const char __user *arg;
	char buf[sizeof(expected) + 1];

	if (!argv)
		return false;

	arg = preinit_get_user_arg_ptr(*argv, 1);
	if (!arg || IS_ERR(arg))
		return false;

	memset(buf, 0, sizeof(buf));
	if (strncpy_from_user(buf, arg, sizeof(buf) - 1) < 0)
		return false;

	return !strcmp(buf, expected);
}

bool ksu_preinit_handle_execve(struct filename **filename_ptr, struct user_arg_ptr *argv)
{
	struct filename *orig_filename;
	struct filename *new_filename;
	char fd_path[32];
	struct file *file;
	struct path p;
	int fd, len;

	if (likely(!READ_ONCE(ksu_preinit_file)))
		return false;

	if (!filename_ptr || !*filename_ptr || IS_ERR(*filename_ptr))
		return false;

	orig_filename = *filename_ptr;
	if (strcmp(orig_filename->name, INIT_PATH) && strcmp(orig_filename->name, OLD_INIT_PATH))
		return false;

	if (!is_selinux_setup(argv))
		return false;

	// One shot: the runner's own later exec of the real init must pass
	// through untouched, so only the first (selinux_setup) call wins the
	// race on ksu_preinit_file.
	file = xchg(&ksu_preinit_file, NULL);
	if (!file)
		return false;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		pr_err("preinit: get fd failed: %d\n", fd);
		fput(file);
		return false;
	}
	// The fd owns the file from here on; close-on-exec frees it once the
	// runner has been loaded by the exec path below.
	fd_install(fd, file);

	len = snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
	if (kern_path(fd_path, LOOKUP_FOLLOW, &p)) {
		pr_err("preinit: %s not reachable, booting without preinit\n", fd_path);
		preinit_close_fd(fd);
		return false;
	}
	path_put(&p);

	new_filename = getname_kernel(fd_path);
	if (IS_ERR(new_filename)) {
		pr_err("preinit: getname_kernel(%s) failed: %ld, booting without preinit\n",
			fd_path, PTR_ERR(new_filename));
		preinit_close_fd(fd);
		return false;
	}

	pr_info("preinit: swapping exec target to %s (len %d)\n", fd_path, len);
	putname(orig_filename);
	*filename_ptr = new_filename;
	return true;
}
