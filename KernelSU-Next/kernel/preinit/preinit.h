#ifndef __KSU_H_PREINIT
#define __KSU_H_PREINIT

#include <linux/fs.h>

// Forward-declared on purpose, not included: some callers (e.g.
// runtime/ksud_integration.c) keep their own local copy of this struct
// (same layout, verified) rather than including runtime/user_arg_ptr.h, and
// including it here too would make it a duplicate definition in their
// translation unit. A pointer type only needs this forward declaration.
struct user_arg_ptr;

#ifndef KSU_NO_PREINIT
void ksu_preinit_init(void);
void ksu_preinit_exit(void);

// Swap the runner in for PID 1's "/system/bin/init selinux_setup" (or
// "/init selinux_setup" pre-Android-10) execve. Called from inside the
// manual execve hook, before the real exec runs. Mutates *filename_ptr in
// place (freeing the original and allocating a fresh struct filename) and
// returns true when it did so; the caller does not need to do anything
// else; the normal exec path takes it from there.
bool ksu_preinit_handle_execve(struct filename **filename_ptr, struct user_arg_ptr *argv);

// Drop the staged runner if selinux_setup was never seen (e.g. this is a
// late-loaded LKM, or the module reached second_stage/zygote without us
// ever matching the hook -- shouldn't normally happen, but avoids leaking
// the shmem file forever if it does).
void ksu_preinit_release(void);

// Whether the runner is built in and not disabled with preinit=0.
bool ksu_preinit_enabled_param(void);
#else
static inline void ksu_preinit_init(void)
{
}
static inline void ksu_preinit_exit(void)
{
}
static inline bool ksu_preinit_handle_execve(struct filename **filename_ptr, struct user_arg_ptr *argv)
{
	return false;
}
static inline void ksu_preinit_release(void)
{
}
static inline bool ksu_preinit_enabled_param(void)
{
	return false;
}
#endif

#endif // __KSU_H_PREINIT
