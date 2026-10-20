#ifndef __KSU_SYMBOL_RESOLVER_H
#define __KSU_SYMBOL_RESOLVER_H

void *ksu_resolve_symbol_for_functable_hook(const char *symbol_name);
unsigned long find_kernel_symbol_exact(const char *symbol_name);
void ksu_init_symbol_resolver();

// Batch wrapper around find_kernel_symbol_exact() for KSU_IOCTL_LOOKUP_SYMBOLS.
// names/addrs are kernel-side arrays of `count` entries (already copied in
// from userspace by the caller); a name that doesn't resolve gets addrs[i] = 0.
// Returns the number of symbols that resolved, or a negative errno.
int ksu_lookup_kernel_symbols(const char *const *names, unsigned long *addrs, unsigned int count);

#endif
