/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Forced into every Linux translation unit after Linux's compiler_types.h.
 * Linux places code and data in named sections for its own linker script:
 * init and exit code, read-mostly data, once flags, symbol and parameter
 * tables. Linux code links into Stela's images instead, which keep every
 * object in the platform's default sections and enumerate none of those
 * tables; Mach-O hosts also reject their names. */
#undef __section
#define __section(section)
/* The pinned headers also reach that named-section placement through the
 * built-in `__section__` spelling that cache.h's __cacheline_aligned and the
 * init section macros expand to; no Stela linker script enumerates those
 * tables, so shadow it as a variadic macro alongside the macro above. */
#define __section__(...)
#if defined(__MACH__)
/* Mach-O rejects the `alias` attribute these stubs carry, and a hosted build
 * links no syscall table, so the stubs are dead weight: keep the upstream
 * expansions verbatim, dropping only the alias. */
#define __SYSCALL_DEFINEx(x, name, ...) \
	asmlinkage long sys##name(__MAP(x,__SC_DECL,__VA_ARGS__)); \
	ALLOW_ERROR_INJECTION(sys##name, ERRNO); \
	static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__)); \
	asmlinkage long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__)); \
	asmlinkage long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__)) \
	{ \
		long ret = __do_sys##name(__MAP(x,__SC_CAST,__VA_ARGS__)); \
		__MAP(x,__SC_TEST,__VA_ARGS__); \
		__PROTECT(x, ret,__MAP(x,__SC_ARGS,__VA_ARGS__)); \
		return ret; \
	} \
	static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))
#define COMPAT_SYSCALL_DEFINEx(x, name, ...) \
	asmlinkage long compat_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__)); \
	static inline long __do_compat_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__)); \
	asmlinkage long __se_compat_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__)); \
	asmlinkage long __se_compat_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__)) \
	{ \
		long ret = __do_compat_sys##name(__MAP(x,__SC_DELOUSE,__VA_ARGS__)); \
		__MAP(x,__SC_TEST,__VA_ARGS__); \
		return ret; \
	} \
	static inline long __do_compat_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))
#endif
#undef __noinstr_section
#define __noinstr_section(section) noinline notrace

/* Explicit driver and helper identities take precedence over the common one. */
#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "stela-linux"
#endif
#ifndef KBUILD_MODFILE
#define KBUILD_MODFILE "stela-linux"
#endif

/* Linux's -fshort-wchar contract also applies to hosted ELF builds; without
 * it, an original L"..." is incompatible with EFI's 16-bit character ABI. */
#ifndef __ASSEMBLER__
_Static_assert(sizeof(*L"") == 2, "Linux compiler requires 16-bit wide literals");
#endif
/* Client calls cannot bypass the single boot-owned namespace authority. */
#include <stela/acpi_client.h>
