// SPDX-License-Identifier: GPL-2.0-or-later
/* Kernel services Stela does not provide yet. */
#include <linux/folio_batch.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/platform_device.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/swap.h>
#include <stela/linux.h>
#include <unsupported.h>

/* Pages behind shmem files and shmem-backed GEM objects, which swap and
 * nouveau's TTM objects never need: TTM allocates pages from its own pool and
 * Stela never reclaims them. */
STELA_UNSUPPORTED(struct folio *, shmem_read_folio_gfp, struct address_space *, pgoff_t, gfp_t)
STELA_UNSUPPORTED(struct page *, shmem_read_mapping_page_gfp, struct address_space *, pgoff_t,
		  gfp_t)
STELA_UNSUPPORTED(void, shmem_truncate_range, struct inode *, loff_t, uoff_t)
struct swap_iocb;
STELA_UNSUPPORTED(int, shmem_writeout, struct folio *, struct swap_iocb **, struct list_head *)
STELA_UNSUPPORTED(bool, folio_clear_dirty_for_io, struct folio *)
/* Transparent huge mappings of shmem-backed objects. */
STELA_UNSUPPORTED(unsigned long, mm_get_unmapped_area, struct file *, unsigned long,
		  unsigned long, unsigned long, unsigned long)
/* debugfs's seq_file operations, which no file opens: Stela has no debugfs. */
STELA_UNSUPPORTED(int, single_open, struct file *, int (*)(struct seq_file *, void *), void *)
STELA_UNSUPPORTED(int, single_release, struct inode *, struct file *)
STELA_UNSUPPORTED(ssize_t, seq_read, struct file *, char __user *, size_t, loff_t *)
STELA_UNSUPPORTED(loff_t, seq_lseek, struct file *, loff_t, int)
/* Platform devices, of which only HDMI audio codecs reach DRM. */
STELA_UNSUPPORTED(void, platform_device_unregister, struct platform_device *)

/* The mm/vma.o member that Stela's environment compiles references the
 * surrounding MM subsystem, whose provider files (mm/rmap.c, mm/mmap.c,
 * mm/mmu_gather.c, mm/mlock.c, mm/shmem.c, mm/util.c) Stela deliberately
 * does not build: Linux code under Stela owns no address space and edits no
 * CPU page table. The references are link-time only; no Stela entry point
 * reaches them, so each traps rather than inventing an answer. Types named
 * here that are not in the public headers are forward-declared. */
struct unmap_desc;
/* mm/rmap.c: the anon_vma chain maintenance vma.o references on unmap.
 * anon_vma_clone's enum argument is passed by value; its ABI is an int, so
 * the trap takes an int rather than naming the private enum vma_operation. */
STELA_UNSUPPORTED(int, anon_vma_clone, struct vm_area_struct *, struct vm_area_struct *, int)
STELA_UNSUPPORTED(int, __anon_vma_prepare, struct vm_area_struct *)
STELA_UNSUPPORTED(void, unlink_anon_vmas, struct vm_area_struct *)
STELA_UNSUPPORTED(void, anon_vma_interval_tree_insert, struct anon_vma_chain *,
		  struct rb_root_cached *)
STELA_UNSUPPORTED(void, anon_vma_interval_tree_remove, struct anon_vma_chain *,
		  struct rb_root_cached *)
/* mm/mmap.c: VMA lookups and the mmu_gather/TLB teardown vma.o calls. */
STELA_UNSUPPORTED(struct vm_area_struct *, find_vma_prev, struct mm_struct *, unsigned long,
		  struct vm_area_struct **)
STELA_UNSUPPORTED(struct vm_area_struct *, find_vma_intersection, struct mm_struct *,
		  unsigned long, unsigned long)
STELA_UNSUPPORTED(void, unmap_vmas, struct mmu_gather *, struct unmap_desc *)
STELA_UNSUPPORTED(void, free_pgtables, struct mmu_gather *, struct unmap_desc *)
STELA_UNSUPPORTED(void, tlb_gather_mmu, struct mmu_gather *, struct mm_struct *)
STELA_UNSUPPORTED(void, tlb_finish_mmu, struct mmu_gather *)
STELA_UNSUPPORTED(void, vma_interval_tree_insert, struct vm_area_struct *,
		  struct rb_root_cached *)
STELA_UNSUPPORTED(void, vma_interval_tree_remove, struct vm_area_struct *,
		  struct rb_root_cached *)
STELA_UNSUPPORTED(bool, may_expand_vm, struct mm_struct *, const vma_flags_t *, unsigned long)
STELA_UNSUPPORTED(void, vm_stat_account, struct mm_struct *, vm_flags_t, long)
STELA_UNSUPPORTED(void, vma_set_page_prot, struct vm_area_struct *)
STELA_UNSUPPORTED(int, mmap_action_prepare, struct vm_area_desc *)
STELA_UNSUPPORTED(int, mmap_action_complete, struct vm_area_struct *,
		  struct mmap_action *, bool)
/* mm/util.c / mm/mmap.c: the mmap policy checks and the security LSM hook. */
STELA_UNSUPPORTED(int, __vm_enough_memory, const struct mm_struct *, long, int)
STELA_UNSUPPORTED(int, cap_vm_enough_memory, struct mm_struct *, long)
STELA_UNSUPPORTED(int, compat_vma_mmap, struct file *, struct vm_area_struct *)
/* mm/mlock.c: the mlock charge check. */
STELA_UNSUPPORTED(bool, mlock_future_ok, const struct mm_struct *, bool, unsigned long)
/* mm/shmem.c: the shmem zero-fault setup. */
STELA_UNSUPPORTED(int, shmem_zero_setup, struct vm_area_struct *)
/* The MM policy variables vma.o reads; their boot-time values are irrelevant
 * to a link-time reference that no Stela path reaches. */
unsigned long mmap_min_addr = 0;
unsigned long stack_guard_gap = 0;
int sysctl_max_map_count = 0;
