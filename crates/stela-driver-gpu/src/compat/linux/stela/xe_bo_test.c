// SPDX-License-Identifier: GPL-2.0-or-later
/* xe_bo reservation state machine on the original dma_resv/dma_fence
 * environment: a completed BO write fence coexists with an in-flight BO read
 * fence, and a preemption replace drops the in-flight fence so readers can
 * proceed. Stacked fences with a no-op release keep the test owner-free
 * beyond the bare stela_linux_enter boundary. The heap-allocated resv list
 * is reclaimed by the host on exit; no fence or list free path is exercised. */
#include <linux/dma-fence.h>
#include <linux/dma-resv.h>
#include <stela/linux.h>
#include <stela/test.h>

struct bo_fence {
	struct dma_fence base;
};
static void fence_release(struct dma_fence *fence)
{
	(void)fence; /* stacked object, reclaimed when main returns */
}
static const char *fence_name(struct dma_fence *fence)
{
	(void)fence;
	return "xe-bo";
}
static const struct dma_fence_ops bo_ops = {
	.get_driver_name = fence_name,
	.get_timeline_name = fence_name,
	.release = fence_release,
};

static struct bo_fence make_fence(u64 context, u64 seqno)
{
	struct bo_fence f = {0};
	dma_fence_init(&f.base, &bo_ops, NULL, context, seqno);
	return f;
}

int main(void)
{
	stela_linux_enter(&stela_linux_bare);
	struct dma_resv resv;
	dma_resv_init(&resv);
	assert(!dma_resv_reserve_fences(&resv, 4));
	u64 write_ctx = dma_fence_context_alloc(1);
	u64 read_ctx = dma_fence_context_alloc(1);

	/* A completed BO write fence on its own context, fully signaled. */
	struct bo_fence done = make_fence(write_ctx, 1);
	dma_fence_signal_timestamp_locked(&done.base, 0);
	assert(dma_fence_is_signaled(&done.base));
	dma_resv_add_fence(&resv, &done.base, DMA_RESV_USAGE_WRITE);

	/* An in-flight BO read fence on a second context: the object is not
	 * yet usable for readers even though the writer already completed. */
	struct bo_fence pending = make_fence(read_ctx, 1);
	assert(!dma_fence_is_signaled(&pending.base));
	dma_resv_add_fence(&resv, &pending.base, DMA_RESV_USAGE_READ);
	assert(dma_resv_test_signaled(&resv, DMA_RESV_USAGE_WRITE));
	assert(!dma_resv_test_signaled(&resv, DMA_RESV_USAGE_READ));

	/* Preemption replaces the in-flight read fence with the completed one,
	 * so a reader no longer waits on pending work and the object is free. */
	dma_resv_replace_fences(&resv, pending.base.context, &done.base,
				DMA_RESV_USAGE_READ);
	assert(dma_resv_test_signaled(&resv, DMA_RESV_USAGE_READ));
	assert(dma_resv_test_signaled(&resv, DMA_RESV_USAGE_BOOKKEEP));

	stela_linux_exit();
	printf("Linux Xe bo resv: contexts %llu/%llu, preemption replace, signaled fences\n",
	       (unsigned long long)write_ctx, (unsigned long long)read_ctx);
	return 0;
}
