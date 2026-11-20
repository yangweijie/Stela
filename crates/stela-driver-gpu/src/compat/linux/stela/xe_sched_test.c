// SPDX-License-Identifier: GPL-2.0-or-later
/* xe scheduler fence signaling on the original dma_fence environment:
 * queued callbacks fire exactly once on signal, late callbacks are rejected,
 * and an errored fence reports its failure status. */
#include <linux/dma-fence.h>
#include <linux/errno.h>
#include <stela/linux.h>
#include <stela/test.h>

struct sched_fence {
	struct dma_fence base;
	unsigned int fired;
};

static void fence_release(struct dma_fence *fence)
{
	(void)fence; /* stacked object, reclaimed when main returns */
}
static const char *fence_name(struct dma_fence *fence)
{
	(void)fence;
	return "xe-sched";
}
static const struct dma_fence_ops sched_ops = {
	.get_driver_name = fence_name,
	.get_timeline_name = fence_name,
	.release = fence_release,
};

static void sched_callback(struct dma_fence *fence, struct dma_fence_cb *cb)
{
	struct sched_fence *sf = container_of(fence, struct sched_fence, base);
	(void)cb;
	sf->fired++;
}

int main(void)
{
	stela_linux_enter(&stela_linux_bare);
	u64 context = dma_fence_context_alloc(1);
	struct sched_fence f = {0};
	dma_fence_init(&f.base, &sched_ops, NULL, context, 1);

	/* Unsignaled: status is zero and nothing has fired. */
	assert(dma_fence_get_status(&f.base) == 0);

	/* A queued callback is registered and fires exactly once on signal. */
	struct dma_fence_cb cb = {0};
	assert(!dma_fence_add_callback(&f.base, &cb, sched_callback));
	dma_fence_signal_timestamp_locked(&f.base, 0);
	assert(dma_fence_is_signaled(&f.base));
	assert(dma_fence_get_status(&f.base) == 1);
	assert(f.fired == 1);

	/* A callback added after the fence is signaled is rejected. */
	struct dma_fence_cb late = {0};
	assert(dma_fence_add_callback(&f.base, &late, sched_callback) == -ENOENT);
	dma_fence_put(&f.base);

	/* An errored fence reports its failure status on completion. */
	struct sched_fence e = {0};
	dma_fence_init(&e.base, &sched_ops, NULL, context, 2);
	dma_fence_set_error(&e.base, -EIO);
	dma_fence_signal_timestamp_locked(&e.base, 0);
	assert(dma_fence_is_signaled(&e.base));
	assert(dma_fence_get_status(&e.base) == -EIO);
	dma_fence_put(&e.base);

	stela_linux_exit();
	printf("Linux Xe sched fence: callback on signal, late rejection, error status\n");
	return 0;
}
