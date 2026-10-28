/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PANIC_NOTIFIER_H
#define _LINUX_PANIC_NOTIFIER_H

#include <linux/types.h>

#define NOTIFY_DONE 0x0000
#define NOTIFY_OK   0x0001

struct notifier_block {
	int (*notifier_call)(struct notifier_block *nb, unsigned long action, void *data);
	struct notifier_block *next;
	int priority;
};

struct atomic_notifier_head {
	struct notifier_block *head;
};

extern struct atomic_notifier_head panic_notifier_list;

static inline int atomic_notifier_chain_register(struct atomic_notifier_head *nh,
						 struct notifier_block *n)
{
	n->next = nh->head;
	nh->head = n;
	return 0;
}

#endif /* _LINUX_PANIC_NOTIFIER_H */
