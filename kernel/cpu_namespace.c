// SPDX-License-Identifier: GPL-2.0-only
/*
 * CPU namespaces
 *
 * Author:
 *    (C) 2021 Pratik Rajesh Sampat <psampat@linux.ibm.com>, IBM
*/

#include <linux/cpu_namespace.h>
#include <linux/syscalls.h>
#include <linux/proc_ns.h>
#include <linux/export.h>
#include <linux/acct.h>
#include <linux/err.h>
#include <linux/random.h>

static struct kmem_cache *cpu_ns_cachep;

static void dec_cpu_namespaces(struct ucounts *ucounts)
{
	dec_ucount(ucounts, UCOUNT_CPU_NAMESPACES);
}

// static void delayed_free_cpuns(struct rcu_head *p)
// {
// 	struct cpu_namespace *ns = container_of(p, struct cpu_namespace, rcu);

// 	dec_cpu_namespaces(ns->ucounts);
// 	put_user_ns(ns->user_ns);

// 	kmem_cache_free(cpu_ns_cachep, ns);
// }

static void destroy_cpu_namespace(struct cpu_namespace *ns)
{
	ns_free_inum(&ns->ns);

	dec_cpu_namespaces(ns->ucounts);
	put_user_ns(ns->user_ns);

	kmem_cache_free(cpu_ns_cachep, ns);

	// call_rcu(&ns->rcu, delayed_free_cpuns);
}

static struct ucounts *inc_cpu_namespaces(struct user_namespace *ns)
{
	return inc_ucount(ns, current_euid(), UCOUNT_CPU_NAMESPACES);
}

/*
 * Shuffle logic - https://benpfaff.org/writings/clc/shuffle.html
 * Copyright © 2004 Ben Pfaff.
*/
#define RAND_MAX	32767
void shuffle(int *array, size_t n)
{
	int i;
	unsigned int rnd_num;
	int j, t;

	if (n <= 1)
		return;

	for (i = 0; i < n-1; i++) {
		get_random_bytes(&rnd_num, sizeof(rnd_num));
		rnd_num = rnd_num % RAND_MAX;

		j = i + rnd_num / (RAND_MAX / (n - i) + 1);
		t = array[j];
		array[j] = array[i];
		array[i] = t;
	}
}
static struct cpu_namespace *create_cpu_namespace(struct user_namespace *user_ns,
	struct cpu_namespace *parent_cpu_ns)
{
	struct cpu_namespace *ns;
	struct ucounts *ucounts;
	// int cpu_arr[200];
	int *cpu_arr;
	int err;
	int cpu;
	int n = 0;
	int i;
	struct task_struct *p = current;
	cpumask_t temp;

	err = -EINVAL;
	if (!in_userns(parent_cpu_ns->user_ns, user_ns))
		goto out;

	ucounts = inc_cpu_namespaces(user_ns);
	if (!ucounts)
		goto out;

	err = -ENOMEM;
	ns = kmem_cache_zalloc(cpu_ns_cachep, GFP_KERNEL);
	if (ns == NULL)
		goto out_dec;

	err = ns_alloc_inum(&ns->ns);
	if (err)
		goto out_free_kmem_cache;
	ns->ns.ops = &cpuns_operations;

	refcount_set(&ns->ns.count, 1);
	ns->parent = get_cpu_ns(parent_cpu_ns);
	ns->user_ns = get_user_ns(user_ns);
	cpumask_copy(&ns->v_cpuset_cpus, &parent_cpu_ns->v_cpuset_cpus);
	memcpy (ns->trans_map, parent_cpu_ns->trans_map, sizeof(parent_cpu_ns->trans_map)); 

	cpu_arr = kmalloc(sizeof(int) * num_possible_cpus(), GFP_KERNEL);
	if (!cpu_arr)
		goto out_free_kmem_cache;

	for_each_present_cpu(cpu) {
		cpu_arr[n++] = cpu;
	}

	shuffle(cpu_arr, n);

	cpumask_clear(&temp);
	for (i = 0; i < n; i++) {
		// printk(KERN_DEBUG "[DEBUG] CPU [%d] = %d\n", i, cpu_arr[i]);
		ns->trans_map[i] = cpu_arr[i];
		cpumask_set_cpu(cpu_arr[i], &temp);
	}


	printk(KERN_DEBUG "[DEBUG] CPU [%d] = %d\n", 0, ns->trans_map[0]);

	printk(KERN_DEBUG "[DEBUG] cpu namespace has been cloned\n");
	printk(KERN_DEBUG "[DEBUG] PID %d\n", p->pid);

	do_set_cpus_allowed(p, &temp);
	kfree (cpu_arr);

	return ns;

out_free_kmem_cache:
	kmem_cache_free(cpu_ns_cachep, ns);
out_dec:
	dec_cpu_namespaces(ucounts);
out:
	return ERR_PTR(err);
}

struct cpu_namespace *copy_cpu_ns(unsigned long flags,
	struct user_namespace *user_ns, struct cpu_namespace *old_ns)
{
	if (!(flags & CLONE_NEWCPU))
		return get_cpu_ns(old_ns);
	return create_cpu_namespace(user_ns, old_ns);
}

void put_cpu_ns(struct cpu_namespace *ns)
{
	struct cpu_namespace *parent;

	while (ns != &init_cpu_ns) {
		parent = ns->parent;
		if (!refcount_dec_and_test(&ns->ns.count))
			break;
		destroy_cpu_namespace(ns);
		ns = parent;
	}
}
EXPORT_SYMBOL_GPL(put_cpu_ns);

static inline struct cpu_namespace *to_cpu_ns(struct ns_common *ns)
{
	return container_of(ns, struct cpu_namespace, ns);
}

static struct ns_common *cpuns_get(struct task_struct *task)
{
	struct cpu_namespace *ns = NULL;
	struct nsproxy *nsproxy;

	task_lock(task);
	nsproxy = task->nsproxy;
	if (nsproxy) {
		ns = nsproxy->cpu_ns;
		get_cpu_ns(ns);
	}
	task_unlock(task);

	return ns ? &ns->ns : NULL;
}

static struct ns_common *cpuns_for_children_get(struct task_struct *task)
{
	struct cpu_namespace *ns = NULL;
	struct nsproxy *nsproxy;

	task_lock(task);
	nsproxy = task->nsproxy;
	if (nsproxy) {
		ns = nsproxy->cpu_ns_for_children;
		get_cpu_ns(ns);
	}
	task_unlock(task);

	return ns ? &ns->ns : NULL;

}

static void cpuns_put(struct ns_common *ns)
{
	put_cpu_ns(to_cpu_ns(ns));
}

static int cpuns_install(struct nsset *nsset, struct ns_common *new)
{
	struct nsproxy *nsproxy = nsset->nsproxy;
	struct cpu_namespace *ns = to_cpu_ns(new);

	if (!ns_capable(ns->user_ns, CAP_SYS_ADMIN) ||
	    !ns_capable(nsset->cred->user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	get_cpu_ns(ns);
	put_cpu_ns(nsproxy->cpu_ns);
	nsproxy->cpu_ns = ns;

	/* TOOD: CPU ns for children */
	get_cpu_ns(ns);
	put_cpu_ns(nsproxy->cpu_ns_for_children);
	nsproxy->cpu_ns_for_children = ns;
	return 0;
}

static struct user_namespace *cpuns_owner(struct ns_common *ns)
{
	return to_cpu_ns(ns)->user_ns;
}

// TODO
// static struct ns_common *cpuns_get_parent(struct ns_common *ns)
// {
// 	return;
// }

const struct proc_ns_operations cpuns_operations = {
	.name		= "cpu",
	.type		= CLONE_NEWCPU,
	.get		= cpuns_get,
	.put		= cpuns_put,
	.install	= cpuns_install,
	.owner		= cpuns_owner,
	// .get_parent	= cpuns_get_parent,
};

const struct proc_ns_operations cpuns_for_children_operations = {
	.name		= "cpu_for_children",
	.real_ns_name	= "cpu",
	.type		= CLONE_NEWCPU,
	.get		= cpuns_for_children_get,
	.put		= cpuns_put,
	.install	= cpuns_install,
	.owner		= cpuns_owner,
	// .get_parent	= cpuns_get_parent,
};


struct cpu_namespace init_cpu_ns = {
	.ns.count	= REFCOUNT_INIT(2),
	.user_ns	= &init_user_ns,
	.ns.inum	= PROC_CPU_INIT_INO,
	.ns.ops		= &cpuns_operations,
};
EXPORT_SYMBOL(init_cpu_ns);

static __init int cpu_namespaces_init(void)
{
	int cpu;

	cpu_ns_cachep = KMEM_CACHE(cpu_namespace, SLAB_PANIC);

	cpumask_copy(&init_cpu_ns.v_cpuset_cpus, cpu_present_mask);

	/* Identity mapping for the cpu_namespace init */
	for_each_present_cpu(cpu) {
		init_cpu_ns.trans_map[cpu] = cpu;
	}

	printk(KERN_DEBUG "[DEBUG] cpu namespace has been initted\n");

	return 0;
}
__initcall(cpu_namespaces_init);
