/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_CPU_NS_H
#define _LINUX_CPU_NS_H

#include <linux/sched.h>
#include <linux/bug.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>

struct cpu_namespace {
	/* Virtual map of cpus in the cpuset */
	cpumask_t v_cpuset_cpus;
	/* map for CPU translation -- Physical --> Virtual */
	int p_v_trans_map[NR_CPUS];
	/* map for CPU translation -- Virtual --> Physical */
	int v_p_trans_map[NR_CPUS];
	struct cpu_namespace *parent;
	struct ucounts *ucounts;
	struct user_namespace *user_ns;
	struct ns_common ns;
} __randomize_layout;

extern struct cpu_namespace init_cpu_ns;

#ifdef CONFIG_CPU_NS

static inline struct cpu_namespace *get_cpu_ns(struct cpu_namespace *ns)
{
	if (ns != &init_cpu_ns)
		refcount_inc(&ns->ns.count);
	return ns;
}

/*
 * Get the virtual CPU for the requested physical CPU in the ns context
*/
static inline int get_vcpu_cpuns(struct cpu_namespace *c, int pcpu)
{
	if (pcpu >= NR_CPUS)
		return -1;

	return c->p_v_trans_map[pcpu];
}

/*
 * Get the physical CPU for requested virtual CPU in the ns context
*/
static inline int get_pcpu_cpuns(struct cpu_namespace *c, int vcpu)
{
	if (vcpu >= NR_CPUS)
		return -1;
	
	return c->v_p_trans_map[vcpu];
}

/*
 * Given the physical CPU map get the virtual CPUs corresponding to that ns
*/
static inline cpumask_t get_vcpus_cpuns(struct cpu_namespace *c,
					const cpumask_var_t mask)
{
	int cpu;
	cpumask_t temp;

	cpumask_clear(&temp);

	for_each_cpu(cpu, mask) {
		cpumask_set_cpu(get_vcpu_cpuns(c, cpu), &temp);
	}

	return temp;
}

/*
 * Given a virtual CPU map get the physical CPUs corresponding to that ns
*/
static inline cpumask_t get_pcpus_cpuns(struct cpu_namespace *c,
					const cpumask_var_t mask)
{
	int cpu;
	cpumask_t temp;

	cpumask_clear(&temp);

	for_each_cpu(cpu, mask) {
		cpumask_set_cpu(get_pcpu_cpuns(c, cpu), &temp);
	}

	return temp;
}

extern struct cpu_namespace *copy_cpu_ns(unsigned long flags,
	struct user_namespace *user_ns, struct cpu_namespace *ns);
extern void zap_cpu_ns_processes(struct cpu_namespace *cpu_ns);
extern int reboot_cpu_ns(struct cpu_namespace *cpu_ns, int cmd);
extern void put_cpu_ns(struct cpu_namespace *ns);

#else /* !CONFIG_CPU_NS */
#include <linux/err.h>

static inline struct cpu_namespace *get_cpu_ns(struct cpu_namespace *ns)
{
	return ns;
}

static inline struct cpu_namespace *copy_cpu_ns(unsigned long flags,
	struct user_namespace *user_ns, struct cpu_namespace *ns)
{
	if (flags & CLONE_NEWCPU)
		ns = ERR_PTR(-EINVAL);
	return ns;
}

static inline void zap_cpu_ns_processes(struct cpu_namespace *cpu_ns)
{
	BUG();
}

static inline int reboot_cpu_ns(struct cpu_namespace *cpu_ns, int cmd)
{
	return 0;
}

static inline void put_cpu_ns(struct cpu_namespace *ns)
{
	return;
}

static inline cpumask_t get_vcpus_cpuns(struct cpu_namespace *c,
					const cpumask_var_t mask)
{
	cpumask_t temp;

	cpumask_clear(&temp);
	return temp;
}

static inline cpumask_t get_pcpus_cpuns(struct cpu_namespace *c,
					const cpumask_var_t mask)
{
	cpumask_t temp;

	cpumask_clear(&temp);
	return temp;
}

static inline int get_vcpu_cpuns(struct cpu_namespace *c, int pcpu)
{
	return pcpu;
}

static inline int get_pcpu_cpuns(struct cpu_namespace *c, int vcpu)
{
	return vcpu;
}

// struct cpu_namespace init_cpu_ns = {
// 	.ns.count	= REFCOUNT_INIT(0),
// 	.user_ns	= &init_user_ns,
// 	.ns.inum	= 0,
// 	.ns.ops		= NULL,
// };
// struct cpu_namespace init_cpu_ns = NULL;
// EXPORT_SYMBOL(init_cpu_ns);

#endif /* CONFIG_CPU_NS */

#endif /* _LINUX_CPU_NS_H */