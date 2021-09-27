/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_CPU_NS_H
#define _LINUX_CPU_NS_H

#include <linux/sched.h>
#include <linux/bug.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>

/*
 * Virtual CPUs  => View of the CPUs in the CPU NS context
 * Physical CPUs => CPU as viewed by host, also known as logical CPUs
 */
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
	if (pcpu >= num_possible_cpus())
		return -1;

	return c->p_v_trans_map[pcpu];
}

/*
 * Get the physical CPU for requested virtual CPU in the ns context
 */
static inline int get_pcpu_cpuns(struct cpu_namespace *c, int vcpu)
{
	if (vcpu >= num_possible_cpus())
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

static inline void put_cpu_ns(struct cpu_namespace *ns)
{
}

static inline int get_vcpu_cpuns(struct cpu_namespace *c, int pcpu)
{
	return pcpu;
}

static inline int get_pcpu_cpuns(struct cpu_namespace *c, int vcpu)
{
	return vcpu;
}

static inline cpumask_t get_vcpus_cpuns(struct cpu_namespace *c,
					const cpumask_var_t mask)
{
	cpumask_t temp;
	int cpu;

	cpumask_clear(&temp);

	for_each_cpu(cpu, mask) {
		cpumask_set_cpu(get_vcpu_cpuns(c, cpu), &temp);
	}

	return temp;
}

static inline cpumask_t get_pcpus_cpuns(struct cpu_namespace *c,
					const cpumask_var_t mask)
{
	cpumask_t temp;
	int cpu;

	cpumask_clear(&temp);

	for_each_cpu(cpu, mask) {
		cpumask_set_cpu(get_pcpu_cpuns(c, cpu), &temp);
	}

	return temp;
}

#endif /* CONFIG_CPU_NS */

#endif /* _LINUX_CPU_NS_H */
