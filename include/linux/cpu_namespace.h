/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_CPU_NS_H
#define _LINUX_CPU_NS_H

#include <linux/sched.h>
#include <linux/bug.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>


/*
 * Cpumask:
 *
 * display_cpus_mask is a mask that is used to show to the cpuset.cpus and
 * populate sysfs online/possible/present files and directories
 *
 * translation_cpu_mask is what is passed to the scheduler by calling
 * __do_set_cpus_allowed with the list which passes the mask to the
 * task struct cpus_mask
 *
 * Case 1: Init
 * display_cpus_mask = online cpus
 * translation_cpu_mask = online cpus
 *
 * Case 2: In case of cpuset
 * display_cpu_mask = cpuset.cpus gotten from cgroups
 * translation_cpu_mask = N CPUs from display_cpu_mask but scambled
 * 		from online cpus.
 * 		Challenge: How to determine the translating CPUs without
 * 		hurting the performance of the other workloads
 *
 * Case 3: In case of setting period and quota
 * If quota not -1. then number of cpus = period/quota = N cpus
 * display_cpu_mask: 0 to (N -1) cpus
 * translation_cpu_mask: online cpus list
 *
*/

struct cpu_namespace {
	cpumask_t v_cpuset_cpus;
	/* map for the translation -- TODO convert to hashmap for O(1) search pcpu->vcpu search */
	int trans_map[NR_CPUS];
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

static inline bool cpu_online_cpu_ns(unsigned int cpu)
{
	if (current->nsproxy->cpu_ns == &init_cpu_ns)
		return cpumask_test_cpu(cpu, cpu_online_mask);

	printk(KERN_DEBUG "cpu online entered for CPU: %d\n", cpu);
	return cpumask_test_cpu(cpu, &current->nsproxy->cpu_ns->v_cpuset_cpus);
}

/*
 * Get the translation of the cpumask in the context in that CPU namespace
*/
static inline void get_vcpus_cpuns(struct cpu_namespace *c, cpumask_var_t mask)
{
	int cpu;
	cpumask_var_t temp;

	cpumask_clear(temp);

	for_each_cpu(cpu, mask) {
		cpumask_set_cpu(c->trans_map[cpu], temp);
	}

	printk(KERN_DEBUG "[DEBUG] get_vcpus_cpuns mask %*pbl\n",
			cpumask_pr_args(temp));

	cpumask_copy(mask, temp);
}

static inline void get_pcpus_cpuns(struct cpu_namespace *c, cpumask_var_t mask)
{
	int cpu;
	cpumask_var_t temp;
	int t_cpu;

	cpumask_clear(temp);

	for_each_cpu(cpu, mask) {
		for (t_cpu = 0; t_cpu < NR_CPUS; t_cpu++) {
			if (c->trans_map[t_cpu] == cpu)
				cpumask_set_cpu(t_cpu, temp);
		}
	}

	printk(KERN_DEBUG "[DEBUG] get_pcpus_cpuns mask %*pbl\n",
			cpumask_pr_args(temp));

	cpumask_copy(mask, temp);
}

static inline void get_cpuns_cpus_temp(struct cpu_namespace *c, cpumask_var_t mask)
{
	int cpu;
	cpumask_var_t temp;

	cpumask_clear(temp);

	for_each_cpu(cpu, mask) {
		cpumask_set_cpu(c->trans_map[cpu], temp);
	}

	printk(KERN_DEBUG "[DEBUG] get_cpuns_cpus mask %*pbl\n",
			cpumask_pr_args(temp));

	cpumask_copy(&c->v_cpuset_cpus, temp);
}


static inline int get_pcpu_ns(struct cpu_namespace *c, int cpu)
{
	int t_cpu;

	for (t_cpu = 0; t_cpu < NR_CPUS; t_cpu++) {
		if (c->trans_map[t_cpu] == cpu)
			return t_cpu;
	}
	return -1;
}

static inline int get_vcpu(struct cpu_namespace *c, int pcpu)
{
	int t_cpu;

	for (t_cpu = 0; t_cpu < NR_CPUS; t_cpu++) {
		if (c->trans_map[t_cpu] == pcpu)
			return t_cpu;
	}
	return -1;
}

// static inline void update_cpu_ns_cfs(struct cpu_namespace *ns, long quota, long period)
// {
// 	int num_cpus = 0;
// 	int i;

// 	if (quota == -1) {
// 		cpumask_copy(&ns->display_cpus_mask, cpu_present_mask);
// 		return ;
// 	}

// 	// printk(KERN_DEBUG "quota %lld period: %lld\n", quota, period);
// 	num_cpus = DIV_ROUND_UP_ULL(quota, period);

// 	cpumask_clear(&ns->display_cpus_mask);

// 	for (i = 0; i < num_cpus; i++)
// 		cpumask_set_cpu(i, &ns->display_cpus_mask);

// 	// printk(KERN_DEBUG "[DEBUG] update_cpu_ns_cfs mask %*pbl\n",
// 	// 		cpumask_pr_args(&ns->display_cpus_mask));
// 	// cpumask_copy(&ns->v_cpuset_cpus, &ns->display_cpus_mask);
// }



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
}

static inline void get_vcpus_cpuns(struct cpu_namespace *ns, cpumask_var_t mask)
{
}

static inline int get_vcpu(struct cpu_namespace *c, int pcpu)
{

}

static inline int get_pcpu_ns(struct cpu_namespace *c, int cpu)
{

}
#endif /* CONFIG_CPU_NS */

#endif /* _LINUX_CPU_NS_H */