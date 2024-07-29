// SPDX-License-Identifier: GPL-2.0
#include <linux/sizes.h>

#include <test_util.h>
#include <kvm_util.h>
#include <processor.h>
#include "sev.h"

/* Arbitrarily chosen values */
#define TEST_SIZE		(SZ_2M + PAGE_SIZE)
#define TEST_NPAGES		(TEST_SIZE / PAGE_SIZE)
#define TEST_SLOT		10
#define TEST_GPA		0x100000000ul
#define TEST_GVA		0x100000000ul

/*
 * Test for falloc-dealloc behavior in combination that primarily
 * pivots around the SNP_LAUNCH_UPDATE boundary
 */
enum falloc_test_type {
	NO_FALLOC,

	/* falloc-dealloc test before launch_update */
	ALLOC_BEFORE_SNP_LAUNCH_UPDATE,
	DEALLOC_BEFORE_SNP_LAUNCH_UPDATE,
	ALLOC_DEALLOC_BEFORE_SNP_LAUNCH_UPDATE,

	/* falloc-dealloc test after launch_update */
	ALLOC_AFTER_SNP_LAUNCH_UPDATE,
	DEALLOC_AFTER_SNP_LAUNCH_UPDATE,	/* Negative test */
	ALLOC_DEALLOC_AFTER_SNP_LAUNCH_UPDATE	/* Negative test */
};

static void guest_code_sev(void)
{
	volatile uint64_t val __used;
	int i;

	GUEST_ASSERT(rdmsr(MSR_AMD64_SEV) & MSR_AMD64_SEV_ENABLED);

	for (i = 0; i < TEST_NPAGES; i++) {
		uint64_t *src = (uint64_t *)(TEST_GVA + i * PAGE_SIZE);

		val = *src;
		/* Validate the data stored in the pages */
		if ((i < TEST_NPAGES / 2 && val == i + 1) ||
		    (i >= TEST_NPAGES / 2 && val == 0)) {
			continue;
		}
		GUEST_FAIL("Inconsistent view of memory values in guest");
	}

	if (rdmsr(MSR_AMD64_SEV) & MSR_AMD64_SEV_ES_ENABLED) {
		wrmsr(MSR_AMD64_SEV_ES_GHCB, GHCB_MSR_TERM_REQ);
		__asm__ __volatile__("rep; vmmcall");
		GUEST_FAIL("This should be unreachable.");
	}

	GUEST_DONE();
}

static void __pre_fault_memory(struct kvm_vcpu *vcpu, u64 gpa, u64 size,
			       u64 left, bool private, bool expect_fail)
{
	struct kvm_pre_fault_memory range = {
		.gpa = gpa,
		.size = size,
		.flags = 0,
	};
	bool cond;
	u64 prev;
	int ret, save_errno;

	do {
		prev = range.size;
		ret = __vcpu_ioctl(vcpu, KVM_PRE_FAULT_MEMORY, &range);
		save_errno = errno;
		TEST_ASSERT((range.size < prev) ^ (ret < 0),
			    "%sexpecting range.size to change on %s",
			    ret < 0 ? "not " : "",
			    ret < 0 ? "failure" : "success");
	} while (ret >= 0 ? range.size : save_errno == EINTR);

	cond = (range.size == left);
	TEST_ASSERT(expect_fail ? !cond : cond,
		    "[EXPECT %s] Completed with %lld bytes left, expected %" PRId64,
		    expect_fail ? "FAIL" : "PASS",
		    range.size, left);

	if (left == 0) {
		cond = !ret;
	} else {
		/*
		 * For shared memory, no memory slot causes RET_PF_EMULATE. It
		 * results in -ENOENT.
		 *
		 * For private memory, no memory slot is an error case returning
		 * -EFAULT, but it also possible the only the GPA ranges backed
		 *  by a slot are marked as private, in which case the noslot
		 *  range will also result in -ENOENT.
		 *
		 *  So allow both errors for now, but in the future it would be
		 *  good to distinguish between these cases to tighten up the
		 *  error-checking.
		 */
		cond = ret && (save_errno == EFAULT || save_errno == ENOENT);
	}

	TEST_ASSERT(expect_fail ? !cond : cond,
		    "[EXPECT %s] KVM_PRE_FAULT_MEMORY",
		    expect_fail ? "FAIL" : "PASS");
}

static void pre_fault_memory_private(struct kvm_vcpu *vcpu, u64 gpa,
				     u64 size, u64 left)
{
	__pre_fault_memory(vcpu, gpa, size, left, true, false);
}

static void pre_fault_memory_shared(struct kvm_vcpu *vcpu, u64 gpa,
				    u64 size, u64 left)
{
	__pre_fault_memory(vcpu, gpa, size, left, false, false);
}

static void pre_fault_memory_negative(struct kvm_vcpu *vcpu, u64 gpa,
					   u64 size, u64 left, bool private)
{
	__pre_fault_memory(vcpu, gpa, size, left, private, true);
}


static void __falloc_region(struct kvm_vm *vm, bool punch_hole)
{
	int ctr, ret, flags = FALLOC_FL_KEEP_SIZE;
	struct userspace_mem_region *region;

	hash_for_each(vm->regions.slot_hash, ctr, region, slot_node) {
		if (punch_hole)
			flags |= FALLOC_FL_PUNCH_HOLE;
		ret = fallocate(region->region.guest_memfd, flags, 0, PAGE_SIZE * TEST_NPAGES);
		TEST_ASSERT(!ret, "fallocate should succeed.");
	}
}

static void falloc_region(struct kvm_vm *vm)
{
	__falloc_region(vm, false);
}

static void falloc_hole_punch_region(struct kvm_vm *vm)
{
	__falloc_region(vm, true);
}

static void test_pre_fault_memory_sev(unsigned long vm_type, bool private,
				      enum falloc_test_type f_type)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct ucall uc;
	int i;

	vm = vm_sev_create_with_one_vcpu(vm_type, guest_code_sev, &vcpu);

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    TEST_GPA, TEST_SLOT, TEST_NPAGES,
				    (vm_type == KVM_X86_SNP_VM) ? KVM_MEM_GUEST_MEMFD : 0);

	/*
	 * Make sure guest page table is in agreement with what pages will be
	 * initially encrypted by the ASP.
	 */
	if (private)
		vm_mem_set_protected(vm, TEST_SLOT, TEST_GPA, TEST_NPAGES);

	virt_map(vm, TEST_GVA, TEST_GPA, TEST_NPAGES);

	/*
	 * Populate the pages to compare data read from the guest
	 * Populate the first half with data and second half as all zeros.
	 */
	for (i = 0; i < TEST_NPAGES; i++) {
		uint64_t *hva = addr_gva2hva(vm, TEST_GVA + i * PAGE_SIZE);

		if (i < TEST_NPAGES / 2)
			*hva = i + 1;
		else
			*hva = 0;
	}

	if (vm_type == KVM_X86_SNP_VM) {
		uint64_t policy = SNP_POLICY_SMT | SNP_POLICY_RSVD_MBO;
		int ret;

		if (f_type == ALLOC_BEFORE_SNP_LAUNCH_UPDATE ||
		    f_type == ALLOC_DEALLOC_BEFORE_SNP_LAUNCH_UPDATE) {
			falloc_region(vm);
		}

		pre_fault_memory_negative(vcpu, TEST_GPA, SZ_2M, 0, false);

		if (f_type == DEALLOC_BEFORE_SNP_LAUNCH_UPDATE ||
		    f_type == ALLOC_DEALLOC_BEFORE_SNP_LAUNCH_UPDATE) {
			falloc_hole_punch_region(vm);
		}

		ret = snp_vm_launch(vm, policy, 0);
		TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_SEV_SNP_LAUNCH_START, ret));

		if (f_type == ALLOC_BEFORE_SNP_LAUNCH_UPDATE ||
		    f_type == ALLOC_DEALLOC_BEFORE_SNP_LAUNCH_UPDATE) {
			falloc_region(vm);
		}

		if (f_type == DEALLOC_BEFORE_SNP_LAUNCH_UPDATE ||
		    f_type == ALLOC_DEALLOC_BEFORE_SNP_LAUNCH_UPDATE) {
			falloc_hole_punch_region(vm);
		}
		/*
		 * NOTE: For SNP, the pre-faulting of private pages needs to be
		 * done after SNP_LAUNCH_START, since that is the point when the
		 * guest ASID is bound to the SNP context, and that operation
		 * will fail if RMP entries have already been setup that
		 * reference the ASID being bound.
		 *
		 * Furthermore, pre-faulting must be skipped for any pages that
		 * are to be part of the initial encrypted/measured guest state,
		 * since those pages must initially be in a shared state in the
		 * RMP table.
		 */
		if (private) {
			/*
			 * Make sure when pages are pre-faulted later after
			 * finalization they are treated the same as a private
			 * access by the guest and so that the expected gmem
			 * backing pages are used.
			 */
			pre_fault_memory_negative(vcpu, TEST_GPA, SZ_2M, 0, false);
			vm_mem_set_private(vm, TEST_GPA, TEST_SIZE);
			pre_fault_memory_negative(vcpu, TEST_GPA, SZ_2M, 0, true);
		} else {
			/* Shared pages can be pre-faulted any time. */
			pre_fault_memory_negative(vcpu, TEST_GPA, SZ_2M, 0, true);
		}

		ret = snp_vm_launch_update(vm, KVM_SEV_SNP_PAGE_TYPE_NORMAL);
		TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_SEV_SNP_LAUNCH_UPDATE, ret));

		if (f_type == ALLOC_AFTER_SNP_LAUNCH_UPDATE ||
		    f_type == ALLOC_DEALLOC_AFTER_SNP_LAUNCH_UPDATE) {
			falloc_region(vm);
		}

		if (f_type == DEALLOC_AFTER_SNP_LAUNCH_UPDATE ||
		    f_type == ALLOC_DEALLOC_AFTER_SNP_LAUNCH_UPDATE) {
			falloc_hole_punch_region(vm);
		}

		ret = snp_vm_launch_finish(vm, 0);
		TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_SEV_SNP_LAUNCH_FINISH, ret));

		/*
		 * After finalization, pre-faulting either private or shared
		 * ranges should work regardless of whether the pages were
		 * encrypted as part of setting up initial guest state.
		 */
		pre_fault_memory_private(vcpu, TEST_GPA, SZ_2M, 0);
		pre_fault_memory_private(vcpu, TEST_GPA + SZ_2M, PAGE_SIZE * 2, PAGE_SIZE);
		pre_fault_memory_private(vcpu, TEST_GPA + TEST_SIZE, PAGE_SIZE, PAGE_SIZE);

		if (f_type == ALLOC_AFTER_SNP_LAUNCH_UPDATE ||
		    f_type == ALLOC_DEALLOC_AFTER_SNP_LAUNCH_UPDATE) {
			falloc_region(vm);
		}

		if (f_type == DEALLOC_AFTER_SNP_LAUNCH_UPDATE ||
		    f_type == ALLOC_DEALLOC_AFTER_SNP_LAUNCH_UPDATE) {
			falloc_hole_punch_region(vm);
		}
	} else {
		uint32_t policy = (vm_type == KVM_X86_SEV_ES_VM) ? SEV_POLICY_ES : 0;
		void *measurement;
		int ret;

		pre_fault_memory_shared(vcpu, TEST_GPA, SZ_2M, 0);
		pre_fault_memory_shared(vcpu, TEST_GPA + SZ_2M, PAGE_SIZE * 2, PAGE_SIZE);
		pre_fault_memory_shared(vcpu, TEST_GPA + TEST_SIZE, PAGE_SIZE, PAGE_SIZE);

		ret = sev_vm_launch_start(vm, policy);
		TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_SEV_LAUNCH_START, ret));

		pre_fault_memory_shared(vcpu, TEST_GPA, SZ_2M, 0);
		pre_fault_memory_shared(vcpu, TEST_GPA + SZ_2M, PAGE_SIZE * 2, PAGE_SIZE);
		pre_fault_memory_shared(vcpu, TEST_GPA + TEST_SIZE, PAGE_SIZE, PAGE_SIZE);

		ret = sev_vm_launch_update(vm, policy);
		TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_SEV_LAUNCH_UPDATE_DATA, ret));

		measurement = alloca(256);
		ret = sev_vm_launch_measure(vm, measurement);
		TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_SEV_LAUNCH_MEASURE, ret));

		pre_fault_memory_shared(vcpu, TEST_GPA, SZ_2M, 0);
		pre_fault_memory_shared(vcpu, TEST_GPA + SZ_2M, PAGE_SIZE * 2, PAGE_SIZE);
		pre_fault_memory_shared(vcpu, TEST_GPA + TEST_SIZE, PAGE_SIZE, PAGE_SIZE);

		ret = sev_vm_launch_finish(vm);
		TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_SEV_LAUNCH_FINISH, ret));

		pre_fault_memory_shared(vcpu, TEST_GPA, SZ_2M, 0);
		pre_fault_memory_shared(vcpu, TEST_GPA + SZ_2M, PAGE_SIZE * 2, PAGE_SIZE);
		pre_fault_memory_shared(vcpu, TEST_GPA + TEST_SIZE, PAGE_SIZE, PAGE_SIZE);
	}

	vcpu_run(vcpu);

	/* Expect SHUTDOWN when we fallocate using PUNCH_HOLE after SNP_UPDATE */
	if (f_type == DEALLOC_AFTER_SNP_LAUNCH_UPDATE ||
	    f_type == ALLOC_DEALLOC_AFTER_SNP_LAUNCH_UPDATE) {
		TEST_ASSERT(vcpu->run->exit_reason == KVM_EXIT_SHUTDOWN,
			    "Wanted SYSTEM_EVENT, got %s",
			    exit_reason_str(vcpu->run->exit_reason));
		goto out;
	}

	if (vm->type == KVM_X86_SEV_ES_VM || vm->type == KVM_X86_SNP_VM) {
		TEST_ASSERT(vcpu->run->exit_reason == KVM_EXIT_SYSTEM_EVENT,
			    "Wanted SYSTEM_EVENT, got %s",
			    exit_reason_str(vcpu->run->exit_reason));
		TEST_ASSERT_EQ(vcpu->run->system_event.type, KVM_SYSTEM_EVENT_SEV_TERM);
		TEST_ASSERT_EQ(vcpu->run->system_event.ndata, 1);
		TEST_ASSERT_EQ(vcpu->run->system_event.data[0], GHCB_MSR_TERM_REQ);
		goto out;
	}

	switch (get_ucall(vcpu, &uc)) {
	case UCALL_DONE:
		break;
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
	default:
		TEST_FAIL("Unexpected exit: %s",
			  exit_reason_str(vcpu->run->exit_reason));
	}

out:
	kvm_vm_free(vm);
}

static void test_pre_fault_memory(unsigned long vm_type, bool private)
{
	if (vm_type && !(kvm_check_cap(KVM_CAP_VM_TYPES) & BIT(vm_type))) {
		pr_info("Skipping tests for vm_type 0x%lx\n", vm_type);
		return;
	}

	switch (vm_type) {
	case KVM_X86_SEV_VM:
	case KVM_X86_SEV_ES_VM:
		test_pre_fault_memory_sev(vm_type, private, NO_FALLOC);
		break;
	case KVM_X86_SNP_VM:
		for (int test = NO_FALLOC; test <= ALLOC_DEALLOC_AFTER_SNP_LAUNCH_UPDATE; test++) {
			test_pre_fault_memory_sev(vm_type, private, test);
		}
		break;
	default:
		abort();
	}
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_check_cap(KVM_CAP_PRE_FAULT_MEMORY));

	test_pre_fault_memory(KVM_X86_SEV_VM, false);
	test_pre_fault_memory(KVM_X86_SEV_VM, true);
	test_pre_fault_memory(KVM_X86_SEV_ES_VM, false);
	test_pre_fault_memory(KVM_X86_SEV_ES_VM, true);
	test_pre_fault_memory(KVM_X86_SNP_VM, false);
	test_pre_fault_memory(KVM_X86_SNP_VM, true);

	return 0;
}
