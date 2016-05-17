#include "qemutcg.h"
#include "qemu/osdep.h"
#include "cpu.h"
#include "tcg.h"

static const char *tcg_type_nm_map[] = {"I32", "I64", "COUNT"};

static void dump_tcg_globals(void) {
  for (unsigned i = 0; i < tcg_ctx.nb_globals; ++i) {
    TCGTemp *ts = &tcg_ctx.temps[i];
    printf("type: %s "
           "name: %s "
           "reg: %u "
           "fixed_reg: %u "
           "indirect_reg: %u "
           "indirect_base: %u "
           "mem_coherent: %u "
           "mem_allocated: %u "
           "mem_offset: %u "
           "val: %u\n",
           tcg_type_nm_map[ts->type],
           ts->name,
           (unsigned)ts->reg,
           (unsigned)ts->fixed_reg,
           (unsigned)ts->indirect_reg,
           (unsigned)ts->indirect_base,
           (unsigned)ts->mem_coherent,
           (unsigned)ts->mem_allocated,
           (unsigned)ts->mem_offset,
           (unsigned)ts->val);
  }
}

static void print_tcg_globals(void) {
  for (unsigned i = 0; i < tcg_ctx.nb_globals; ++i) {
    TCGTemp* ts = &tcg_ctx.temps[i];

    // 
    // we are interested in TCG global memory regs, not TCG global regs (e.g. env).
    // From target-i386/translate.c:7865, we can see that a TCG global reg has
    // fixed_reg = 1
    //

    if (ts->fixed_reg)
      continue;

    printf("%s\n%u\n%s\n", tcg_type_nm_map[ts->type], (unsigned)ts->mem_offset,
           ts->name);
  }
}

#define CPUSTATE_FIELD(FIELD) do { \
    printf("  " #FIELD " : " "%u = 0x%x\n", \
      (unsigned)offsetof(CPUX86State, FIELD), \
      (unsigned)offsetof(CPUX86State, FIELD)); \
} while (0)

void dump_cpu_state(void) {
#if defined(TARGET_X86_64)
  printf("CPUX86State\n");
  CPUSTATE_FIELD(regs);
  CPUSTATE_FIELD(eip);
  CPUSTATE_FIELD(eflags);
  CPUSTATE_FIELD(cc_dst);
  CPUSTATE_FIELD(cc_src);
  CPUSTATE_FIELD(cc_src2);
  CPUSTATE_FIELD(cc_op);
  CPUSTATE_FIELD(df);
  CPUSTATE_FIELD(hflags);
  CPUSTATE_FIELD(hflags2);
  CPUSTATE_FIELD(segs);
  CPUSTATE_FIELD(ldt);
  CPUSTATE_FIELD(tr);
  CPUSTATE_FIELD(gdt);
  CPUSTATE_FIELD(idt);
  CPUSTATE_FIELD(cr);
  CPUSTATE_FIELD(a20_mask);
  CPUSTATE_FIELD(bnd_regs);
  CPUSTATE_FIELD(bndcs_regs);
  CPUSTATE_FIELD(msr_bndcfgs);
  CPUSTATE_FIELD(efer);
  CPUSTATE_FIELD(fpstt);
  CPUSTATE_FIELD(fpus);
  CPUSTATE_FIELD(fpuc);
  CPUSTATE_FIELD(fptags);
  CPUSTATE_FIELD(fpregs);
  CPUSTATE_FIELD(fpop);
  CPUSTATE_FIELD(fpip);
  CPUSTATE_FIELD(fpdp);
  CPUSTATE_FIELD(fp_status);
  CPUSTATE_FIELD(ft0);
  CPUSTATE_FIELD(mmx_status);
  CPUSTATE_FIELD(sse_status);
  CPUSTATE_FIELD(mxcsr);
  CPUSTATE_FIELD(xmm_regs);
  CPUSTATE_FIELD(xmm_t0);
  CPUSTATE_FIELD(mmx_t0);
  CPUSTATE_FIELD(opmask_regs);
  CPUSTATE_FIELD(sysenter_cs);
  CPUSTATE_FIELD(sysenter_esp);
  CPUSTATE_FIELD(sysenter_eip);
  CPUSTATE_FIELD(star);
  CPUSTATE_FIELD(vm_hsave);
  CPUSTATE_FIELD(lstar);
  CPUSTATE_FIELD(cstar);
  CPUSTATE_FIELD(fmask);
  CPUSTATE_FIELD(kernelgsbase);
  CPUSTATE_FIELD(tsc);
  CPUSTATE_FIELD(tsc_adjust);
  CPUSTATE_FIELD(tsc_deadline);
  CPUSTATE_FIELD(mcg_status);
  CPUSTATE_FIELD(msr_ia32_misc_enable);
  CPUSTATE_FIELD(msr_ia32_feature_control);
  CPUSTATE_FIELD(msr_fixed_ctr_ctrl);
  CPUSTATE_FIELD(msr_global_ctrl);
  CPUSTATE_FIELD(msr_global_status);
  CPUSTATE_FIELD(msr_global_ovf_ctrl);
  CPUSTATE_FIELD(msr_fixed_counters);
  CPUSTATE_FIELD(msr_gp_counters);
  CPUSTATE_FIELD(msr_gp_evtsel);
  CPUSTATE_FIELD(pat);
  CPUSTATE_FIELD(smbase);
  CPUSTATE_FIELD(system_time_msr);
  CPUSTATE_FIELD(wall_clock_msr);
  CPUSTATE_FIELD(steal_time_msr);
  CPUSTATE_FIELD(async_pf_en_msr);
  CPUSTATE_FIELD(pv_eoi_en_msr);
  CPUSTATE_FIELD(msr_hv_hypercall);
  CPUSTATE_FIELD(msr_hv_guest_os_id);
  CPUSTATE_FIELD(msr_hv_vapic);
  CPUSTATE_FIELD(msr_hv_tsc);
  CPUSTATE_FIELD(msr_hv_crash_params);
  CPUSTATE_FIELD(msr_hv_runtime);
  CPUSTATE_FIELD(error_code);
  CPUSTATE_FIELD(exception_is_int);
  CPUSTATE_FIELD(exception_next_eip);
  CPUSTATE_FIELD(dr);
  CPUSTATE_FIELD(cpu_breakpoint);
  CPUSTATE_FIELD(cpu_watchpoint);
  CPUSTATE_FIELD(old_exception);
  CPUSTATE_FIELD(vm_vmcb);
  CPUSTATE_FIELD(tsc_offset);
  CPUSTATE_FIELD(intercept);
  CPUSTATE_FIELD(intercept_cr_read);
  CPUSTATE_FIELD(intercept_cr_write);
  CPUSTATE_FIELD(intercept_dr_read);
  CPUSTATE_FIELD(intercept_dr_write);
  CPUSTATE_FIELD(intercept_exceptions);
  CPUSTATE_FIELD(v_tpr);
  CPUSTATE_FIELD(nmi_injected);
  CPUSTATE_FIELD(nmi_pending);
  CPUSTATE_FIELD(cpuid_level);
  CPUSTATE_FIELD(cpuid_xlevel);
  CPUSTATE_FIELD(cpuid_xlevel2);
  CPUSTATE_FIELD(cpuid_vendor1);
  CPUSTATE_FIELD(cpuid_vendor2);
  CPUSTATE_FIELD(cpuid_vendor3);
  CPUSTATE_FIELD(cpuid_version);
  CPUSTATE_FIELD(features);
  CPUSTATE_FIELD(cpuid_model);
  CPUSTATE_FIELD(mtrr_fixed);
  CPUSTATE_FIELD(mtrr_deftype);
  CPUSTATE_FIELD(mtrr_var);
  CPUSTATE_FIELD(mp_state);
  CPUSTATE_FIELD(exception_injected);
  CPUSTATE_FIELD(interrupt_injected);
  CPUSTATE_FIELD(soft_interrupt);
  CPUSTATE_FIELD(has_error_code);
  CPUSTATE_FIELD(sipi_vector);
  CPUSTATE_FIELD(tsc_valid);
  CPUSTATE_FIELD(tsc_khz);
  CPUSTATE_FIELD(kvm_xsave_buf);
  CPUSTATE_FIELD(mcg_cap);
  CPUSTATE_FIELD(mcg_ctl);
  CPUSTATE_FIELD(mce_banks);
  CPUSTATE_FIELD(tsc_aux);
  CPUSTATE_FIELD(fpus_vmstate);
  CPUSTATE_FIELD(fptag_vmstate);
  CPUSTATE_FIELD(fpregs_format_vmstate);
  CPUSTATE_FIELD(xstate_bv);
  CPUSTATE_FIELD(xcr0);
  CPUSTATE_FIELD(xss);
  CPUSTATE_FIELD(tpr_access_type);
#endif
}

int main(int argc, char** argv) {
  libqemutcg_init();

  if (argc == 2)
    dump_tcg_globals();
  else if (argc == 3)
    dump_cpu_state();
  else
    print_tcg_globals();

  return 0;
}
