#include "jove/jove.h"

static unsigned long guest_base_addr;
#define g2h(x) ((void *)((((unsigned long)(target_ulong)(x)) - guest_base_addr) + guest_base))

#include "tcg.hpp"
#include "stubs.hpp"

//
// global stubs
//
TraceEvent _TRACE_GUEST_MEM_BEFORE_EXEC_EVENT = {0};
TraceEvent _TRACE_GUEST_MEM_BEFORE_TRANS_EVENT = {0};
uint16_t _TRACE_OBJECT_CLASS_DYNAMIC_CAST_ASSERT_DSTATE;
int singlestep;
int qemu_loglevel;
int trace_events_enabled_count;
unsigned long guest_base;
FILE *qemu_logfile = stdout;
bool qemu_log_in_addr_range(uint64_t addr) { return false; }
const char *lookup_symbol(target_ulong orig_addr) { return nullptr; }
void target_disas(FILE *out, CPUState *cpu, target_ulong code,
                  target_ulong size) {}
void cpu_abort(CPUState *cpu, const char *fmt, ...) {
  abort();
}

namespace jove {
static void _qemu_log(const char *);
}

int qemu_log(const char *fmt, ...) {
  int size;
  va_list ap;

  /* Determine required size */

  va_start(ap, fmt);
  size = vsnprintf(nullptr, 0, fmt, ap);
  va_end(ap);

  if (size < 0)
    return 0;

  size++; /* For '\0' */
  char *p = (char *)malloc(size);
  if (!p)
    return 0;

  va_start(ap, fmt);
  size = vsnprintf(p, size, fmt, ap);
  va_end(ap);

  if (size < 0) {
    free(p);
    return 0;
  }

  jove::_qemu_log(p);
  free(p);

  return size;
}

namespace jove {

static bool do_tcg_optimization = false;

struct tiny_code_generator_t {
#if defined(__x86_64__) || defined(__i386__)
  X86CPU _cpu;
#elif defined(__aarch64__)
  ARMCPU _cpu;
#endif

  TCGContext _ctx;

  tiny_code_generator_t() {
    // zero-initialize CPU
    memset(&_cpu, 0, sizeof(_cpu));

    _cpu.parent_obj.env_ptr = &_cpu.env;

#if defined(__x86_64__)
    _cpu.env.eflags = 514;
    _cpu.env.hflags = 0x0040c0b3;
    _cpu.env.hflags2 = 1;
    _cpu.env.a20_mask = -1;
    _cpu.env.cr[0] = 0x80010001;
    _cpu.env.cr[4] = 0x00000220;
    _cpu.env.mxcsr = 0x00001f80;
    _cpu.env.xcr0 = 3;
    _cpu.env.msr_ia32_misc_enable = 1;
    _cpu.env.pat = 0x0007040600070406ULL;
    _cpu.env.smbase = 0x30000;
    _cpu.env.features[0] = 126614525;
    _cpu.env.features[1] = 2147491841;
    _cpu.env.features[5] = 563346429;
    _cpu.env.features[6] = 5;
    _cpu.env.user_features[0] = 2;
#elif defined(__i386__)
    _cpu.env.eflags = 514;
    _cpu.env.hflags = 0x004000b3;
    _cpu.env.hflags2 = 1;
    _cpu.env.a20_mask = -1;
    _cpu.env.cr[0] = 0x80010001;
    _cpu.env.cr[4] = 0x00000200;
    _cpu.env.mxcsr = 0x00001f80;
    _cpu.env.xcr0 = 3;
    _cpu.env.msr_ia32_misc_enable = 1;
    _cpu.env.pat = 0x0007040600070406ULL;
    _cpu.env.smbase = 0x30000;
    _cpu.env.features[0] = 125938685;
    _cpu.env.features[1] = 2147483649;
    _cpu.env.user_features[0] = 2;
#elif defined(__aarch64__)
    _cpu.env.aarch64 = 1;
    _cpu.env.features = 192517101788915;
#endif

    // zero-initialize TCG
    memset(&_ctx, 0, sizeof(_ctx));

    tcg_context_init(&_ctx);
    _ctx.cpu = &_cpu.parent_obj;

#if defined(__x86_64__) || defined(__i386__)
    tcg_x86_init();
#elif defined(__aarch64__)
    arm_translate_init();
#endif
  }

  void set_section(target_ulong base, const void *contents) {
    guest_base_addr = base;
    guest_base = reinterpret_cast<unsigned long>(contents);
  }

  std::pair<unsigned, terminator_info_t> translate(target_ulong pc,
                                                   target_ulong pc_end = 0) {
    tcg_func_start(&_ctx);

    struct TranslationBlock tb;

    // zero-initialize TranslationBlock
    memset(&tb, 0, sizeof(tb));

    tcg_ctx = &_ctx;

    uint32_t cflags = CF_PARALLEL;
    tcg_ctx->tb_cflags = cflags;
    tb.cflags          = cflags;

    tb.pc = pc;
#if defined(__x86_64__) || defined(__i386__)
    tb.flags = _cpu.env.hflags;
#elif defined(__aarch64__)
    tb.flags = ARM_TBFLAG_AARCH64_STATE_MASK;
#endif
    tb.jove.T.Addr = pc;
    tb.jove.T.Type = TERMINATOR::UNKNOWN;

    __jove_end_pc = pc_end;
    gen_intermediate_code(&_cpu.parent_obj, &tb);

    if (do_tcg_optimization)
      tcg_optimize(&_ctx);

    liveness_pass_1(&_ctx);
    if (_ctx.nb_indirects > 0) {
      /* Replace indirect temps with direct temps.  */
      if (liveness_pass_2(&_ctx)) {
        /* If changes were made, re-run liveness.  */
        liveness_pass_1(&_ctx);
      }
    }

#if defined(__i386__)
    struct terminator_info_t &ti = tb.jove.T;

    /* quirk */
    if (ti.Type == jove::TERMINATOR::CALL &&
        ti._call.Target == ti._call.NextPC) {
      uintptr_t NextPC = ti._call.NextPC;

      ti.Type = jove::TERMINATOR::UNCONDITIONAL_JUMP;
      ti._unconditional_jump.Target = NextPC;
    }
#endif

    return std::make_pair(tb.size, tb.jove.T);
  }

  void dump_operations(void) {
    tcg_dump_ops(&_ctx);
  }
};

#if defined(__x86_64__)

static const unsigned sys_ni_syscall = 0;

static const unsigned __x64_sys_accept = 3;
static const unsigned __x64_sys_accept4 = 4;
static const unsigned __x64_sys_access = 2;
static const unsigned __x64_sys_acct = 1;
static const unsigned __x64_sys_add_key = 5;
static const unsigned __x64_sys_adjtimex = 1;
static const unsigned __x64_sys_alarm = 1;
static const unsigned __x64_sys_arch_prctl = 2;
static const unsigned __x64_sys_bind = 3;
static const unsigned __x64_sys_bpf = 3;
static const unsigned __x64_sys_brk = 1;
static const unsigned __x64_sys_capget = 2;
static const unsigned __x64_sys_capset = 2;
static const unsigned __x64_sys_chdir = 1;
static const unsigned __x64_sys_chmod = 2;
static const unsigned __x64_sys_chown = 3;
static const unsigned __x64_sys_chroot = 1;
static const unsigned __x64_sys_clock_adjtime = 2;
static const unsigned __x64_sys_clock_getres = 2;
static const unsigned __x64_sys_clock_gettime = 2;
static const unsigned __x64_sys_clock_nanosleep = 4;
static const unsigned __x64_sys_clock_settime = 2;
static const unsigned __x64_sys_clone = 5;
static const unsigned __x64_sys_close = 1;
static const unsigned __x64_sys_connect = 3;
static const unsigned __x64_sys_copy_file_range = 6;
static const unsigned __x64_sys_creat = 2;
static const unsigned __x64_sys_delete_module = 2;
static const unsigned __x64_sys_dup = 1;
static const unsigned __x64_sys_dup2 = 2;
static const unsigned __x64_sys_dup3 = 3;
static const unsigned __x64_sys_epoll_create = 1;
static const unsigned __x64_sys_epoll_create1 = 1;
static const unsigned __x64_sys_epoll_ctl = 4;
static const unsigned __x64_sys_epoll_pwait = 6;
static const unsigned __x64_sys_epoll_wait = 4;
static const unsigned __x64_sys_eventfd = 1;
static const unsigned __x64_sys_eventfd2 = 2;
static const unsigned __x64_sys_execve = 3;
static const unsigned __x64_sys_execveat = 5;
static const unsigned __x64_sys_exit = 1;
static const unsigned __x64_sys_exit_group = 1;
static const unsigned __x64_sys_faccessat = 3;
static const unsigned __x64_sys_fadvise64 = 4;
static const unsigned __x64_sys_fallocate = 4;
static const unsigned __x64_sys_fanotify_init = 2;
static const unsigned __x64_sys_fanotify_mark = 5;
static const unsigned __x64_sys_fchdir = 1;
static const unsigned __x64_sys_fchmod = 2;
static const unsigned __x64_sys_fchmodat = 3;
static const unsigned __x64_sys_fchown = 3;
static const unsigned __x64_sys_fchownat = 5;
static const unsigned __x64_sys_fcntl = 3;
static const unsigned __x64_sys_fdatasync = 1;
static const unsigned __x64_sys_fgetxattr = 4;
static const unsigned __x64_sys_finit_module = 3;
static const unsigned __x64_sys_flistxattr = 3;
static const unsigned __x64_sys_flock = 2;
static const unsigned __x64_sys_fork = 0;
static const unsigned __x64_sys_fremovexattr = 2;
static const unsigned __x64_sys_fsetxattr = 5;
static const unsigned __x64_sys_fstatfs = 2;
static const unsigned __x64_sys_fsync = 1;
static const unsigned __x64_sys_ftruncate = 2;
static const unsigned __x64_sys_futex = 6;
static const unsigned __x64_sys_futimesat = 3;
static const unsigned __x64_sys_get_mempolicy = 5;
static const unsigned __x64_sys_get_robust_list = 3;
static const unsigned __x64_sys_getcpu = 3;
static const unsigned __x64_sys_getcwd = 2;
static const unsigned __x64_sys_getdents = 3;
static const unsigned __x64_sys_getdents64 = 3;
static const unsigned __x64_sys_getegid = 0;
static const unsigned __x64_sys_geteuid = 0;
static const unsigned __x64_sys_getgid = 0;
static const unsigned __x64_sys_getgroups = 2;
static const unsigned __x64_sys_getitimer = 2;
static const unsigned __x64_sys_getpeername = 3;
static const unsigned __x64_sys_getpgid = 1;
static const unsigned __x64_sys_getpgrp = 0;
static const unsigned __x64_sys_getpid = 0;
static const unsigned __x64_sys_getppid = 0;
static const unsigned __x64_sys_getpriority = 2;
static const unsigned __x64_sys_getrandom = 3;
static const unsigned __x64_sys_getresgid = 3;
static const unsigned __x64_sys_getresuid = 3;
static const unsigned __x64_sys_getrlimit = 2;
static const unsigned __x64_sys_getrusage = 2;
static const unsigned __x64_sys_getsid = 1;
static const unsigned __x64_sys_getsockname = 3;
static const unsigned __x64_sys_getsockopt = 5;
static const unsigned __x64_sys_gettid = 0;
static const unsigned __x64_sys_gettimeofday = 2;
static const unsigned __x64_sys_getuid = 0;
static const unsigned __x64_sys_getxattr = 4;
static const unsigned __x64_sys_init_module = 3;
static const unsigned __x64_sys_inotify_add_watch = 3;
static const unsigned __x64_sys_inotify_init = 0;
static const unsigned __x64_sys_inotify_init1 = 1;
static const unsigned __x64_sys_inotify_rm_watch = 2;
static const unsigned __x64_sys_io_cancel = 3;
static const unsigned __x64_sys_io_destroy = 1;
static const unsigned __x64_sys_io_getevents = 5;
static const unsigned __x64_sys_io_pgetevents = 6;
static const unsigned __x64_sys_io_setup = 2;
static const unsigned __x64_sys_io_submit = 3;
static const unsigned __x64_sys_ioctl = 3;
static const unsigned __x64_sys_ioperm = 3;
static const unsigned __x64_sys_iopl = 1;
static const unsigned __x64_sys_ioprio_get = 2;
static const unsigned __x64_sys_ioprio_set = 3;
static const unsigned __x64_sys_kcmp = 5;
static const unsigned __x64_sys_kexec_file_load = 5;
static const unsigned __x64_sys_kexec_load = 4;
static const unsigned __x64_sys_keyctl = 5;
static const unsigned __x64_sys_kill = 2;
static const unsigned __x64_sys_lchown = 3;
static const unsigned __x64_sys_lgetxattr = 4;
static const unsigned __x64_sys_link = 2;
static const unsigned __x64_sys_linkat = 5;
static const unsigned __x64_sys_listen = 2;
static const unsigned __x64_sys_listxattr = 3;
static const unsigned __x64_sys_llistxattr = 3;
static const unsigned __x64_sys_lookup_dcookie = 3;
static const unsigned __x64_sys_lremovexattr = 2;
static const unsigned __x64_sys_lseek = 3;
static const unsigned __x64_sys_lsetxattr = 5;
static const unsigned __x64_sys_madvise = 3;
static const unsigned __x64_sys_mbind = 6;
static const unsigned __x64_sys_membarrier = 2;
static const unsigned __x64_sys_memfd_create = 2;
static const unsigned __x64_sys_migrate_pages = 4;
static const unsigned __x64_sys_mincore = 3;
static const unsigned __x64_sys_mkdir = 2;
static const unsigned __x64_sys_mkdirat = 3;
static const unsigned __x64_sys_mknod = 3;
static const unsigned __x64_sys_mknodat = 4;
static const unsigned __x64_sys_mlock = 2;
static const unsigned __x64_sys_mlock2 = 3;
static const unsigned __x64_sys_mlockall = 1;
static const unsigned __x64_sys_mmap = 6;
static const unsigned __x64_sys_modify_ldt = 3;
static const unsigned __x64_sys_mount = 5;
static const unsigned __x64_sys_move_pages = 6;
static const unsigned __x64_sys_mprotect = 3;
static const unsigned __x64_sys_mq_getsetattr = 3;
static const unsigned __x64_sys_mq_notify = 2;
static const unsigned __x64_sys_mq_open = 4;
static const unsigned __x64_sys_mq_timedreceive = 5;
static const unsigned __x64_sys_mq_timedsend = 5;
static const unsigned __x64_sys_mq_unlink = 1;
static const unsigned __x64_sys_mremap = 5;
static const unsigned __x64_sys_msgctl = 3;
static const unsigned __x64_sys_msgget = 2;
static const unsigned __x64_sys_msgrcv = 5;
static const unsigned __x64_sys_msgsnd = 4;
static const unsigned __x64_sys_msync = 3;
static const unsigned __x64_sys_munlock = 2;
static const unsigned __x64_sys_munlockall = 0;
static const unsigned __x64_sys_munmap = 2;
static const unsigned __x64_sys_name_to_handle_at = 5;
static const unsigned __x64_sys_nanosleep = 2;
static const unsigned __x64_sys_newfstat = 2;
static const unsigned __x64_sys_newfstatat = 4;
static const unsigned __x64_sys_newlstat = 2;
static const unsigned __x64_sys_newstat = 2;
static const unsigned __x64_sys_newuname = 1;
static const unsigned __x64_sys_open = 3;
static const unsigned __x64_sys_open_by_handle_at = 3;
static const unsigned __x64_sys_openat = 4;
static const unsigned __x64_sys_pause = 0;
static const unsigned __x64_sys_perf_event_open = 5;
static const unsigned __x64_sys_personality = 1;
static const unsigned __x64_sys_pipe = 1;
static const unsigned __x64_sys_pipe2 = 2;
static const unsigned __x64_sys_pivot_root = 2;
static const unsigned __x64_sys_pkey_alloc = 2;
static const unsigned __x64_sys_pkey_free = 1;
static const unsigned __x64_sys_pkey_mprotect = 4;
static const unsigned __x64_sys_poll = 3;
static const unsigned __x64_sys_ppoll = 5;
static const unsigned __x64_sys_prctl = 5;
static const unsigned __x64_sys_pread64 = 4;
static const unsigned __x64_sys_preadv = 5;
static const unsigned __x64_sys_preadv2 = 6;
static const unsigned __x64_sys_prlimit64 = 4;
static const unsigned __x64_sys_process_vm_readv = 6;
static const unsigned __x64_sys_process_vm_writev = 6;
static const unsigned __x64_sys_pselect6 = 6;
static const unsigned __x64_sys_ptrace = 4;
static const unsigned __x64_sys_pwrite64 = 4;
static const unsigned __x64_sys_pwritev = 5;
static const unsigned __x64_sys_pwritev2 = 6;
static const unsigned __x64_sys_quotactl = 4;
static const unsigned __x64_sys_read = 3;
static const unsigned __x64_sys_readahead = 3;
static const unsigned __x64_sys_readlink = 3;
static const unsigned __x64_sys_readlinkat = 4;
static const unsigned __x64_sys_readv = 3;
static const unsigned __x64_sys_reboot = 4;
static const unsigned __x64_sys_recvfrom = 6;
static const unsigned __x64_sys_recvmmsg = 5;
static const unsigned __x64_sys_recvmsg = 3;
static const unsigned __x64_sys_remap_file_pages = 5;
static const unsigned __x64_sys_removexattr = 2;
static const unsigned __x64_sys_rename = 2;
static const unsigned __x64_sys_renameat = 4;
static const unsigned __x64_sys_renameat2 = 5;
static const unsigned __x64_sys_request_key = 4;
static const unsigned __x64_sys_restart_syscall = 0;
static const unsigned __x64_sys_rmdir = 1;
static const unsigned __x64_sys_rseq = 4;
static const unsigned __x64_sys_rt_sigaction = 4;
static const unsigned __x64_sys_rt_sigpending = 2;
static const unsigned __x64_sys_rt_sigprocmask = 4;
static const unsigned __x64_sys_rt_sigqueueinfo = 3;
static const unsigned __x64_sys_rt_sigreturn = 0;
static const unsigned __x64_sys_rt_sigsuspend = 2;
static const unsigned __x64_sys_rt_sigtimedwait = 4;
static const unsigned __x64_sys_rt_tgsigqueueinfo = 4;
static const unsigned __x64_sys_sched_get_priority_max = 1;
static const unsigned __x64_sys_sched_get_priority_min = 1;
static const unsigned __x64_sys_sched_getaffinity = 3;
static const unsigned __x64_sys_sched_getattr = 4;
static const unsigned __x64_sys_sched_getparam = 2;
static const unsigned __x64_sys_sched_getscheduler = 1;
static const unsigned __x64_sys_sched_rr_get_interval = 2;
static const unsigned __x64_sys_sched_setaffinity = 3;
static const unsigned __x64_sys_sched_setattr = 3;
static const unsigned __x64_sys_sched_setparam = 2;
static const unsigned __x64_sys_sched_setscheduler = 3;
static const unsigned __x64_sys_sched_yield = 0;
static const unsigned __x64_sys_seccomp = 3;
static const unsigned __x64_sys_select = 5;
static const unsigned __x64_sys_semctl = 4;
static const unsigned __x64_sys_semget = 3;
static const unsigned __x64_sys_semop = 3;
static const unsigned __x64_sys_semtimedop = 4;
static const unsigned __x64_sys_sendfile64 = 4;
static const unsigned __x64_sys_sendmmsg = 4;
static const unsigned __x64_sys_sendmsg = 3;
static const unsigned __x64_sys_sendto = 6;
static const unsigned __x64_sys_set_mempolicy = 3;
static const unsigned __x64_sys_set_robust_list = 2;
static const unsigned __x64_sys_set_tid_address = 1;
static const unsigned __x64_sys_setdomainname = 2;
static const unsigned __x64_sys_setfsgid = 1;
static const unsigned __x64_sys_setfsuid = 1;
static const unsigned __x64_sys_setgid = 1;
static const unsigned __x64_sys_setgroups = 2;
static const unsigned __x64_sys_sethostname = 2;
static const unsigned __x64_sys_setitimer = 3;
static const unsigned __x64_sys_setns = 2;
static const unsigned __x64_sys_setpgid = 2;
static const unsigned __x64_sys_setpriority = 3;
static const unsigned __x64_sys_setregid = 2;
static const unsigned __x64_sys_setresgid = 3;
static const unsigned __x64_sys_setresuid = 3;
static const unsigned __x64_sys_setreuid = 2;
static const unsigned __x64_sys_setrlimit = 2;
static const unsigned __x64_sys_setsid = 0;
static const unsigned __x64_sys_setsockopt = 5;
static const unsigned __x64_sys_settimeofday = 2;
static const unsigned __x64_sys_setuid = 1;
static const unsigned __x64_sys_setxattr = 5;
static const unsigned __x64_sys_shmat = 3;
static const unsigned __x64_sys_shmctl = 3;
static const unsigned __x64_sys_shmdt = 1;
static const unsigned __x64_sys_shmget = 3;
static const unsigned __x64_sys_shutdown = 2;
static const unsigned __x64_sys_sigaltstack = 2;
static const unsigned __x64_sys_signalfd = 3;
static const unsigned __x64_sys_signalfd4 = 4;
static const unsigned __x64_sys_socket = 3;
static const unsigned __x64_sys_socketpair = 4;
static const unsigned __x64_sys_splice = 6;
static const unsigned __x64_sys_statfs = 2;
static const unsigned __x64_sys_statx = 5;
static const unsigned __x64_sys_swapoff = 1;
static const unsigned __x64_sys_swapon = 2;
static const unsigned __x64_sys_symlink = 2;
static const unsigned __x64_sys_symlinkat = 3;
static const unsigned __x64_sys_sync = 0;
static const unsigned __x64_sys_sync_file_range = 4;
static const unsigned __x64_sys_syncfs = 1;
static const unsigned __x64_sys_sysctl = 1;
static const unsigned __x64_sys_sysfs = 3;
static const unsigned __x64_sys_sysinfo = 1;
static const unsigned __x64_sys_syslog = 3;
static const unsigned __x64_sys_tee = 4;
static const unsigned __x64_sys_tgkill = 3;
static const unsigned __x64_sys_time = 1;
static const unsigned __x64_sys_timer_create = 3;
static const unsigned __x64_sys_timer_delete = 1;
static const unsigned __x64_sys_timer_getoverrun = 1;
static const unsigned __x64_sys_timer_gettime = 2;
static const unsigned __x64_sys_timer_settime = 4;
static const unsigned __x64_sys_timerfd_create = 2;
static const unsigned __x64_sys_timerfd_gettime = 2;
static const unsigned __x64_sys_timerfd_settime = 4;
static const unsigned __x64_sys_times = 1;
static const unsigned __x64_sys_tkill = 2;
static const unsigned __x64_sys_truncate = 2;
static const unsigned __x64_sys_umask = 1;
static const unsigned __x64_sys_umount = 2;
static const unsigned __x64_sys_unlink = 1;
static const unsigned __x64_sys_unlinkat = 3;
static const unsigned __x64_sys_unshare = 1;
static const unsigned __x64_sys_userfaultfd = 1;
static const unsigned __x64_sys_ustat = 2;
static const unsigned __x64_sys_utime = 2;
static const unsigned __x64_sys_utimensat = 4;
static const unsigned __x64_sys_utimes = 2;
static const unsigned __x64_sys_vfork = 0;
static const unsigned __x64_sys_vhangup = 0;
static const unsigned __x64_sys_vmsplice = 4;
static const unsigned __x64_sys_wait4 = 4;
static const unsigned __x64_sys_waitid = 5;
static const unsigned __x64_sys_write = 3;
static const unsigned __x64_sys_writev = 3;

static const unsigned sys_call_arg_cnt_table[334 + 1] = {
    [0 ... 334] = sys_ni_syscall,

    [0] = __x64_sys_read,
    [1] = __x64_sys_write,
    [2] = __x64_sys_open,
    [3] = __x64_sys_close,
    [4] = __x64_sys_newstat,
    [5] = __x64_sys_newfstat,
    [6] = __x64_sys_newlstat,
    [7] = __x64_sys_poll,
    [8] = __x64_sys_lseek,
    [9] = __x64_sys_mmap,
    [10] = __x64_sys_mprotect,
    [11] = __x64_sys_munmap,
    [12] = __x64_sys_brk,
    [13] = __x64_sys_rt_sigaction,
    [14] = __x64_sys_rt_sigprocmask,
    [15] = __x64_sys_rt_sigreturn,
    [16] = __x64_sys_ioctl,
    [17] = __x64_sys_pread64,
    [18] = __x64_sys_pwrite64,
    [19] = __x64_sys_readv,
    [20] = __x64_sys_writev,
    [21] = __x64_sys_access,
    [22] = __x64_sys_pipe,
    [23] = __x64_sys_select,
    [24] = __x64_sys_sched_yield,
    [25] = __x64_sys_mremap,
    [26] = __x64_sys_msync,
    [27] = __x64_sys_mincore,
    [28] = __x64_sys_madvise,
    [29] = __x64_sys_shmget,
    [30] = __x64_sys_shmat,
    [31] = __x64_sys_shmctl,
    [32] = __x64_sys_dup,
    [33] = __x64_sys_dup2,
    [34] = __x64_sys_pause,
    [35] = __x64_sys_nanosleep,
    [36] = __x64_sys_getitimer,
    [37] = __x64_sys_alarm,
    [38] = __x64_sys_setitimer,
    [39] = __x64_sys_getpid,
    [40] = __x64_sys_sendfile64,
    [41] = __x64_sys_socket,
    [42] = __x64_sys_connect,
    [43] = __x64_sys_accept,
    [44] = __x64_sys_sendto,
    [45] = __x64_sys_recvfrom,
    [46] = __x64_sys_sendmsg,
    [47] = __x64_sys_recvmsg,
    [48] = __x64_sys_shutdown,
    [49] = __x64_sys_bind,
    [50] = __x64_sys_listen,
    [51] = __x64_sys_getsockname,
    [52] = __x64_sys_getpeername,
    [53] = __x64_sys_socketpair,
    [54] = __x64_sys_setsockopt,
    [55] = __x64_sys_getsockopt,
    [56] = __x64_sys_clone,
    [57] = __x64_sys_fork,
    [58] = __x64_sys_vfork,
    [59] = __x64_sys_execve,
    [60] = __x64_sys_exit,
    [61] = __x64_sys_wait4,
    [62] = __x64_sys_kill,
    [63] = __x64_sys_newuname,
    [64] = __x64_sys_semget,
    [65] = __x64_sys_semop,
    [66] = __x64_sys_semctl,
    [67] = __x64_sys_shmdt,
    [68] = __x64_sys_msgget,
    [69] = __x64_sys_msgsnd,
    [70] = __x64_sys_msgrcv,
    [71] = __x64_sys_msgctl,
    [72] = __x64_sys_fcntl,
    [73] = __x64_sys_flock,
    [74] = __x64_sys_fsync,
    [75] = __x64_sys_fdatasync,
    [76] = __x64_sys_truncate,
    [77] = __x64_sys_ftruncate,
    [78] = __x64_sys_getdents,
    [79] = __x64_sys_getcwd,
    [80] = __x64_sys_chdir,
    [81] = __x64_sys_fchdir,
    [82] = __x64_sys_rename,
    [83] = __x64_sys_mkdir,
    [84] = __x64_sys_rmdir,
    [85] = __x64_sys_creat,
    [86] = __x64_sys_link,
    [87] = __x64_sys_unlink,
    [88] = __x64_sys_symlink,
    [89] = __x64_sys_readlink,
    [90] = __x64_sys_chmod,
    [91] = __x64_sys_fchmod,
    [92] = __x64_sys_chown,
    [93] = __x64_sys_fchown,
    [94] = __x64_sys_lchown,
    [95] = __x64_sys_umask,
    [96] = __x64_sys_gettimeofday,
    [97] = __x64_sys_getrlimit,
    [98] = __x64_sys_getrusage,
    [99] = __x64_sys_sysinfo,
    [100] = __x64_sys_times,
    [101] = __x64_sys_ptrace,
    [102] = __x64_sys_getuid,
    [103] = __x64_sys_syslog,
    [104] = __x64_sys_getgid,
    [105] = __x64_sys_setuid,
    [106] = __x64_sys_setgid,
    [107] = __x64_sys_geteuid,
    [108] = __x64_sys_getegid,
    [109] = __x64_sys_setpgid,
    [110] = __x64_sys_getppid,
    [111] = __x64_sys_getpgrp,
    [112] = __x64_sys_setsid,
    [113] = __x64_sys_setreuid,
    [114] = __x64_sys_setregid,
    [115] = __x64_sys_getgroups,
    [116] = __x64_sys_setgroups,
    [117] = __x64_sys_setresuid,
    [118] = __x64_sys_getresuid,
    [119] = __x64_sys_setresgid,
    [120] = __x64_sys_getresgid,
    [121] = __x64_sys_getpgid,
    [122] = __x64_sys_setfsuid,
    [123] = __x64_sys_setfsgid,
    [124] = __x64_sys_getsid,
    [125] = __x64_sys_capget,
    [126] = __x64_sys_capset,
    [127] = __x64_sys_rt_sigpending,
    [128] = __x64_sys_rt_sigtimedwait,
    [129] = __x64_sys_rt_sigqueueinfo,
    [130] = __x64_sys_rt_sigsuspend,
    [131] = __x64_sys_sigaltstack,
    [132] = __x64_sys_utime,
    [133] = __x64_sys_mknod,
    [135] = __x64_sys_personality,
    [136] = __x64_sys_ustat,
    [137] = __x64_sys_statfs,
    [138] = __x64_sys_fstatfs,
    [139] = __x64_sys_sysfs,
    [140] = __x64_sys_getpriority,
    [141] = __x64_sys_setpriority,
    [142] = __x64_sys_sched_setparam,
    [143] = __x64_sys_sched_getparam,
    [144] = __x64_sys_sched_setscheduler,
    [145] = __x64_sys_sched_getscheduler,
    [146] = __x64_sys_sched_get_priority_max,
    [147] = __x64_sys_sched_get_priority_min,
    [148] = __x64_sys_sched_rr_get_interval,
    [149] = __x64_sys_mlock,
    [150] = __x64_sys_munlock,
    [151] = __x64_sys_mlockall,
    [152] = __x64_sys_munlockall,
    [153] = __x64_sys_vhangup,
    [154] = __x64_sys_modify_ldt,
    [155] = __x64_sys_pivot_root,
    [156] = __x64_sys_sysctl,
    [157] = __x64_sys_prctl,
    [158] = __x64_sys_arch_prctl,
    [159] = __x64_sys_adjtimex,
    [160] = __x64_sys_setrlimit,
    [161] = __x64_sys_chroot,
    [162] = __x64_sys_sync,
    [163] = __x64_sys_acct,
    [164] = __x64_sys_settimeofday,
    [165] = __x64_sys_mount,
    [166] = __x64_sys_umount,
    [167] = __x64_sys_swapon,
    [168] = __x64_sys_swapoff,
    [169] = __x64_sys_reboot,
    [170] = __x64_sys_sethostname,
    [171] = __x64_sys_setdomainname,
    [172] = __x64_sys_iopl,
    [173] = __x64_sys_ioperm,
    [175] = __x64_sys_init_module,
    [176] = __x64_sys_delete_module,
    [179] = __x64_sys_quotactl,
    [186] = __x64_sys_gettid,
    [187] = __x64_sys_readahead,
    [188] = __x64_sys_setxattr,
    [189] = __x64_sys_lsetxattr,
    [190] = __x64_sys_fsetxattr,
    [191] = __x64_sys_getxattr,
    [192] = __x64_sys_lgetxattr,
    [193] = __x64_sys_fgetxattr,
    [194] = __x64_sys_listxattr,
    [195] = __x64_sys_llistxattr,
    [196] = __x64_sys_flistxattr,
    [197] = __x64_sys_removexattr,
    [198] = __x64_sys_lremovexattr,
    [199] = __x64_sys_fremovexattr,
    [200] = __x64_sys_tkill,
    [201] = __x64_sys_time,
    [202] = __x64_sys_futex,
    [203] = __x64_sys_sched_setaffinity,
    [204] = __x64_sys_sched_getaffinity,
    [206] = __x64_sys_io_setup,
    [207] = __x64_sys_io_destroy,
    [208] = __x64_sys_io_getevents,
    [209] = __x64_sys_io_submit,
    [210] = __x64_sys_io_cancel,
    [212] = __x64_sys_lookup_dcookie,
    [213] = __x64_sys_epoll_create,
    [216] = __x64_sys_remap_file_pages,
    [217] = __x64_sys_getdents64,
    [218] = __x64_sys_set_tid_address,
    [219] = __x64_sys_restart_syscall,
    [220] = __x64_sys_semtimedop,
    [221] = __x64_sys_fadvise64,
    [222] = __x64_sys_timer_create,
    [223] = __x64_sys_timer_settime,
    [224] = __x64_sys_timer_gettime,
    [225] = __x64_sys_timer_getoverrun,
    [226] = __x64_sys_timer_delete,
    [227] = __x64_sys_clock_settime,
    [228] = __x64_sys_clock_gettime,
    [229] = __x64_sys_clock_getres,
    [230] = __x64_sys_clock_nanosleep,
    [231] = __x64_sys_exit_group,
    [232] = __x64_sys_epoll_wait,
    [233] = __x64_sys_epoll_ctl,
    [234] = __x64_sys_tgkill,
    [235] = __x64_sys_utimes,
    [237] = __x64_sys_mbind,
    [238] = __x64_sys_set_mempolicy,
    [239] = __x64_sys_get_mempolicy,
    [240] = __x64_sys_mq_open,
    [241] = __x64_sys_mq_unlink,
    [242] = __x64_sys_mq_timedsend,
    [243] = __x64_sys_mq_timedreceive,
    [244] = __x64_sys_mq_notify,
    [245] = __x64_sys_mq_getsetattr,
    [246] = __x64_sys_kexec_load,
    [247] = __x64_sys_waitid,
    [248] = __x64_sys_add_key,
    [249] = __x64_sys_request_key,
    [250] = __x64_sys_keyctl,
    [251] = __x64_sys_ioprio_set,
    [252] = __x64_sys_ioprio_get,
    [253] = __x64_sys_inotify_init,
    [254] = __x64_sys_inotify_add_watch,
    [255] = __x64_sys_inotify_rm_watch,
    [256] = __x64_sys_migrate_pages,
    [257] = __x64_sys_openat,
    [258] = __x64_sys_mkdirat,
    [259] = __x64_sys_mknodat,
    [260] = __x64_sys_fchownat,
    [261] = __x64_sys_futimesat,
    [262] = __x64_sys_newfstatat,
    [263] = __x64_sys_unlinkat,
    [264] = __x64_sys_renameat,
    [265] = __x64_sys_linkat,
    [266] = __x64_sys_symlinkat,
    [267] = __x64_sys_readlinkat,
    [268] = __x64_sys_fchmodat,
    [269] = __x64_sys_faccessat,
    [270] = __x64_sys_pselect6,
    [271] = __x64_sys_ppoll,
    [272] = __x64_sys_unshare,
    [273] = __x64_sys_set_robust_list,
    [274] = __x64_sys_get_robust_list,
    [275] = __x64_sys_splice,
    [276] = __x64_sys_tee,
    [277] = __x64_sys_sync_file_range,
    [278] = __x64_sys_vmsplice,
    [279] = __x64_sys_move_pages,
    [280] = __x64_sys_utimensat,
    [281] = __x64_sys_epoll_pwait,
    [282] = __x64_sys_signalfd,
    [283] = __x64_sys_timerfd_create,
    [284] = __x64_sys_eventfd,
    [285] = __x64_sys_fallocate,
    [286] = __x64_sys_timerfd_settime,
    [287] = __x64_sys_timerfd_gettime,
    [288] = __x64_sys_accept4,
    [289] = __x64_sys_signalfd4,
    [290] = __x64_sys_eventfd2,
    [291] = __x64_sys_epoll_create1,
    [292] = __x64_sys_dup3,
    [293] = __x64_sys_pipe2,
    [294] = __x64_sys_inotify_init1,
    [295] = __x64_sys_preadv,
    [296] = __x64_sys_pwritev,
    [297] = __x64_sys_rt_tgsigqueueinfo,
    [298] = __x64_sys_perf_event_open,
    [299] = __x64_sys_recvmmsg,
    [300] = __x64_sys_fanotify_init,
    [301] = __x64_sys_fanotify_mark,
    [302] = __x64_sys_prlimit64,
    [303] = __x64_sys_name_to_handle_at,
    [304] = __x64_sys_open_by_handle_at,
    [305] = __x64_sys_clock_adjtime,
    [306] = __x64_sys_syncfs,
    [307] = __x64_sys_sendmmsg,
    [308] = __x64_sys_setns,
    [309] = __x64_sys_getcpu,
    [310] = __x64_sys_process_vm_readv,
    [311] = __x64_sys_process_vm_writev,
    [312] = __x64_sys_kcmp,
    [313] = __x64_sys_finit_module,
    [314] = __x64_sys_sched_setattr,
    [315] = __x64_sys_sched_getattr,
    [316] = __x64_sys_renameat2,
    [317] = __x64_sys_seccomp,
    [318] = __x64_sys_getrandom,
    [319] = __x64_sys_memfd_create,
    [320] = __x64_sys_kexec_file_load,
    [321] = __x64_sys_bpf,
    [322] = __x64_sys_execveat,
    [323] = __x64_sys_userfaultfd,
    [324] = __x64_sys_membarrier,
    [325] = __x64_sys_mlock2,
    [326] = __x64_sys_copy_file_range,
    [327] = __x64_sys_preadv2,
    [328] = __x64_sys_pwritev2,
    [329] = __x64_sys_pkey_mprotect,
    [330] = __x64_sys_pkey_alloc,
    [331] = __x64_sys_pkey_free,
    [332] = __x64_sys_statx,
    [333] = __x64_sys_io_pgetevents,
    [334] = __x64_sys_rseq,
};

#endif

}
