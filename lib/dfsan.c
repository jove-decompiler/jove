#include <stdint.h>
#include <stdbool.h>
#include <sys/mman.h>

#define _CTOR   __attribute__((constructor))
#define _INL    __attribute__((always_inline))
#define _NAKED  __attribute__((naked))
#define _NOINL  __attribute__((noinline))
#define _NORET  __attribute__((noreturn))
#define _UNUSED __attribute__((unused))

#define JOVE_SYS_ATTR _INL _UNUSED
#include "jove_sys.h"

static int internal_strcmp(const char *s1, const char *s2);

typedef uint16_t dfsan_label_t;

typedef unsigned long uptr;

struct dfsan_label_info_t {
  dfsan_label_t l1;
  dfsan_label_t l2;
  const char *desc;
  void *userdata;
};

static const dfsan_label_t kInitializingLabel = -1;

static const uptr kNumLabels = 1 << (sizeof(dfsan_label_t) * 8);

static dfsan_label_t  __dfsan_last_label;
static struct dfsan_label_info_t __dfsan_label_info[kNumLabels];

__thread dfsan_label_t __dfsan_retval_tls;
__thread dfsan_label_t __dfsan_arg_tls[64];

uptr __dfsan_shadow_ptr_mask;

typedef dfsan_label_t dfsan_union_table_t[kNumLabels][kNumLabels];

#if defined(__x86_64__)
static const uptr kShadowAddr = 0x10000;
static const uptr kUnionTableAddr = 0x200000000000;
static const uptr kAppAddr = 0x700000008000;
static const uptr kShadowMask = ~0x700000000000;
static const uptr kPageSize = 4096;
#else
#error
#endif

static uptr ShadowAddr()     { return kShadowAddr; }
static uptr UnionTableAddr() { return kUnionTableAddr; }
static uptr AppAddr()        { return kAppAddr; }
static uptr ShadowMask()     { return kShadowMask; }

static uptr UnusedAddr() {
  return kUnionTableAddr + sizeof(dfsan_union_table_t);
}

static dfsan_label_t *shadow_for(void *ptr) {
  return (dfsan_label_t *)((((uptr)ptr) & ShadowMask()) << 1);
}

static dfsan_label_t *union_table(dfsan_label_t l1, dfsan_label_t l2) {
  return &(*(dfsan_union_table_t *)UnionTableAddr())[l1][l2];
}

// Checks we do not run out of labels.
static void dfsan_check_label(dfsan_label_t label) {
  if (label == kInitializingLabel) {
    //
    // FATAL: DataFlowSanitizer: out of labels
    //
    __builtin_trap();
    __builtin_unreachable();
  }
}

#define swap(a, b) \
        do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

// Resolves the union of two unequal labels.  Nonequality is a precondition for
// this function (the instrumentation pass inlines the equality test).
dfsan_label_t __dfsan_union(dfsan_label_t l1, dfsan_label_t l2) {
#if 0
  if (flags().fast16labels)
    return l1 | l2;
  DCHECK_NE(l1, l2);
#endif

  if (l1 == 0)
    return l2;
  if (l2 == 0)
    return l1;

  if (l1 > l2)
    swap(l1, l2);

  dfsan_label_t *table_ent = union_table(l1, l2);
  // We need to deal with the case where two threads concurrently request
  // a union of the same pair of labels.  If the table entry is uninitialized,
  // (i.e. 0) use a compare-exchange to set the entry to kInitializingLabel
  // (i.e. -1) to mark that we are initializing it.
  dfsan_label_t label = 0;
  if (__atomic_compare_exchange_n(table_ent, &label, kInitializingLabel,
                                  false /* strong */, __ATOMIC_ACQUIRE,
                                  __ATOMIC_RELAXED)) {
    // Check whether l2 subsumes l1.  We don't need to check whether l1
    // subsumes l2 because we are guaranteed here that l1 < l2, and (at least
    // in the cases we are interested in) a label may only subsume labels
    // created earlier (i.e. with a lower numerical value).
    if (__dfsan_label_info[l2].l1 == l1 ||
        __dfsan_label_info[l2].l2 == l1) {
      label = l2;
    } else {
      label = __atomic_fetch_add(&__dfsan_last_label, 1, __ATOMIC_RELAXED) + 1;

      dfsan_check_label(label);
      __dfsan_label_info[label].l1 = l1;
      __dfsan_label_info[label].l2 = l2;
    }
    __atomic_store_n(table_ent, label, __ATOMIC_RELEASE);
  } else if (label == kInitializingLabel) {
    // Another thread is initializing the entry.  Wait until it is finished.
    do {
      _jove_sys_sched_yield();
      label = __atomic_load_n(table_ent, __ATOMIC_ACQUIRE);
    } while (label == kInitializingLabel);
  }
  return label;
}

dfsan_label_t __dfsan_union_load(const dfsan_label_t *ls, uptr n) {
  dfsan_label_t label = ls[0];
  for (uptr i = 1; i != n; ++i) {
    dfsan_label_t next_label = ls[i];
    if (label != next_label)
      label = __dfsan_union(label, next_label);
  }
  return label;
}

void __dfsan_unimplemented(char *fname) {
  //
  // WARNING: DataFlowSanitizer: call to uninstrumented function
  //
  __builtin_trap();
  __builtin_unreachable();
}

// Use '-mllvm -dfsan-debug-nonzero-labels' and break on this function
// to try to figure out where labels are being introduced in a nominally
// label-free program.
void __dfsan_nonzero_label() {
  //
  // WARNING: DataFlowSanitizer: saw nonzero label
  //
}

// Indirect call to an uninstrumented vararg function. We don't have a way of
// handling these at the moment.
void __dfsan_vararg_wrapper(const char *fname) {
  //
  // FATAL: DataFlowSanitizer: unsupported indirect call to vararg function
  //
  __builtin_trap();
  __builtin_unreachable();
}

// Like __dfsan_union, but for use from the client or custom functions.  Hence
// the equality comparison is done here before calling __dfsan_union.
dfsan_label_t dfsan_union(dfsan_label_t l1, dfsan_label_t l2) {
  if (l1 == l2)
    return l1;
  return __dfsan_union(l1, l2);
}

dfsan_label_t dfsan_create_label(const char *desc, void *userdata) {
  dfsan_label_t label =
      __atomic_fetch_add(&__dfsan_last_label, 1, __ATOMIC_RELAXED) + 1;
  dfsan_check_label(label);
  __dfsan_label_info[label].l1 = __dfsan_label_info[label].l2 = 0;
  __dfsan_label_info[label].desc = desc;
  __dfsan_label_info[label].userdata = userdata;
  return label;
}

void __dfsan_set_label(dfsan_label_t label, void *addr, uptr size) {
  for (dfsan_label_t *labelp = shadow_for(addr); size != 0; --size, ++labelp) {
    // Don't write the label if it is already the value we need it to be.
    // In a program where most addresses are not labeled, it is common that
    // a page of shadow memory is entirely zeroed.  The Linux copy-on-write
    // implementation will share all of the zeroed pages, making a copy of a
    // page when any value is written.  The un-sharing will happen even if
    // the value written does not change the value in memory.  Avoiding the
    // write when both |label| and |*labelp| are zero dramatically reduces
    // the amount of real memory used by large programs.
    if (label == *labelp)
      continue;

    *labelp = label;
  }
}

void dfsan_set_label(dfsan_label_t label, void *addr, uptr size) {
  __dfsan_set_label(label, addr, size);
}

void dfsan_add_label(dfsan_label_t label, void *addr, uptr size) {
  for (dfsan_label_t *labelp = shadow_for(addr); size != 0; --size, ++labelp)
    if (*labelp != label)
      *labelp = __dfsan_union(*labelp, label);
}

// Unlike the other dfsan interface functions the behavior of this function
// depends on the label of one of its arguments.  Hence it is implemented as a
// custom function.
dfsan_label_t __dfsw_dfsan_get_label(long data, dfsan_label_t data_label,
                                     dfsan_label_t *ret_label) {
  *ret_label = 0;
  return data_label;
}

dfsan_label_t dfsan_read_label(const void *addr, uptr size) {
  if (size == 0)
    return 0;
  return __dfsan_union_load(shadow_for((void *)addr), size);
}

const struct dfsan_label_info_t *dfsan_get_label_info(dfsan_label_t label) {
  return &__dfsan_label_info[label];
}

int dfsan_has_label(dfsan_label_t label, dfsan_label_t elem) {
  if (label == elem)
    return true;
  const struct dfsan_label_info_t *info = dfsan_get_label_info(label);
  if (info->l1 != 0) {
    return dfsan_has_label(info->l1, elem) || dfsan_has_label(info->l2, elem);
  } else {
    return false;
  }
}

dfsan_label_t dfsan_has_label_with_desc(dfsan_label_t label, const char *desc) {
  const struct dfsan_label_info_t *info = dfsan_get_label_info(label);
  if (info->l1 != 0) {
    return dfsan_has_label_with_desc(info->l1, desc) ||
           dfsan_has_label_with_desc(info->l2, desc);
  } else {
    return internal_strcmp(desc, info->desc) == 0;
  }
}

uptr dfsan_get_label_count(void) {
  dfsan_label_t max_label_allocated =
      __atomic_load_n(&__dfsan_last_label, __ATOMIC_RELAXED);

  return (uptr)max_label_allocated;
}

void dfsan_dump_labels(int fd) {
#if 0
  dfsan_label_t last_label =
      atomic_load(&__dfsan_last_label, memory_order_relaxed);

  for (uptr l = 1; l <= last_label; ++l) {
    char buf[64];
    internal_snprintf(buf, sizeof(buf), "%u %u %u ", l,
                      __dfsan_label_info[l].l1, __dfsan_label_info[l].l2);
    WriteToFile(fd, buf, internal_strlen(buf));
    if (__dfsan_label_info[l].l1 == 0 && __dfsan_label_info[l].desc) {
      WriteToFile(fd, __dfsan_label_info[l].desc,
                  internal_strlen(__dfsan_label_info[l].desc));
    }
    WriteToFile(fd, "\n", 1);
  }
#endif
}

static void dfsan_fini() {
#if 0
  if (internal_strcmp(flags().dump_labels_at_exit, "") != 0) {
    fd_t fd = OpenFile(flags().dump_labels_at_exit, WrOnly);
    if (fd == kInvalidFd) {
      Report("WARNING: DataFlowSanitizer: unable to open output file %s\n",
             flags().dump_labels_at_exit);
      return;
    }

    Report("INFO: DataFlowSanitizer: dumping labels to %s\n",
           flags().dump_labels_at_exit);
    dfsan_dump_labels(fd);
    CloseFile(fd);
  }
#endif
}

static bool MmapFixedNoReserve(uptr fixed_addr, uptr size, const char *name);
static void UnmapOrDie(void *addr, uptr size);

void dfsan_flush() {
  UnmapOrDie((void*)ShadowAddr(), UnusedAddr() - ShadowAddr());
  if (!MmapFixedNoReserve(ShadowAddr(), UnusedAddr() - ShadowAddr(), NULL)) {
    __builtin_trap();
    __builtin_unreachable();
  }
}

static void *MmapFixedNoAccess(uptr fixed_addr, uptr size, const char *name);

static void dfsan_init(int argc, char **argv, char **envp) {
  if (!MmapFixedNoReserve(ShadowAddr(), UnusedAddr() - ShadowAddr(), NULL)) {
    __builtin_trap();
    __builtin_unreachable();
  }

  // Protect the region of memory we don't use, to preserve the one-to-one
  // mapping from application to shadow memory. But if ASLR is disabled, Linux
  // will load our executable in the middle of our unused region. This mostly
  // works so long as the program doesn't use too much memory. We support this
  // case by disabling memory protection when ASLR is disabled.
  uptr init_addr = (uptr)&dfsan_init;
  if (!(init_addr >= UnusedAddr() && init_addr < AppAddr()))
    MmapFixedNoAccess(UnusedAddr(), AppAddr() - UnusedAddr(), NULL);

#if 0
  InitializeInterceptors();

  // Register the fini callback to run when the program terminates successfully
  // or it is killed by the runtime.
  Atexit(dfsan_fini);
  AddDieCallback(dfsan_fini);
#endif

  __dfsan_label_info[kInitializingLabel].desc = "<init label>";
}

#if 1 /* SANITIZER_CAN_USE_PREINIT_ARRAY */
__attribute__((section(".preinit_array"), used))
static void (*dfsan_init_ptr)(int, char **, char **) = dfsan_init;
#endif

static uptr RoundUpTo(uptr Size, uptr Boundary) {
  return (Size + Boundary - 1) & ~(Boundary - 1);
}

static uptr RoundDownTo(uptr x, uptr boundary) {
  return x & ~(boundary - 1);
}

static uptr GetPageSizeCached() {
  return kPageSize;
}

static uptr MmapNamed(void *addr, uptr length, int prot, int flags,
                      const char *name);

static void IncreaseTotalMmap(uptr size);

bool MmapFixedNoReserve(uptr fixed_addr, uptr size, const char *name) {
  size = RoundUpTo(size, GetPageSizeCached());
  fixed_addr = RoundDownTo(fixed_addr, GetPageSizeCached());
  uptr p = MmapNamed((void *)fixed_addr, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_FIXED | MAP_NORESERVE | MAP_ANON, name);
  if (p == 0x0) {
    //
    // ERROR: failed to allocate 0x%zx (%zd) bytes at address %zx (errno: %d)
    //
    __builtin_trap();
    return false;
  }

  IncreaseTotalMmap(size);
  return true;
}

void *MmapFixedNoAccess(uptr fixed_addr, uptr size, const char *name) {
  return (void *)MmapNamed((void *)fixed_addr, size, PROT_NONE,
                           MAP_PRIVATE | MAP_FIXED | MAP_NORESERVE | MAP_ANON,
                           name);
}

static int GetNamedMappingFd(const char *name, uptr size, int *flags);
static void DecorateMapping(uptr addr, uptr size, const char *name);

uptr MmapNamed(void *addr, uptr length, int prot, int flags, const char *name) {
  int fd = GetNamedMappingFd(name, length, &flags);
  long ret = _jove_sys_mmap((uptr)addr, length, prot, flags, fd, 0);
  if (ret < 0) {
    return 0; /* i.e. NULL */
  } else {
    uptr res = (uptr)ret;
    DecorateMapping(res, length, name);
    return res;
  }
}

static void DecreaseTotalMmap(uptr size);

void UnmapOrDie(void *addr, uptr size) {
  long ret = _jove_sys_munmap((uptr)addr, size);
  if (ret < 0) {
    __builtin_trap();
    __builtin_unreachable();
  }

  DecreaseTotalMmap(size);
}

int internal_strcmp(const char *s1, const char *s2) {
  while (true) {
    unsigned c1 = *s1;
    unsigned c2 = *s2;
    if (c1 != c2) return (c1 < c2) ? -1 : 1;
    if (c1 == 0) break;
    s1++;
    s2++;
  }
  return 0;
}

static unsigned long g_total_mmaped;

void IncreaseTotalMmap(uptr size) {
#if 0
  if (!common_flags()->mmap_limit_mb) return;
  uptr total_mmaped =
      atomic_fetch_add(&g_total_mmaped, size, memory_order_relaxed) + size;
  // Since for now mmap_limit_mb is not a user-facing flag, just kill
  // a program. Use RAW_CHECK to avoid extra mmaps in reporting.
  RAW_CHECK((total_mmaped >> 20) < common_flags()->mmap_limit_mb);
#endif
}

void DecreaseTotalMmap(uptr size) {
#if 0
  if (!common_flags()->mmap_limit_mb) return;
  atomic_fetch_sub(&g_total_mmaped, size, memory_order_relaxed);
#endif
}

int GetNamedMappingFd(const char *name, uptr size, int *flags) {
#if 0
  if (!common_flags()->decorate_proc_maps || !name)
    return -1;
  char shmname[200];
  CHECK(internal_strlen(name) < sizeof(shmname) - 10);
  internal_snprintf(shmname, sizeof(shmname), "/dev/shm/%zu [%s]",
                    internal_getpid(), name);
  int fd = ReserveStandardFds(
      internal_open(shmname, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, S_IRWXU));
  CHECK_GE(fd, 0);
  int res = internal_ftruncate(fd, size);
  CHECK_EQ(0, res);
  res = internal_unlink(shmname);
  CHECK_EQ(0, res);
  *flags &= ~(MAP_ANON | MAP_ANONYMOUS);
  return fd;
#else
  return -1;
#endif
}

void DecorateMapping(uptr addr, uptr size, const char *name) {
#if 0 /* SANITIZER_ANDROID */
#define PR_SET_VMA 0x53564d41
#define PR_SET_VMA_ANON_NAME 0
  if (!common_flags()->decorate_proc_maps || !name)
    return;
  internal_prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, addr, size, (uptr)name);
#endif
}
