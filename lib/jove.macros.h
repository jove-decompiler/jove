#pragma once
#include <boost/preprocessor/stringize.hpp>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define _IOV_ENTRY(var) {.iov_base = &var, .iov_len = sizeof(var)}

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define MAX_ERRNO       4095
#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)-MAX_ERRNO)

#define memory_barrier() do { __sync_synchronize(); } while(0)

#ifdef JOVE_MT
#define __JTHREAD __thread
#else
#define __JTHREAD
#endif

#define _CTOR   __attribute__((constructor(0)))
#define _INL    __attribute__((always_inline))
#define _NAKED  __attribute__((naked))
#define _NOINL  __attribute__((noinline))
#define _NORET  __attribute__((noreturn))
#define _UNUSED __attribute__((unused))
#define _HIDDEN __attribute__((visibility("hidden")))

#define QEMU_ALIGN_DOWN(n, m) ((n) / (m) * (m))
#define QEMU_ALIGN_UP(n, m) QEMU_ALIGN_DOWN((n) + (m) - 1, (m))

#if !defined(__x86_64__) && defined(__i386__)
#define _REGPARM __attribute__((regparm(3)))
#define WINAPI __attribute__((stdcall))
#else
#define _REGPARM
#define WINAPI
#endif

#define TRUE 1
#define FALSE 0

#define __ANSI_COLOR_PREFIX "\033["
#define __ANSI_COLOR_SUFFIX "m"

#define __ANSI_GREEN          __ANSI_COLOR_PREFIX "32" __ANSI_COLOR_SUFFIX
#define __ANSI_RED            __ANSI_COLOR_PREFIX "31" __ANSI_COLOR_SUFFIX
#define __ANSI_BOLD_GREEN     __ANSI_COLOR_PREFIX "1;32" __ANSI_COLOR_SUFFIX
#define __ANSI_BOLD_BLUE      __ANSI_COLOR_PREFIX "1;34" __ANSI_COLOR_SUFFIX
#define __ANSI_BOLD_RED       __ANSI_COLOR_PREFIX "1;31" __ANSI_COLOR_SUFFIX "CS-ERROR: "
#define __ANSI_MAGENTA        __ANSI_COLOR_PREFIX "35" __ANSI_COLOR_SUFFIX
#define __ANSI_CYAN           __ANSI_COLOR_PREFIX "36" __ANSI_COLOR_SUFFIX
#define __ANSI_YELLOW         __ANSI_COLOR_PREFIX "33" __ANSI_COLOR_SUFFIX
#define __ANSI_BOLD_YELLOW    __ANSI_COLOR_PREFIX "1;33" __ANSI_COLOR_SUFFIX
#define __ANSI_NORMAL_COLOR   __ANSI_COLOR_PREFIX "0" __ANSI_COLOR_SUFFIX

#define UNIQUE_VAR_NAME(base) base##__COUNTER__

#define _UNREACHABLE(...)                                                      \
  do {                                                                         \
    static const char __msg[] =                                                \
        "JOVE UNREACHABLE: " __VA_ARGS__ " "                                   \
        "(" BOOST_PP_STRINGIZE(__FILE__) ":"                                   \
            BOOST_PP_STRINGIZE(__LINE__) ")\n";                                \
                                                                               \
    long __rc;                                                                 \
    do {                                                                       \
      __rc = _jove_sys_write(2 /* stderr */, &__msg[0], sizeof(__msg));        \
    } while (__rc == -EINTR);                                                  \
                                                                               \
    _jove_sys_exit_group(1);                                                   \
    __builtin_unreachable();                                                   \
  } while (false)

#define _ASSERT(cond)                                                          \
  do {                                                                         \
    if (unlikely(!(cond)))                                                     \
      _UNREACHABLE("!(" BOOST_PP_STRINGIZE(cond) ")");                         \
  } while (false)

#define _VERY_UNREACHABLE(...)                                                 \
  do {                                                                         \
    __builtin_trap();                                                          \
    __builtin_unreachable();                                                   \
  } while (false)

#define _CLEANUP(x) __attribute__((cleanup(x)))
