#pragma once

#include <stddef.h>
#include <boost/preprocessor/cat.hpp>

//
// QEMU helper code is, strictly speaking, written in the C programming
// language. It should never encroach upon the tools.
//
#pragma GCC poison CONFIG_JOVE
#pragma GCC poison CONFIG_JOVE_HELPERS

//
// The __error__ attribute is useful, because it allows one to write code that
// won't compile unless it's dead-code-eliminated away.
//
#define __compiletime_error(msg) __attribute__((__error__(msg)))

#define __noreturn __attribute__((__noreturn__))

#define __compiletime_assert(condition, msg, prefix, suffix)                   \
  do {                                                                         \
    /*                                                                         \
     * __noreturn is needed to give the compiler enough                        \
     * information to avoid certain possibly-uninitialized                     \
     * warnings (regardless of the build failing).                             \
     */                                                                        \
    __noreturn extern void prefix##suffix(void) __compiletime_error(msg);      \
    if (!(condition))                                                          \
      prefix##suffix();                                                        \
  } while (0)

#define _compiletime_assert(condition, msg, prefix, suffix)                    \
  __compiletime_assert(condition, msg, prefix, suffix)

#define compiletime_assert(condition, msg)                                     \
  _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)

extern void __compiletime_error("unreachable")
__compiletime_unreachable(void);

//
// essential common stuff (taken from linux)
//
#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#define UNIQUE_VAR_NAME(base) BOOST_PP_CAT(base,__COUNTER__)

#define JOVE_CONTAINER_OF(ptr, T, member)                                      \
  (reinterpret_cast<T *>(reinterpret_cast<char *>(ptr) -                       \
                         __builtin_offsetof(T, member)))

#define JOVE_CONTAINER_OF_CONST(ptr, T, member)                                \
  (reinterpret_cast<const T *>(reinterpret_cast<const char *>(ptr) -           \
                               __builtin_offsetof(T, member)))
