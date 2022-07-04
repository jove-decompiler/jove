#pragma once
#include <llvm/Support/WithColor.h>

#define JOVE_UNUSED __attribute__((unused))

#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

JOVE_UNUSED static inline void __warn(const char *file, int line) {
  llvm::WithColor::warning() << llvm::formatv("{0}:{1}\n", file, line);
}

#ifndef WARN
#define WARN()                                                                 \
  do {                                                                         \
    __warn(__FILE__, __LINE__);                                                \
  } while (0)
#endif

#ifndef WARN_ON
#define WARN_ON(condition)                                                     \
  ({                                                                           \
    int __ret_warn_on = !!(condition);                                         \
    if (unlikely(__ret_warn_on))                                               \
      WARN();                                                                  \
    unlikely(__ret_warn_on);                                                   \
  })
#endif

#define __ANSI_COLOR_PREFIX "\033["
#define __ANSI_COLOR_SUFFIX "m"

#define __ANSI_GREEN          __ANSI_COLOR_PREFIX "32" __ANSI_COLOR_SUFFIX
#define __ANSI_RED            __ANSI_COLOR_PREFIX "31" __ANSI_COLOR_SUFFIX
#define __ANSI_BLUE           __ANSI_COLOR_PREFIX "34" __ANSI_COLOR_SUFFIX
#define __ANSI_BOLD_GREEN     __ANSI_COLOR_PREFIX "1;32" __ANSI_COLOR_SUFFIX
#define __ANSI_BOLD_BLUE      __ANSI_COLOR_PREFIX "1;34" __ANSI_COLOR_SUFFIX
#define __ANSI_BOLD_RED       __ANSI_COLOR_PREFIX "1;31" __ANSI_COLOR_SUFFIX
#define __ANSI_GRAY           __ANSI_COLOR_PREFIX "93" __ANSI_COLOR_SUFFIX
#define __ANSI_MAGENTA        __ANSI_COLOR_PREFIX "35" __ANSI_COLOR_SUFFIX
#define __ANSI_CYAN           __ANSI_COLOR_PREFIX "36" __ANSI_COLOR_SUFFIX
#define __ANSI_YELLOW         __ANSI_COLOR_PREFIX "33" __ANSI_COLOR_SUFFIX
#define __ANSI_MAGENTA        __ANSI_COLOR_PREFIX "35" __ANSI_COLOR_SUFFIX
#define __ANSI_BOLD_YELLOW    __ANSI_COLOR_PREFIX "1;33" __ANSI_COLOR_SUFFIX
#define __ANSI_NORMAL_COLOR   __ANSI_COLOR_PREFIX "0" __ANSI_COLOR_SUFFIX
