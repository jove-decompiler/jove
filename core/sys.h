#pragma once

#ifdef JOVE_SYS_ATTR
#error
#endif

#define JOVE_SYS_ATTR inline

#ifdef JOVE_SYS_H
#error
#endif

#if defined(__x86_64__)
#define JOVE_SYS_PATH "arch/x86_64/jove_sys.h"
#elif defined(__i386__)
#define JOVE_SYS_PATH "arch/i386/jove_sys.h"
#elif defined(__aarch64__)
#define JOVE_SYS_PATH "arch/aarch64/jove_sys.h"
#elif defined(__mips64)
#define JOVE_SYS_PATH "arch/mips64/jove_sys.h"
#elif defined(__mips__)
#define JOVE_SYS_PATH "arch/mips32/jove_sys.h"
#else
#error
#endif

#include JOVE_SYS_PATH

#undef JOVE_SYS_PATH
