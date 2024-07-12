#pragma once

#if defined(__x86_64__)
#define mb() asm volatile("mfence" ::: "memory")
#elif defined(__i386__)
#define mb() asm volatile("lock; addl $0,0(%%esp)" ::: "memory")
#elif defined(__aarch64__)
#define mb() asm volatile("dmb ish" ::: "memory")
#elif defined(__mips64)
#define mb() asm volatile("sync" ::: "memory")
#elif defined(__mips__)
#define mb() asm volatile("sync 0x00" ::: "memory")
#else
#error
#endif
