#ifndef IN_JOVE_H
#error "only to be included inline in jove/jove.h"
#endif

#if defined(__mips64) || defined(__mips__)
//
// it is highly likely that the user is running under an emulation
// (e.g. firmadyne), so it makes sense to make everything single-threaded. [1]
//
// FIXME make this configurable at build-time.
//
// [1] ALE: the only physical MIPS machine I've possessed is a rhino labs UTM8
// (rt80-Cavium-Octeon). Unfortunately, the newest debian stable (bookworm) does
// not run (unless one patches a bunch of programs (e.g. sshd)) because the
// kernel is an out-of-tree 3.10.
//
constexpr auto maybe_par_unseq = std::execution::seq;
constexpr bool AreWeMT = false;
#define __THREAD_IF_WE_ARE_MT
#define JOVE_NO_BACKEND
#define JOVE_NO_TBB
#else
constexpr auto maybe_par_unseq = std::execution::par_unseq;
constexpr bool AreWeMT = true;
#define __THREAD_IF_WE_ARE_MT                                                  \
  thread_local __attribute__((tls_model("initial-exec")))
#endif
