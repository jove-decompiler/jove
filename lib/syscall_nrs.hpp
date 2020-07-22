namespace jove {
namespace syscalls {

namespace NR {
#define ___SYSCALL(nr, nm) constexpr unsigned nm = nr;
#include "syscalls.inc.h"
}

static constexpr unsigned NR_END = std::max<unsigned>({0u

#define ___SYSCALL(nr, nm) ,nr
#include "syscalls.inc.h"

                                   }) +
                                   1u;

static const unsigned nparams_tbl[NR_END] = {
    [0 ... NR_END - 1] = 6,

#define SYSCALLNPARAMS(nr, nparams) [nr] = nparams,

#define ___SYSCALL0(nr, ...) SYSCALLNPARAMS(nr, 0)
#define ___SYSCALL1(nr, ...) SYSCALLNPARAMS(nr, 1)
#define ___SYSCALL2(nr, ...) SYSCALLNPARAMS(nr, 2)
#define ___SYSCALL3(nr, ...) SYSCALLNPARAMS(nr, 3)
#define ___SYSCALL4(nr, ...) SYSCALLNPARAMS(nr, 4)
#define ___SYSCALL5(nr, ...) SYSCALLNPARAMS(nr, 5)
#define ___SYSCALL6(nr, ...) SYSCALLNPARAMS(nr, 6)

#include "syscalls.inc.h"

#undef SYSCALLNPARAMS

};

} // namespace syscalls
} // namespace jove
