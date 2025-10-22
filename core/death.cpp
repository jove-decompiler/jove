#include <linux/prctl.h>  /* Definition of PR_* constants */
#include <sys/prctl.h>
#include <signal.h>

namespace jove {

static void __attribute__((__constructor__)) death_init(void) {
  (void)::prctl(PR_SET_PDEATHSIG, SIGTERM);
}

}
