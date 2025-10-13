#include "redirect.h"
#include "sys.h"

#include <llvm/Support/FormatVariadic.h>

#include <signal.h>

namespace jove {

static Tool *the_tool;
static get_redirectee_proc_t get_redirectee = [](void) -> int {
  return -1;
};

static void RedirectSigHandler(int no) {
  assert(the_tool);
  Tool &tool = *the_tool;

#if 1
#endif

  pid_t child = get_redirectee();
  if (child < 0) {
#if 0
    tool.HumanOut() << llvm::formatv(
        "received {0} but no app to redirect to!\n", signame);
#endif
    return;
  }

  //
  // redirect the signal.
  //
  if (no == SIGINT) {
#if 0
    if (tool.IsVerbose())
      tool.HumanOut() << "Received SIGINT. Cancelling..\n";
#endif
    tool.interrupted.store(true, std::memory_order_relaxed);
  }

#if 1
  if (tool.IsVeryVerbose()) {
    const char *const sigdesc = strsignal(no);
    std::string signame("SIG");
    signame.append(sigabbrev_np(no));

    tool.HumanOut() << llvm::formatv("redirecting {0} to {1}... <{2}>\n",
                                     signame, child, sigdesc);
  }
#endif

  if (_jove_sys_kill(child, no) < 0) {
#if 0
    int err = errno;
    tool.HumanOut() << llvm::formatv("failed to redirect {0}\n", signame);
#endif
  }
}

void SetupSignalsRedirection(std::span<const int> signals, Tool &tool,
                             get_redirectee_proc_t get_redirectee_proc) {
  the_tool = &tool;
  get_redirectee = get_redirectee_proc;

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));

  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  sa.sa_handler = RedirectSigHandler;

  for (const int no : signals)
    aassert(!(::sigaction(no, &sa, nullptr) < 0));
}
}
