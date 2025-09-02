#include "redirect.h"

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

#if 0
  const char *const sigdesc = strsignal(no);
  std::string signame("SIG");
  signame.append(sigabbrev_np(no));
#endif

  pid_t child = get_redirectee();
  if (child < 0) {
#if 0
    tool.HumanOut() << llvm::formatv(
        "received {0} but no app to redirect to!\n", signame);
#endif
  } else {
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

#if 0
    if (tool.IsVerbose())
      tool.HumanOut() << llvm::formatv("redirecting {0} to {1}... <{2}>\n",
                                       signame, child, sigdesc);
#endif

    if (::kill(child, no) < 0) {
#if 0
      int err = errno;
      tool.HumanOut() << llvm::formatv("failed to redirect {0}\n", signame);
#endif
    }
  }
}

void setup_to_redirect_signal(int no, Tool &tool,
                              get_redirectee_proc_t get_redirectee_proc) {
  the_tool = &tool;
  get_redirectee = get_redirectee_proc;

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));

  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  sa.sa_handler = RedirectSigHandler;

  if (::sigaction(no, &sa, nullptr) < 0)
    throw std::runtime_error(std::string("sigaction failed: ") +
                             strerror(errno));
}

}
