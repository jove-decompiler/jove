#include "crash.h"
#include "util.h"
#include "fd.h"
#include "sys.h"
#include "robust.h"

#include <sstream>
#include <iostream>

#include <boost/stacktrace.hpp>

#include <sys/mman.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/resource.h>

namespace jove {

//
// This function is basically meant as a last-ditch effort to convey information
// that may be useful for debugging.
//
// This function must be safe to call from signal handler.
//
static void dump_to_somewhere(const char *content) {
  static char filename[128] = "/tmp/jove.crash."; /* FIXME /tmp? */

  {
    char buff[65];
    uint_to_string(::_jove_sys_gettid(), buff, 10);
    strcat(filename, buff);
  }

  scoped_fd fd(_jove_sys_openat(-1, filename, O_WRONLY | O_CREAT | O_TRUNC, 0666));
  if (fd)
    robust::write(fd.get(), content, strlen(content));
}

static void crash_signal_handler(int no) {
  //
  // In theory, walking the stack without decoding and demangling should be
  // async signal safe. In practice, it is not. Therefore we must strive to
  // acquire the trace *before* the deadly signal has been delivered. We do this
  // by using C++ exceptions, throughout jove.
  //

  static const char rest[] = " crashed! attach a debugger...\n";

  char msg[65 + sizeof(rest)];
  memcpy(uint_to_string(_jove_sys_gettid(), msg, 10), rest, sizeof(rest));
  size_t len = strlen(msg);

  //
  // try to stand out in htop via nice(7)
  //
  _jove_sys_setpriority(PRIO_PROCESS, 0, 7);

  for (;;) {
    if (robust::write(STDERR_FILENO, msg, len) != len)
      robust::write(STDOUT_FILENO, msg, len);


    {
      struct timespec ts;

      if (_jove_sys_clock_gettime(CLOCK_MONOTONIC, (struct __kernel_timespec *)&ts) == 0) {
        ts.tv_sec += 1;

        do {} while (_jove_sys_clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, (struct __kernel_timespec *)&ts, NULL) == -EINTR);
      }
    }
  }
  __builtin_unreachable();
}

void setup_crash_signal_handler(void) {
  const unsigned altstack_size = SIGSTKSZ;

  void *altstack = mmap(NULL, altstack_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (altstack == MAP_FAILED)
    throw std::runtime_error("mmap failed: " + std::string(strerror(errno)));

  stack_t ss;
  ss.ss_sp = altstack;
  ss.ss_size = altstack_size;
  ss.ss_flags = 0;

  if (::sigaltstack(&ss, nullptr) < 0)
    throw std::runtime_error("sigaltstack failed: " + std::string(strerror(errno)));

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));

  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_NODEFER | SA_ONSTACK;
  sa.sa_handler = crash_signal_handler;

  if (::sigaction(SIGSEGV, &sa, nullptr) < 0 ||
      ::sigaction(SIGABRT, &sa, nullptr) < 0 ||
      ::sigaction(SIGBUS, &sa, nullptr) < 0)
    throw std::runtime_error("sigaction failed: " +
                             std::string(strerror(errno)));
}

static void terminate_handler(void) {
  try {
    std::stringstream ss;
    {
      auto trace = boost::stacktrace::stacktrace::from_current_exception();
      if (trace)
        ss << trace;
      else
        ss << "FAILED TO GET STACKTRACE!\n";
    }
    std::string s = ss.str();

    std::cerr << s;
    dump_to_somewhere(s.c_str());
  } catch (...) {}

  std::abort();
}

void setup_crash_handler(void) { std::set_terminate(&terminate_handler); }

}
