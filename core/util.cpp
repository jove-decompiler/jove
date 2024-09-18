#include "util.h"
#include "fd.h"

#include <cassert>
#include <cstring>
#include <stdexcept>
#include <sstream>

#include <sched.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/mman.h>

namespace jove {

uint64_t size_of_file(const char *path) {
  struct stat64 st;
  if (::stat64(path, &st) < 0) {
    int err = errno;
    throw std::runtime_error(std::string("size_of_file: stat64 failed: ") + strerror(err));
  }

  return st.st_size;
}

uint32_t size_of_file32(const char *path) {
  uint64_t res = size_of_file(path);
  if (res > 0xffffffff)
    throw std::runtime_error("size_of_file32: overflow");

  return static_cast<uint32_t>(res);
}

unsigned num_cpus(void) {
  cpu_set_t cpu_mask;
  if (sched_getaffinity(0, sizeof(cpu_mask), &cpu_mask) < 0) {
    int err = errno;
    throw std::runtime_error(std::string("sched_getaffinity failed: ") + strerror(err));
  }

  return CPU_COUNT(&cpu_mask);
}

void read_file_into_vector(const char *path, std::vector<uint8_t> &out) {
  read_file_into_thing<std::vector<uint8_t>>(path, out);
}

void read_file_into_a_string(const char *path, std::string &out) {
  read_file_into_thing<std::string>(path, out);
}

std::string read_file_into_string(const char *infile) {
  std::ifstream ifs(infile);
  if (!ifs.is_open())
    throw std::runtime_error(std::string("read_file_into_string: could not open ") + infile);

  std::stringstream buffer;
  buffer << ifs.rdbuf();

  return buffer.str();
}

static void IgnoreSignal(unsigned sig) {
  struct sigaction sa;

  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = SIG_IGN;

  if (::sigaction(sig, &sa, nullptr) < 0) {
    int err = errno;
    throw std::runtime_error(std::string("sigaction failed: ") + strerror(err));
  }
}

void IgnoreCtrlC(void) {
  IgnoreSignal(SIGINT);
}

static void DoDefaultOnSignal(unsigned sig) {
  struct sigaction sa;

  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = SIG_DFL;

  if (::sigaction(sig, &sa, nullptr) < 0) {
    int err = errno;
    throw std::runtime_error(std::string("sigaction failed: ") + strerror(err));
  }
}

void DoDefaultOnErrorSignal(void) {
  DoDefaultOnSignal(SIGABRT);
  DoDefaultOnSignal(SIGSEGV);
}

void exclude_from_coredumps(void *addr, size_t size) {
  ::madvise(addr, size, MADV_DONTDUMP);
}

}
