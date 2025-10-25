#include "util.h"
#include "fd.h"
#include "assert.h"

#include <cerrno>
#include <cstring>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <system_error>

#include <sched.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/mman.h>

static_assert(sizeof(off_t) >= 8, "Build with -D_FILE_OFFSET_BITS=64");

namespace jove {

uint64_t size_of_file(const char* path) {
  struct stat st{};
  if (::stat(path, &st) < 0)
    throw std::system_error(errno, std::generic_category(),
                            std::string("stat('") + path + "') failed");

  if (!S_ISREG(st.st_mode))
    throw std::runtime_error(std::string("not a regular file: ") + path);

  aassert(st.st_size >= 0);
  return static_cast<uint64_t>(st.st_size);
}

uint32_t size_of_file32(const char* path) {
  uint64_t len = size_of_file(path);
  if (len > std::numeric_limits<uint32_t>::max()) {
    throw std::runtime_error("size_of_file32: overflow");
  }
  return static_cast<uint32_t>(len);
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
