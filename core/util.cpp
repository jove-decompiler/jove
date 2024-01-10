#include "util.h"
#include "fd.h"

#include <cassert>
#include <cstring>
#include <stdexcept>

#include <sched.h>
#include <signal.h>
#include <sys/stat.h>

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

std::string read_file_into_string(char const *infile) {
  std::ifstream instream(infile);
  if (!instream.is_open())
    throw std::runtime_error(std::string("read_file_into_string: could not open ") + infile);

  instream.unsetf(std::ios::skipws); // No white space skipping!
  return std::string(std::istreambuf_iterator<char>(instream.rdbuf()),
                     std::istreambuf_iterator<char>());
}

void IgnoreCtrlC(void) {
  struct sigaction sa;

  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
#if 0
  sa.sa_handler = [](int) -> void {};
#else
  sa.sa_handler = SIG_IGN;
#endif

  if (::sigaction(SIGINT, &sa, nullptr) < 0) {
    int err = errno;
    throw std::runtime_error(std::string("IgnoreCtrlC: sigaction failed: ") + strerror(err));
  }
}

}
