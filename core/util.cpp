#include "util.h"
#include "fd.h"

#include <cassert>
#include <cstring>
#include <fstream>
#include <stdexcept>

#include <sched.h>
#include <signal.h>
#include <sys/stat.h>

namespace jove {

void read_file_into_vector(const char *path, std::vector<uint8_t> &out) {
  std::ifstream ifs(path);
  if (!ifs.is_open())
    throw std::runtime_error("read_file_into_vector: failed to open " +
                             std::string(path));

  ifs.seekg(0, std::ios::end);
  out.resize(ifs.tellg());
  ifs.seekg(0);

  ifs.read(reinterpret_cast<char *>(&out[0]), out.size());
}

long size_of_file32(const char *path) {
  uint32_t res;
  {
    struct stat st;
    if (::stat(path, &st) < 0)
      return -errno;

    res = st.st_size;
  }

  return res;
}

unsigned num_cpus(void) {
  cpu_set_t cpu_mask;
  if (sched_getaffinity(0, sizeof(cpu_mask), &cpu_mask) < 0) {
    int err = errno;
    throw std::runtime_error(std::string("sched_getaffinity failed: ") + strerror(err));
  }

  return CPU_COUNT(&cpu_mask);
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
