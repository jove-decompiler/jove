#include "vdso.h"
#include "util.h"
#include "temp.h"
#include "process.h"
#include "fd.h"

#include <cstring>
#include <stdexcept>
#include <memory>

#include <unistd.h>

namespace jove {

std::string_view get_vdso(void) {
  std::string maps = read_file_into_string("/proc/self/maps");
  assert(!maps.empty());

  unsigned n = maps.size();
  char *const beg = &maps[0];
  char *const end = &maps[n];

  char *eol;
  for (char *line = beg; line != end; line = eol + 1) {
    unsigned left = n - (line - beg);

    //
    // find the end of the current line
    //
    eol = (char *)memchr(line, '\n', left);

    //
    // second hex address
    //
    if (eol[-1] == ']' &&
        eol[-2] == 'o' &&
        eol[-3] == 's' &&
        eol[-4] == 'd' &&
        eol[-5] == 'v' &&
        eol[-6] == '[') {
      char *const dash = (char *)memchr(line, '-', left);
      assert(dash);

      char *const space = (char *)memchr(line, ' ', left);
      assert(space);

      *dash = '\0';
      uintptr_t min = strtoul(line, nullptr, 0x10);

      *space = '\0';
      uintptr_t max = strtoul(dash + 1, nullptr, 0x10);

      return std::string_view(reinterpret_cast<const char *>(min), max - min);
    }
  }

  return std::string_view();
}

static const uint8_t dumper_bin_bytes[] = {
#include "dump-vdso.inc"
};

bool capture_vdso(std::string &out) {
  temp_executable temp_exe(&dumper_bin_bytes[0],
                           sizeof(dumper_bin_bytes),
                           "dump-vdso-" TARGET_ARCH_NAME);
  temp_exe.store();

  int pipefd[2];
  if (::pipe(pipefd) < 0) {
    int err = errno;
    throw std::runtime_error("pipe failed: " + std::string(strerror(err)));
  }

  auto rfd = std::make_unique<scoped_fd>(pipefd[0]);
  auto wfd = std::make_unique<scoped_fd>(pipefd[1]);

  pid_t pid = RunExecutable(
      temp_exe.path().c_str(),
      process::no_args,
      process::no_envs, "", "",
      [&](const char **argv, const char **envp) {
        rfd.reset();
        ::dup2(wfd->get(), STDOUT_FILENO);
        wfd.reset();
      });
  wfd.reset();

  out.clear();

  std::vector<char> buff;
  buff.resize(2 * 4096);
  for (;;) {
    ssize_t ret;
    do
      ret = ::read(rfd->get(), &buff[0], buff.size());
    while (ret < 0 && errno == EINTR);

    if (ret < 0)
      throw std::runtime_error("failed to read pipe: " + std::string(strerror(errno)));

    if (ret == 0)
      break; /* done */

    out.append(buff.data(), ret);
  }

  int ret_val = WaitForProcessToExit(pid);

  rfd.reset();

  return ret_val == 0;
}

}
