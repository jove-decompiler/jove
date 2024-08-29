#pragma once
#include <string>
#include <string_view>
#include <vector>

namespace jove {
namespace wine {

std::string convert_to_linux_path(std::string path);
std::string get_prefix(void);

struct stderr_parser {
  const std::string &contents;

  stderr_parser(const std::string &contents) : contents(contents) {}

  long tid_of_NtCreateUserProcess(const char *prog);

  void
  loaddll_loaded_for_tid(unsigned long tid,
                         std::vector<std::pair<std::string, uint64_t>> &out);
};

}
}
