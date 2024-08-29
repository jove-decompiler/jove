#include "wine.h"

#include <boost/filesystem.hpp>

#include <cassert>
#include <algorithm>
#include <stdexcept>
#include <regex>
#include <fstream>

namespace fs = boost::filesystem;

namespace jove {
namespace wine {

std::string convert_to_linux_path(std::string path) {
  assert(!path.empty());

  std::string prefix = "\\\\??\\\\";
  if (path.find(prefix) == 0) {
    path = path.substr(prefix.size());
  }

  std::string c_drive_prefix = "C:\\";
  if (path.find(c_drive_prefix) == 0) {
    path.replace(0, c_drive_prefix.size(), get_prefix() + "/drive_c");
  }

  std::string z_drive_prefix = "Z:\\";
  if (path.find(z_drive_prefix) == 0) {
    path = path.substr(z_drive_prefix.size());
  }

  std::replace(path.begin(), path.end(), '\\', '/');

  // manually remove redundant slashes
  std::string::size_type pos = 0;
  while ((pos = path.find("//", pos)) != std::string::npos) {
    path.replace(pos, 2, "/");
  }

  return path;
}

std::string get_prefix(void) {
  if (const char *wineprefix = std::getenv("WINEPREFIX"))
    return wineprefix;

  // otherwise, assume ~/.wine
  const char *home = std::getenv("HOME");
  if (!home)
    throw std::runtime_error("Could not find home directory!");

  return std::string(home) + "/.wine";
}

long stderr_parser::tid_of_NtCreateUserProcess(const char *prog) {
  std::regex re(
      R"delim([0-9a-z]+:trace:process:NtCreateUserProcess L"([^"]+)" pid ([0-9a-z]+) tid ([0-9a-z]+) handles 0x[0-9a-z]+/0x[0-9a-z]+)delim");

  std::sregex_iterator begin(contents.begin(), contents.end(), re);
  std::sregex_iterator end;
  for (std::sregex_iterator i = begin; i != end; ++i) {
    const std::smatch &match = *i;

    std::string winpath = match[1].str();
    std::string pid_str = match[2].str();
    std::string tid_str = match[3].str();

    if (fs::equivalent(prog, convert_to_linux_path(winpath))) {
      return strtol(tid_str.c_str(), nullptr, 16);
    }
  }

  return -1;
}

void stderr_parser::loaddll_loaded_for_tid(
    unsigned long tid, std::vector<std::pair<std::string, uint64_t>> &out) {
  std::regex re(
      R"delim(([0-9a-z]+):trace:loaddll:build_module Loaded L"([^"]+)" at ([0-9a-zA-Z]+): (builtin|native))delim");

  std::sregex_iterator begin(contents.begin(), contents.end(), re);
  std::sregex_iterator end;
  for (std::sregex_iterator i = begin; i != end; ++i) {
    const std::smatch &match = *i;

    std::string tid_str = match[1].str();
    if (strtol(tid_str.c_str(), nullptr, 16) != tid)
      continue;

    std::string winpath = match[2].str();
    std::string addr_str = match[3].str();

    out.emplace_back(convert_to_linux_path(winpath),
                     strtol(addr_str.c_str(), nullptr, 16));
  }
}

}
}
