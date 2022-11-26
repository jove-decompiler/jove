#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <functional>

namespace jove {

// when using this function carefully consider whether it is the right choice.
inline void ignore_exception(std::function<void(void)> f) {
  try {
    f();
  } catch (...) {
    ;
  }
}

void read_file_into_vector(const char *path, std::vector<uint8_t> &out);
void read_file_into_a_string(const char *path, std::string &out);
std::string read_file_into_string(char const *infile);
uint64_t size_of_file(const char *path);
uint32_t size_of_file32(const char *path);
unsigned num_cpus(void);
void IgnoreCtrlC(void);

}
