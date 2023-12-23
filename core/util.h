#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include <fstream>

namespace jove {

// when using this function carefully consider whether it is the right choice.
inline void ignore_exception(std::function<void(void)> f) {
  try {
    f();
  } catch (...) {
    ;
  }
}

template <typename T>
inline void read_file_into_thing(const char *path, T &out) {
  std::ifstream ifs(path);
  if (!ifs.is_open())
    throw std::runtime_error("read_file_into_vector: failed to open " +
                             std::string(path));

  ifs.seekg(0, std::ios::end);
  out.resize(ifs.tellg());
  ifs.seekg(0);

  ifs.read(reinterpret_cast<char *>(&out[0]), out.size());
}

inline void read_file_into_vector(const char *path, std::vector<uint8_t> &out) {
  read_file_into_thing<std::vector<uint8_t>>(path, out);
}

inline void read_file_into_a_string(const char *path, std::string &out) {
  read_file_into_thing<std::string>(path, out);
}

void read_file_into_vector(const char *path, std::vector<uint8_t> &out);
void read_file_into_a_string(const char *path, std::string &out);
std::string read_file_into_string(char const *infile);
uint64_t size_of_file(const char *path);
uint32_t size_of_file32(const char *path);
unsigned num_cpus(void);
void IgnoreCtrlC(void);

}
