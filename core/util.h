#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include <algorithm>
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

// assigns x to y, returns x != y (before the assignment)
template <typename T> static inline bool updateVariable(T &x, const T &y) {
  if (x != y) {
    x = y;
    return true;
  }

  return false;
}

template <typename T>
inline void read_file_into_thing(const char *path, T &out) {
  out.clear();

  std::ifstream ifs(path);
  if (!ifs.is_open())
    throw std::runtime_error("read_file_into_thing: failed to open " +
                             std::string(path));

  ifs.seekg(0, std::ios::end);

  std::streampos pos = ifs.tellg();
  if (pos == 0)
    return;

  out.resize(pos);
  ifs.seekg(0);

  ifs.read(reinterpret_cast<char *>(&out[0]), out.size());
}

template <typename T>
static inline void insertSortedVec(std::vector<T> &vec, const T &x) {
  // Find the correct position to insert the string
  auto it = std::lower_bound(vec.begin(), vec.end(), x);
  // Insert only if the string is not already in the vector
  if (it == vec.end() || *it != x) {
    vec.insert(it, x);
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
