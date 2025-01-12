#pragma once
#include <algorithm>
#include <boost/scope/defer.hpp>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <string>
#include <vector>

namespace jove {

constexpr void lower_string(std::string &s) {
  std::transform(s.cbegin(), s.cend(), s.begin(),
                 [](auto ch) -> auto { return std::tolower(ch); });
}

static inline std::string lowered_string(const std::string &s) {
  std::string res(s);
  lower_string(res);
  return res;
}

constexpr void upper_string(std::string &s) {
  std::transform(s.cbegin(), s.cend(), s.begin(),
                 [](auto ch) -> auto { return std::toupper(ch); });
}

static inline std::string uppered_string(const std::string &s) {
  std::string res(s);
  upper_string(res);
  return res;
}

// when using this function carefully consider whether it is the right choice.
static inline bool ignore_exception(std::function<void(void)> f) {
  try {
    f();
    return false;
  } catch (...) {
    return true;
  }
}

static inline bool catch_exception(std::function<void(void)> f) {
  return ignore_exception(f);
}

// assigns x to y, returns x != y (before the assignment)
template <typename T> static inline bool updateVariable(T &x, const T &y) {
  if (x != y) {
    x = y;
    return true;
  }

  return false;
}

// doesn't assume the file is seekable
template <typename T>
inline void read_whatever_into_thing(const char *path, T &out) {
  std::ifstream ifs(path);
  if (!ifs.is_open())
    throw std::runtime_error("read_whatever_into_thing: failed to open " +
                             std::string(path));
  std::vector<char> buff;
  const std::size_t chunkSize = 4096;

  for (;;) {
    // Increase the size of the vector to accommodate new data
    std::size_t currentSize = buff.size();
    buff.resize(currentSize + chunkSize);

    // Read data directly into the vector
    ifs.read(&buff[currentSize], chunkSize);
    std::streamsize bytesRead = ifs.gcount();

    // Resize the vector to the actual number of bytes read
    buff.resize(currentSize + bytesRead);

    // Break if we've reached the end of the file
    if (bytesRead < static_cast<std::streamsize>(chunkSize))
      break;
  }

  if (buff.empty())
    throw std::runtime_error("read_whatever_into_thing: empty file \"" +
                             std::string(path) + "\"");

  out.resize(buff.size());
  memcpy(&out[0], &buff[0], buff.size());
}

template <typename T>
inline void read_file_into_thing(const char *path, T &out) {
  out.clear();

  std::ifstream ifs(path, std::ios::binary | std::ios::ate);
  if (!ifs.is_open())
    throw std::runtime_error("read_file_into_thing: failed to open " +
                             std::string(path));

  auto pos = ifs.tellg();
  if (pos == 0)
    return;

  try {
    out.resize(pos);
  } catch (const std::bad_alloc &bad) {
    throw std::runtime_error(
        "read_file_into_thing: attempted to resize vec by " +
        std::to_string(pos) + " bytes after reading \"" + path + "\"");
  }

  ifs.seekg(0, std::ios::beg);

  ifs.read((char *)&out[0], out.size());
}

template <typename T> static void load_file(const char *path, T &out) {
  size_t read;
  FILE *file;
  long fsize;
  int errcode;

  if (!path)
    throw std::runtime_error("load_file: null path");

  errno = 0;
  file = fopen(path, "rb");
  if (!file)
    throw std::runtime_error(std::string("load_file: failed to open \"") +
                             path + "\": " + std::string(strerror(errno)));

  BOOST_SCOPE_DEFER [&] { fclose(file); };

  errcode = fseek(file, 0, SEEK_END);
  if (errcode)
    throw std::runtime_error(
        std::string("load_file: failed to determine size of \"") + path +
        "\": " + std::string(strerror(errno)));

  fsize = ftell(file);
  if (fsize < 0)
    throw std::runtime_error(
        std::string("load_file: failed to tell \"") + path +
        "\": " + std::string(strerror(errno)));

  if (fsize == 0)
    return;

  out.resize((size_t)fsize);

  errcode = fseek(file, 0, SEEK_SET);
  if (errcode)
    throw std::runtime_error(std::string("load_file: failed to seek \"") +
                             path + "\": " + std::string(strerror(errno)));

  read = fread(&out[0], (size_t)fsize, 1u, file);
  if (read != 1)
    throw std::runtime_error(std::string("load_file: failed to read \"") +
                             path + "\": " + std::string(strerror(errno)));
}

template <typename T>
static inline bool insertSortedVec(std::vector<T> &vec, const T &x) {
  // Find the correct position to insert the string
  auto it = std::lower_bound(vec.begin(), vec.end(), x);
  // Insert only if the string is not already in the vector
  if (it == vec.end() || *it != x) {
    vec.insert(it, x);
    return true;
  }

  return false;
}

void read_file_into_vector(const char *path, std::vector<uint8_t> &out);
void read_file_into_a_string(const char *path, std::string &out);
std::string read_file_into_string(const char *infile);
uint64_t size_of_file(const char *path);
uint32_t size_of_file32(const char *path);
unsigned num_cpus(void);
void IgnoreCtrlC(void);
void DoDefaultOnErrorSignal(void);
void exclude_from_coredumps(void *addr, size_t size);

} // namespace jove
