#pragma once
#include "mmap.h"

#include <cstdint>

namespace jove {
namespace loop {

struct shared_t {
  uint32_t child_pid;
  uint32_t recovered;
};

struct shared_mapping_t {
  scoped_mmap mm;

  template <typename... Args>
  shared_mapping_t(Args &&...args) : mm(std::forward<Args>(args)...) {}

  void checkMmapSuceeded(void) const {
    if (!mm)
      throw std::runtime_error("loop mapping no good");
  }

  shared_t &ref(void) {
    checkMmapSuceeded();
    return *reinterpret_cast<shared_t *>(mm.get());
  }

  const shared_t &ref(void) const {
    checkMmapSuceeded();
    return *reinterpret_cast<shared_t *>(mm.get());
  }

  int get_child_pid(void) const {
    return static_cast<int>(
        __atomic_load_n(&this->ref().child_pid, __ATOMIC_RELAXED));
  }

  char get_recovered(void) const {
    return static_cast<char>(
        __atomic_load_n(&this->ref().recovered, __ATOMIC_RELAXED));
  }

  void set_child_pid(pid_t pid) {
    const uint32_t u32_pid = static_cast<uint32_t>(pid);
    __atomic_store_n(&this->ref().child_pid, u32_pid, __ATOMIC_RELAXED);
  }

  void set_recovered(char ch) {
    const uint32_t u32_ch = static_cast<uint32_t>(ch);
    __atomic_store_n(&this->ref().recovered, u32_ch, __ATOMIC_RELAXED);
  }
};

}
}
