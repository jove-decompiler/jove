#pragma once
#include "elf.h"
#include "util.h"

#include <llvm/Object/Binary.h>

#include <functional>
#include <memory>

namespace jove {
namespace B {

std::unique_ptr<llvm::object::Binary> Create(llvm::StringRef Data);

template <typename T>
static inline std::unique_ptr<llvm::object::Binary>
CreateFromFile(const char *path, T &bytes) {
  read_file_into_thing<T>(path, bytes);

  return Create(llvm::StringRef((const char *)bytes.data(), bytes.size()));
}

}
}
