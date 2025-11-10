#pragma once
#include "jove/likely.h"

namespace jove {

struct VerboseThing {
  unsigned VerbosityLevel = 0;

  void SetVerbosity(bool V, bool VV) {
    if (VV)
      this->VerbosityLevel = 2;
    else if (V)
      this->VerbosityLevel = 1;
    else
      this->VerbosityLevel = 0;
  }

  void SetVerbosityLevel(unsigned VerbosityLevel) {
    this->VerbosityLevel = VerbosityLevel;
  }

  VerboseThing() = default;
  VerboseThing(unsigned Level) : VerbosityLevel(Level) {}

public:
  [[clang::always_inline]] unsigned GetVerbosityLevel(void) const {
    return __builtin_expect(this->VerbosityLevel, 0u);
  }

  [[clang::always_inline]] bool IsVerbose(void) const {
    return unlikely(this->VerbosityLevel >= 1);
  }

  [[clang::always_inline]] inline bool IsVeryVerbose(void) const {
    return unlikely(this->VerbosityLevel >= 2);
  }
};

}
