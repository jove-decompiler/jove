#pragma once
#include "likely.h"

#ifndef __clang__
#error
#endif

namespace jove {

struct VerboseThing {
  unsigned VerbosityLevel = 0;

  void SetVerbosityLevel(bool V, bool VV) {
    if (VV)
      this->VerbosityLevel = 2;
    else if (V)
      this->VerbosityLevel = 1;
    else
      this->VerbosityLevel = 0;
  }

public:
  [[alwaysinline]] unsigned GetVerbosity(void) const {
    return __builtin_expect(this->VerbosityLevel, 0u);
  }

  [[alwaysinline]] bool IsVerbose(void) const {
    return unlikely(this->VerbosityLevel >= 1);
  }

  [[alwaysinline]] inline bool IsVeryVerbose(void) const {
    return unlikely(this->VerbosityLevel >= 2);
  }
};

}
