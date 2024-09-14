#pragma once
#include "glibc.h"

namespace jove {

template <class PutEnv>
constexpr
void SetupEnvironForRun(PutEnv Env) {
  if (glibc_tunables_env)
    Env(glibc_tunables_env);

  Env("LD_BIND_NOW=1"); /* disable lazy linking (please) */
}

}
