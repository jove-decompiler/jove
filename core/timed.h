#pragma once
#include "robust.h"
#include "jove/macros.h"

#include <sstream>
#include <memory>
#include <boost/timer/timer.hpp>

namespace jove {

class scoped_timed {
  const bool Disabled = false;
  const char *const name;
  std::stringstream ss;
  std::unique_ptr<boost::timer::auto_cpu_timer> timer;

public:
  scoped_timed(const char *const name, const bool Disabled = false)
      : Disabled(Disabled),
        name(name) {
    if (Disabled)
      return;
    
    assert(name);

    timer = std::make_unique<boost::timer::auto_cpu_timer>(
        ss, 3, "%ws wall, %us user + %ss system = %ts CPU (%p%)\n");

    std::string to_print;
    to_print.push_back('<');
    to_print.append(name);
    to_print.append(">\n");

    robust::write(1 /* stdout */, to_print.c_str(), to_print.size());
  }
  ~scoped_timed () {
    if (Disabled)
      return;

    timer.reset();

    std::string to_print;
    to_print.append("</");
    to_print.append(name);
    to_print.append("> ");
    to_print.append(ss.str());

    robust::write(1 /* stdout */, to_print.c_str(), to_print.size());
  }
};

}

#define ____scoped_timed____(Disabled)                                         \
  [[maybe_unused]] scoped_timed UNIQUE_VAR_NAME(___timed)(__PRETTY_FUNCTION__, Disabled)
