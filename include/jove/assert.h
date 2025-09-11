#include "jove/macros.h"

#include <stdexcept>
#include <cassert>
#include <algorithm>

#include <boost/assert.hpp>
#include <boost/preprocessor/stringize.hpp>

#ifndef JOVE_ASSERT_H
#define JOVE_ASSERT_H

namespace jove {

template <size_t N>
struct StaticString {
  constexpr StaticString(const char (&str)[N]) { std::copy_n(str, N, value); }
  char value[N];
};

struct assertion_failure_base {
  virtual ~assertion_failure_base() {}

  virtual const char* what() const noexcept = 0;
};

template <StaticString Msg>
struct assertion_failure_exception : public assertion_failure_base {
  const char *what() const noexcept override { return Msg.value; }
};

}

#endif

#ifndef NO_JOVE_ASSERT

#ifndef assert
#error "this should come after assert() has already been defined"
#endif

#undef assert

//
// an "always" assert always executes, regardless of whether NDEBUG is defined.
//
// FIXME record __FILE__, __LINE__, ...
//
#define aassert(cond)                                                          \
  do {                                                                         \
    if (unlikely(!(cond))) {                                                   \
      constexpr ::jove::StaticString ____msg{BOOST_PP_STRINGIZE(cond)};        \
      throw ::jove::assertion_failure_exception<____msg>();                    \
    }                                                                          \
  } while (false)

#ifdef NDEBUG
#define assert(cond) do {} while (false)
#else
#define assert(cond) aassert(cond)
#endif

#endif /* NO_JOVE_ASSERT */
