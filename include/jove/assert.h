/* we like destructors. */
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

#ifdef NDEBUG
#define assert(cond) do {} while (false)
#else
#define assert(cond)                                                           \
  do {                                                                         \
    if (unlikely(!(cond))) {                                                   \
      throw jove::assertion_failure_exception<BOOST_PP_STRINGIZE(cond)>();     \
    }                                                                          \
  } while (false)
#endif

#endif /* NO_JOVE_ASSERT */
