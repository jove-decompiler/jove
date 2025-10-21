#include "jove/likely.h"

#include <stdexcept>
#include <cassert>
#include <algorithm>

#include <boost/preprocessor/stringize.hpp>

#ifndef JOVE_ASSERT_H
#define JOVE_ASSERT_H

namespace jove {

template <size_t N>
struct StaticString {
  constexpr StaticString(const char (&str)[N]) { std::copy_n(str, N, value); }
  char value[N];
};

template <size_t N> StaticString(const char (&)[N]) -> StaticString<N>;

struct assertion_failure_base {
  virtual ~assertion_failure_base() {}

  virtual const char* what() const noexcept = 0;
};

template <StaticString Msg>
struct assertion_failure_exception : public assertion_failure_base {
  const char *what() const noexcept override { return Msg.value; }
};

}

//
// an "always" assert always executes, regardless of whether NDEBUG is defined.
//
// FIXME record __FILE__, __LINE__, ...
//
#ifdef NO_JOVE_ASSERT
extern "C" void __assert_fail(const char *__assertion, const char *__file,
                              unsigned int __line, const char *__function)
    __attribute__((noreturn));

#define aassert(cond)                                                          \
  ({                                                                           \
    if (unlikely(!(cond)))                                                     \
      ::__assert_fail(BOOST_PP_STRINGIZE(cond), __FILE__, __LINE__,            \
                                         __PRETTY_FUNCTION__);                 \
                                                                               \
    (void)0;                                                                   \
  })
#else /* NO_JOVE_ASSERT */
#define aassert(cond)                                                          \
  ({                                                                           \
    if (unlikely(!(cond))) {                                                   \
      constexpr ::jove::StaticString ____msg{BOOST_PP_STRINGIZE(cond)};        \
      throw ::jove::assertion_failure_exception<____msg>();                    \
    }                                                                          \
    (void)0;                                                                   \
  })
#endif /* NO_JOVE_ASSERT */
#endif /* JOVE_ASSERT_H*/

#undef assert
#ifdef NDEBUG
#define assert(cond) ({ (void)0; })
#else
#define assert(cond) aassert(cond)
#endif
