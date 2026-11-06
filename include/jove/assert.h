#ifndef JOVE_ASSERT_H
#define JOVE_ASSERT_H
#include "jove/likely.h"

#include <stdexcept>
#include <cassert>
#include <algorithm>

#include <boost/preprocessor/stringize.hpp>

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

struct dynamic_assertion_failure_base {
  virtual ~dynamic_assertion_failure_base() {}

  virtual const char* what() const noexcept = 0;
  virtual const char* what_more() const noexcept = 0;
};

template <StaticString Msg>
struct assertion_failure_exception : public assertion_failure_base {
  const char *what() const noexcept override { return Msg.value; }
};

template <StaticString Msg>
struct dynamic_assertion_failure_exception : public dynamic_assertion_failure_base {
  std::string more;

  template <class... Args>
  dynamic_assertion_failure_exception(Args &&...args)
      : more(std::forward<Args>(args)...) {}

  const char *what() const noexcept override { return Msg.value; }
  const char* what_more() const noexcept override { return this->more.c_str(); }
};

}

//
// an "always" assert always executes, regardless of whether NDEBUG is defined.
//

extern "C" void __assert_fail(const char *__assertion, const char *__file,
                              unsigned int __line, const char *__function)
    __attribute__((noreturn));

#endif /* JOVE_ASSERT_H*/

#ifdef aassert
#undef aassert
#endif
#ifdef assert
#undef assert
#endif

/* always assert (abort)" */
#define aasserta(cond)                                                         \
  ({                                                                           \
    if (unlikely(!(cond)))                                                     \
      ::__assert_fail(BOOST_PP_STRINGIZE(cond), __FILE__, __LINE__,            \
                                         __PRETTY_FUNCTION__);                 \
                                                                               \
    (void)0;                                                                   \
  })

#ifdef NO_JOVE_ASSERT
#define aassert(cond) aasserta(cond)
#define aassert_msg(cond, proc)                                                \
  ({                                                                           \
    if (unlikely(!(cond))) {                                                   \
      constexpr ::jove::StaticString ____msg{                                  \
        "(" BOOST_PP_STRINGIZE(cond) ") @ "                                    \
        BOOST_PP_STRINGIZE(__FILE__) ":" BOOST_PP_STRINGIZE(__LINE__)};        \
      std::string ____the_msg(____msg.value);                                  \
      ____the_msg.append(" ─▶ ");                                              \
      ____the_msg.append((proc)());                                            \
      ::__assert_fail(____the_msg.c_str(), __FILE__, __LINE__, __PRETTY_FUNCTION__);\
    }                                                                          \
    (void)0;                                                                   \
  })
#else /* NO_JOVE_ASSERT */
#define aassert(cond)                                                          \
  ({                                                                           \
    if (unlikely(!(cond))) {                                                   \
      constexpr ::jove::StaticString ____msg{                                  \
        "(" BOOST_PP_STRINGIZE(cond) ") @ "                                    \
        BOOST_PP_STRINGIZE(__FILE__) ":" BOOST_PP_STRINGIZE(__LINE__)};        \
      throw ::jove::assertion_failure_exception<____msg>();                    \
    }                                                                          \
    (void)0;                                                                   \
  })

#define aassert_msg(cond, proc)                                                \
  ({                                                                           \
    if (unlikely(!(cond))) {                                                   \
      constexpr ::jove::StaticString ____msg{                                  \
        "(" BOOST_PP_STRINGIZE(cond) ") @ "                                    \
        BOOST_PP_STRINGIZE(__FILE__) ":" BOOST_PP_STRINGIZE(__LINE__)};        \
      throw ::jove::dynamic_assertion_failure_exception<____msg>((proc)());    \
    }                                                                          \
    (void)0;                                                                   \
  })
#endif /* NO_JOVE_ASSERT */

#ifdef NDEBUG
#define assert(cond) ({ (void)0; })
#define assert_msg(cond) ({ (void)0; })
#else
#define assert(cond) aassert(cond)
#define assert_msg(cond, proc) aassert_msg(cond, proc)
#endif
