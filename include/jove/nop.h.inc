#ifndef IN_JOVE_H
#error "only to be included inline in jove/jove.h"
#endif

//
// this class does exactly what it sounds like: nothing.
//
struct nop_t {
  template <typename... Args>
  nop_t(Args &&...) noexcept {}

#define DEFINE_METHOD_EMPTY_BODY(name)                                         \
  template <typename... Args>                                                  \
  void name(Args &&...) const noexcept {}

  //
  // don't hesitate to add another method here.
  //
  DEFINE_METHOD_EMPTY_BODY(unlock)
  DEFINE_METHOD_EMPTY_BODY(lock)

#undef DEFINE_METHOD_EMPTY_BODY
};
