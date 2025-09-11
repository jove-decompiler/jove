#ifndef IN_JOVE_H
#error "only to be included inline in jove/jove.h"
#endif

//
// create an instance, withot tracking.
//
template <typename T, typename... Args>
T *ip_construct(segment_manager_t &sm, Args &&...args) {
  void *mem = sm.allocate_aligned(sizeof(T), alignof(T));
  assert(mem);

  return new (mem) T(std::forward<Args>(args)...);
}

template <typename T>
void ip_destroy(segment_manager_t &sm, T *p) {
  p->~T();
  sm.deallocate(p);
}
