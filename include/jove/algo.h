#pragma once
#include <algorithm>

namespace jove {

template <typename _ExecutionPolicy, typename Iter, typename Pred, typename Proc>
constexpr
void for_each_if(_ExecutionPolicy &&__exec, Iter first, Iter last, Pred pred, Proc proc) {
  std::for_each(std::forward<_ExecutionPolicy>(__exec), first, last,
                [pred, proc](auto &&elem) {
                  if (pred(elem)) {
                    proc(elem);
                  }
                });
}

template <typename Iter, typename Pred, typename Proc>
constexpr
void for_each_if(Iter first, Iter last, Pred pred, Proc proc) {
  std::for_each(first, last,
                [pred, proc](auto &&elem) {
                  if (pred(elem)) {
                    proc(elem);
                  }
                });
}

}
