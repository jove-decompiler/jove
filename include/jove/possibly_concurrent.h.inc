#ifndef IN_JOVE_H
#error "only to be included inline in jove/jove.h"
#endif

template <bool Node, typename Key, typename Value>
using possibly_concurrent_node_or_flat_map_choose_alloc =
    std::conditional_t<Node,
                       boost::interprocess::node_allocator<std::pair<const Key, Value>, segment_manager_t>,
                       boost::interprocess::allocator<std::pair<const Key, Value>, segment_manager_t>>;

template <bool Node, typename Key, typename Hash, typename Value>
using possibly_concurrent_node_or_flat_set_choose_alloc = std::conditional_t<
    Node,
    boost::interprocess::node_allocator<Key, segment_manager_t>,
    boost::interprocess::allocator<Key, segment_manager_t>>;

//
// The concurrent and non-concurrent data structures can be move-constructed
// from one another.
//
template <bool MT, bool Node, typename Spin, typename Key, typename Value, typename Hash, typename Equal>
using possibly_concurrent_node_or_flat_map = std::conditional_t<
    MT,
    std::conditional_t<Node,
                       boost::concurrent_node_map<Key, Value, Hash, Equal, possibly_concurrent_node_or_flat_map_choose_alloc<Node, Key, Value>, Spin>,
                       boost::concurrent_flat_map<Key, Value, Hash, Equal, possibly_concurrent_node_or_flat_map_choose_alloc<Node, Key, Value>, Spin>>,

    std::conditional_t<Node,
                       boost::unordered_node_map<Key, Value, Hash, Equal, possibly_concurrent_node_or_flat_map_choose_alloc<Node, Key, Value>>,
                       boost::unordered_flat_map<Key, Value, Hash, Equal, possibly_concurrent_node_or_flat_map_choose_alloc<Node, Key, Value>>>>;

template <bool MT, bool Node, typename Key, typename Hash, typename Equal>
using possibly_concurrent_node_or_flat_set = std::conditional_t<
    MT,
    std::conditional_t<Node,
                       boost::concurrent_node_set<Key, Hash, Equal, possibly_concurrent_node_or_flat_set_choose_alloc<Node, Key, Hash, Equal>>,
                       boost::concurrent_flat_set<Key, Hash, Equal, possibly_concurrent_node_or_flat_set_choose_alloc<Node, Key, Hash, Equal>>>,
    std::conditional_t<Node,
                       boost::unordered_node_set<Key, Hash, Equal, possibly_concurrent_node_or_flat_set_choose_alloc<Node, Key, Hash, Equal>>,
                       boost::unordered_flat_set<Key, Hash, Equal, possibly_concurrent_node_or_flat_set_choose_alloc<Node, Key, Hash, Equal>>>>;

template <bool MT, typename Spin, typename... Params>
using possibly_concurrent_node_set =
    std::conditional_t<MT, boost::concurrent_node_set<Params..., Spin>,
                       boost::unordered_node_set<Params...>>;

template <bool MT, bool Node, typename T>
struct PossiblyConcurrentNodeOrFlatSet_t {
  possibly_concurrent_node_or_flat_set<MT, Node, T, boost::hash<T>,
                                       std::equal_to<T>>
      set;

  explicit PossiblyConcurrentNodeOrFlatSet_t(segment_manager_t *sm) noexcept
      : set(sm) {}

  explicit PossiblyConcurrentNodeOrFlatSet_t(
      const PossiblyConcurrentNodeOrFlatSet_t<MT, Node, T> &other) noexcept
      : set(other.set) {}

  template <bool MT2>
  explicit PossiblyConcurrentNodeOrFlatSet_t(
      PossiblyConcurrentNodeOrFlatSet_t<MT2, Node, T> &&other) noexcept
      : set(std::move(other.set)) {}

  template <class _ExecutionPolicy>
  void ForEach(_ExecutionPolicy &&__exec,
               std::function<void(const T &)> proc) const {
    if constexpr (MT)
      set.cvisit_all(std::forward<_ExecutionPolicy>(__exec), proc);
    else
      std::for_each(set.cbegin(), set.cend(), proc);
  }

  void ForEach(std::function<void(const T &)> proc) const {
    ForEach(std::execution::seq, proc);
  }

  // returns false iff proc ever returns false
  bool ForEachWhile(std::function<bool(const T &)> proc) const {
    if constexpr (MT) {
      return set.cvisit_while([&](const T &X) -> bool {
        if (!proc(X))
          return false;
        return true;
      });
    } else {
      auto it = set.cbegin();
      auto it_end = set.cend();
      for (; it != it_end; ++it) {
        const T &X = *it;
        if (!proc(X))
          return false;
      }
      return true;
    }
  }
  bool AnyOf(std::function<bool(const T &)> proc) const {
    if constexpr (MT) {
      bool res = false;
      set.cvisit_while([&](const T &X) -> bool {
        if (proc(X)) {
          res = true;
          return false;
        }
        return true;
      });
      return res;
    } else {
      return std::any_of(set.cbegin(), set.cend(), proc);
    }
  }
  bool AllOf(std::function<bool(const T &)> proc) const {
    if constexpr (MT) {
      bool res = true;
      set.cvisit_while([&](const T &X) -> bool {
        if (!proc(X)) {
          res = false;
          return false;
        }
        return true;
      });
      return res;
    } else {
      return std::all_of(set.cbegin(), set.cend(), proc);
    }
  }
  T Front(void) const {
    if constexpr (MT) {
      T res;
      if (likely(!set.cvisit_while([&](const T &X) -> bool {
            res = X;
            return false;
          }))) {
        return res;
      } else {
        assert(false);
        __builtin_trap();
        __builtin_unreachable();
      }
    } else {
      assert(!set.empty());
      return *set.cbegin();
    }
  }

  template <class ResT>
  ResT Accumulate(ResT init,
                  std::function<ResT(const ResT &, const T &)> op) const {
    if constexpr (MT) {
      set.cvisit_all([&](const T &X) -> void { init = op(std::move(init), X); });
      return init;
    } else {
      return std::accumulate(set.cbegin(), set.cend(), init, op);
    }
  }

  bool empty(void) const {
    return set.empty();
  }

  unsigned size(void) const {
    return set.size();
  }

  bool Insert(const T &X) {
    if constexpr (MT)
      return set.insert(X);
    else
      return set.insert(X).second;
  }
};
