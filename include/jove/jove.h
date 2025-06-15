#ifndef JOVE_H
#define JOVE_H
#define IN_JOVE_H

#include "jove/tcg.h"
#ifdef __cplusplus
#include "jove/macros.h"
#include "jove/constants.h"
#include "jove/types.h"
#include "jove/racy.h"
#include "jove/algo.h"

#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/breadth_first_search.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <boost/unordered/unordered_flat_map.hpp>
#include <boost/unordered/unordered_node_map.hpp>
#include <boost/unordered/unordered_node_set.hpp>
#include <boost/unordered/unordered_flat_set.hpp>
#include <boost/unordered/concurrent_flat_map.hpp>
#include <boost/unordered/concurrent_flat_set.hpp>
#include <boost/unordered/concurrent_node_set.hpp>
#include <boost/unordered/concurrent_node_map.hpp>
#include <boost/interprocess/smart_ptr/unique_ptr.hpp>
#include <boost/smart_ptr/detail/spinlock.hpp>
#include <boost/interprocess/containers/map.hpp>
#include <boost/interprocess/containers/flat_map.hpp>
#include <boost/interprocess/containers/flat_set.hpp>
#include <boost/interprocess/containers/set.hpp>
#include <boost/interprocess/containers/string.hpp>
#include <boost/interprocess/containers/vector.hpp>
#include <boost/interprocess/containers/deque.hpp>
#include <boost/interprocess/managed_mapped_file.hpp>
#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/sync/interprocess_mutex.hpp>
#include <boost/interprocess/sync/interprocess_sharable_mutex.hpp>
#include <boost/interprocess/sync/interprocess_upgradable_mutex.hpp>
#include <boost/interprocess/sync/scoped_lock.hpp>
#include <boost/interprocess/sync/sharable_lock.hpp>
#include <boost/interprocess/sync/upgradable_lock.hpp>
#include <boost/interprocess/sync/interprocess_condition.hpp>
#include <boost/interprocess/allocators/private_node_allocator.hpp>
#include <boost/interprocess/allocators/private_adaptive_pool.hpp>
#include <boost/interprocess/allocators/node_allocator.hpp>
#include <boost/preprocessor/cat.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/optional.hpp>
#include <boost/dynamic_bitset.hpp>
#include <boost/container/static_vector.hpp>
#include <boost/container/vector.hpp>
#include <boost/container/deque.hpp>
#include <boost/container/allocator.hpp>
#include <boost/container/adaptive_pool.hpp>
#include <boost/container/node_allocator.hpp>
#include <boost/container/scoped_allocator.hpp>
#include <boost/array.hpp>
#include <boost/iterator/counting_iterator.hpp>

#include <algorithm>
#include <atomic>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <execution>
#include <functional>
#include <iomanip>
#include <ranges>
#include <limits>
#include <map>
#include <new>
#include <numeric>
#include <shared_mutex>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <tuple>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace llvm {
namespace object {
class Binary;
}
}

namespace jove {

#include "jove/target.h.inc"

template <bool MT, bool MinSize>
class explorer_t;
template <bool MT, bool MinSize>
struct jv_base_t;
template <bool MT, bool MinSize>
struct binary_base_t;

#include "jove/terminator.h.inc"
#include "jove/mt.h.inc"
#include "jove/possibly_concurrent.h.inc"
#include "jove/index.h.inc"
#include "jove/deque.h.inc"
#include "jove/adjacency_list.h.inc"
#include "jove/table.h.inc"
#include "jove/addr_intvl.h.inc"

struct allocates_basic_block_t {
  basic_block_index_t BBIdx = invalid_basic_block_index;

  explicit allocates_basic_block_t () noexcept = default;

  // allocates (creates) new basic block in binary, stores index
  template <bool MT, bool MinSize>
  explicit inline allocates_basic_block_t(binary_base_t<MT, MinSize> &b,
                                          basic_block_index_t &store,
                                          taddr_t Addr) noexcept;

  explicit operator basic_block_index_t() const { return BBIdx; }
};

template <bool MT, bool Node>
using bbbmap_t = possibly_concurrent_node_or_flat_map<
    MT, Node, std::true_type /* Spin */, taddr_t, allocates_basic_block_t,
    boost::hash<taddr_t>, std::equal_to<taddr_t>>;

typedef boost::interprocess::map<
    addr_intvl, basic_block_index_t, addr_intvl_cmp,
    boost::interprocess::private_adaptive_pool<
        std::pair<const addr_intvl, basic_block_index_t>, segment_manager_t>>
    bbmap_t; /* _private_ adaptive pool because of heavyweight bbmap_lock */

template <bool MT>
struct BBMap_t : public ip_base_rw_accessible_nospin<MT> {
  boost::interprocess::offset_ptr<segment_manager_t> sm_ = nullptr;
  boost::interprocess::offset_ptr<bbmap_t> map = nullptr;

  BBMap_t() = delete;
  explicit BBMap_t(jv_file_t &jv_file) noexcept
      : sm_(jv_file.get_segment_manager()),
        map(jv_file.construct<bbmap_t>(boost::interprocess::anonymous_instance)(
            jv_file.get_segment_manager())) {}

  template <bool MT2>
  explicit BBMap_t(BBMap_t<MT2> &&other) noexcept {
    auto e_lck_us = this->exclusive_access();
    auto e_lck = other.exclusive_access();

    std::swap(sm_, other.sm_);
    std::swap(map, other.map);

    assert(sm_);
    assert(map);
  }

  ~BBMap_t() noexcept {
    if (map) {
      assert(sm_);
      sm_->destroy_ptr(map.get());
      map = nullptr;
    }
  }

  template <bool MT2>
  BBMap_t<MT> &operator=(BBMap_t<MT2> &&other) noexcept {
    if constexpr (MT == MT2) {
      if (this == &other)
        return *this;
    }

    auto e_lck_us = this->exclusive_access();
    auto e_lck = other.exclusive_access();

    std::swap(sm_, other.sm_);
    std::swap(map, other.map);

    assert(sm_);
    assert(map);

    return *this;
  }

  BBMap_t(const BBMap_t &) = delete;
  BBMap_t &operator=(const BBMap_t &) = delete;
};

struct allocates_function_t {
  function_index_t FIdx = invalid_function_index;

  explicit allocates_function_t() noexcept = default;

  // allocates (creates) new function in binary, stores index
  template <bool MT, bool MinSize>
  explicit allocates_function_t(binary_base_t<MT, MinSize> &b,
                                function_index_t &store) noexcept;

  explicit operator function_index_t() const { return FIdx; }
};

template <bool MT, bool Node>
using fnmap_t = possibly_concurrent_node_or_flat_map<
    MT, Node, std::true_type /* Spin */, taddr_t, allocates_function_t,
    boost::hash<taddr_t>, std::equal_to<taddr_t>>;

size_t jvDefaultInitialSize(void);

#include "jove/atomic.h.inc"

struct bb_analysis_t {
  struct {
    /* let def_B be the set of variables defined (i.e. definitely */
    /* assigned values) in B prior to any use of that variable in B */
    tcg_global_set_t def;

    /* let use_B be the set of variables whose values may be used in B */
    /* prior to any definition of the variable */
    tcg_global_set_t use;
  } live;

  struct {
    /* the set of globals assigned values in B */
    tcg_global_set_t def;
  } reach;

  std::atomic<bool> Stale = true;

  bb_analysis_t() noexcept = default;

  bb_analysis_t(tcg_global_set_t live_def,
                tcg_global_set_t live_use,
                tcg_global_set_t reach_def) noexcept
      : live{.def = live_def, .use = live_use}, reach{.def = reach_def} {}

  bb_analysis_t(const bb_analysis_t &other) noexcept
      : live(other.live), reach(other.reach) {
    Stale.store(other.Stale.load(std::memory_order_relaxed),
                std::memory_order_relaxed);
  }

  bb_analysis_t(bb_analysis_t &&other) noexcept
      : live(other.live), reach(other.reach) {
    Stale.store(other.Stale.load(std::memory_order_relaxed),
                std::memory_order_relaxed);
  }

  bb_analysis_t &operator=(bb_analysis_t &&other) noexcept {
    live = other.live;
    reach = other.reach;
    Stale.store(other.Stale.load(std::memory_order_relaxed),
                std::memory_order_relaxed);
    return *this;
  }

  bb_analysis_t &operator=(const bb_analysis_t &other) noexcept {
    live = other.live;
    reach = other.reach;
    Stale.store(other.Stale.load(std::memory_order_relaxed),
                std::memory_order_relaxed);
    return *this;
  }

  struct straight_line_t {
    std::atomic<bool> Stale = true;

    basic_block_index_t BBIdx = invalid_basic_block_index;
    taddr_t Addr = uninit_taddr;
    taddr_t TermAddr = uninit_taddr;
    TERMINATOR TermType = TERMINATOR::UNKNOWN;
    boost::container::static_vector<basic_block_index_t, 2> adj;
    boost::container::flat_set<addr_intvl, addr_intvl_cmp> addrng;
  };

private:
  void moveFrom(bb_analysis_t &&other) {
    live = other.live;
    reach = other.reach;

    Stale.store(other.Stale.load(std::memory_order_relaxed),
                std::memory_order_relaxed);
  }
};

template <bool MT, bool MinSize>
void UnserializeJV(jv_base_t<MT, MinSize> &out, jv_file_t &, std::istream &, bool text);
struct UnlockTool;

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

template <bool MT, bool MinSize>
using DynTargets_t =
    PossiblyConcurrentNodeOrFlatSet_t<MT, MinSize, dynamic_target_t>;

struct bbprop_t : public ip_mt_base_rw_accessible_nospin {
  struct pub_t : public ip_mt_base_rw_accessible_nospin {
    std::atomic<bool> is = false;

    pub_t() noexcept = default;

    pub_t(pub_t &&other) noexcept {
      is.store(other.is.load(std::memory_order_relaxed),
               std::memory_order_relaxed);
    }

    pub_t(const pub_t &other) noexcept {
      is.store(other.is.load(std::memory_order_relaxed),
               std::memory_order_relaxed);
    }

    pub_t &operator=(pub_t &&other) noexcept {
      is.store(other.is.load(std::memory_order_relaxed),
               std::memory_order_relaxed);
      return *this;
    }

    pub_t &operator=(const pub_t &other) noexcept {
      is.store(other.is.load(std::memory_order_relaxed),
               std::memory_order_relaxed);
      return *this;
    }
  } pub;

  bool Speculative = false;

  taddr_t Addr = uninit_taddr;
  uint32_t Size = ~uint32_t(0);

  struct {
    taddr_t Addr = uninit_taddr;
    TERMINATOR Type = TERMINATOR::UNKNOWN;

    struct {
      function_index_t Target = invalid_function_index;
    } _call;

    struct {
      bool IsLj = false;
    } _indirect_jump;

    struct {
    } _indirect_call;

    struct {
      bool Returns = false;
    } _return;
  } Term;

  AtomicOffsetPtr<void> pDynTargets;
  boost::interprocess::offset_ptr<segment_manager_t> sm_ = nullptr;

  bool Sj = false;
  bb_analysis_t Analysis;

  template <bool MT, bool MinSize>
  boost::optional<const DynTargets_t<MT, MinSize> &>
  getDynamicTargets(void) const {
    if (const void *const p = pDynTargets.Load(std::memory_order_relaxed)) {
    uintptr_t p_addr = reinterpret_cast<uintptr_t>(p);
    bool TheMT      = !!(p_addr & 1u);
    bool TheMinSize = !!(p_addr & 2u);

    assert(TheMT == MT);
    assert(TheMinSize == MinSize);

    p_addr &= ~3ULL;
      return *reinterpret_cast<const DynTargets_t<MT, MinSize> *>(p_addr);
    }

    return boost::none;
  }

  template <bool MT, bool MinSize>
  boost::optional<const DynTargets_t<MT, MinSize> &>
  getDynamicTargets(const jv_base_t<MT, MinSize> &) const {
    return getDynamicTargets<MT, MinSize>();
  }

  class Parents_t {
    AtomicOffsetPtr<const ip_func_index_vec> _p;

    friend UnlockTool;
    friend bbprop_t;
    friend allocates_basic_block_t;

    //
    // friends
    //
#define VALUES1 ((true))((false))
#define VALUES2 ((true))((false))
#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)
#define DO_FRIEND(r, product)                                                  \
  friend void UnserializeJV<GET_VALUE(BOOST_PP_SEQ_ELEM(1, product)),          \
                            GET_VALUE(BOOST_PP_SEQ_ELEM(0, product))>(         \
      jv_base_t<GET_VALUE(BOOST_PP_SEQ_ELEM(1, product)),                      \
                GET_VALUE(BOOST_PP_SEQ_ELEM(0, product))> &,                   \
      jv_file_t &, std::istream &, bool);
    BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_FRIEND, (VALUES1)(VALUES2))
#undef DO_FRIEND
#undef GET_VALUE
#undef VALUES1
#undef VALUES2

    Parents_t() noexcept = default;

    template <bool MT>
    void set(const ip_func_index_vec &x) {
      _p.Store(&x, MT ? std::memory_order_release : std::memory_order_relaxed);
    }

  public:
    template <bool MT>
    const ip_func_index_vec &get(void) const {
      const ip_func_index_vec *res =
          _p.Load(MT ? std::memory_order_acquire : std::memory_order_relaxed);
      assert(res);
      return *res;
    }

    template <bool MT>
    bool empty(void) const {
      return get<MT>().empty();
    }

    template <bool MT>
    bool contains(function_index_t FIdx) const {
      auto &vec = get<MT>();

      return std::binary_search(vec.cbegin(), vec.cend(), FIdx);
    }

    template <bool MT, bool MinSize>
    void insert(function_index_t, binary_base_t<MT, MinSize> &);
  } Parents;

  bool hasDynTarget(void) const {
    return !!pDynTargets.Load(std::memory_order_relaxed);
  }

  template <bool MT, bool MinSize>
  bool insertDynTarget(binary_index_t ThisBIdx,
                       const dynamic_target_t &,
                       jv_file_t &,
                       jv_base_t<MT, MinSize> &);


  bool IsSingleInstruction(void) const { return Addr == Term.Addr; }

  template <bool MT, bool MinSize>
  void InvalidateAnalysis(jv_base_t<MT, MinSize> &,
                          binary_base_t<MT, MinSize> &);

  explicit bbprop_t() noexcept = default;

  explicit bbprop_t(bbprop_t &&other) noexcept = default;
  bbprop_t &operator=(bbprop_t &&other) noexcept = default;

  ~bbprop_t() noexcept;

  explicit bbprop_t(const bbprop_t &) = delete;
  bbprop_t &operator=(const bbprop_t &) = delete;

private:
  template <bool MT, bool MinSize>
  bool doInsertDynTarget(const dynamic_target_t &,
                         jv_file_t &,
                         jv_base_t<MT, MinSize> &);
};

template <bool MT>
using ip_icfg_base_t =
ip_adjacency_list<MT,
                  true /* Spin */,
                  true /* PointUnique */,
                  boost::setS_ip,     /* OutEdgeList */
                  boost::dequeS_ip,   /* VertexList */
                  boost::directedS,   /* Directed */
                  bbprop_t,           /* VertexProperties */
                  boost::no_property, /* EdgeProperties */
                  boost::no_property, /* GraphProperties */
                  boost::listS_ip>;   /* EdgeList */

#if 0
typedef ip_icfg_base_t<true> ip_icfg_t;

typedef ip_icfg_t::type interprocedural_control_flow_graph_t;

typedef interprocedural_control_flow_graph_t icfg_t;

typedef interprocedural_control_flow_graph_t::vertex_descriptor basic_block_t;
typedef interprocedural_control_flow_graph_t::edge_descriptor control_flow_t;

typedef std::vector<basic_block_t> basic_block_vec_t;

static inline bb_t NullBasicBlock(void) {
  return boost::graph_traits<
      interprocedural_control_flow_graph_t>::null_vertex();
}

template <bool MT, bool MinSize>
using bb_vec_t =
    std::vector<typename ip_icfg_base_t<MT>::vertex_descriptor>;
#endif

constexpr bool IsDefinitelyTailCall(const auto &ICFG, auto bb) {
  auto &bbprop = ICFG[bb];

  assert(bbprop.Term.Type == TERMINATOR::INDIRECT_JUMP); /* catch bugs */
  //WARN_ON(ICFG.out_degree<L>(bb) > 0); /* catch bugs */
  return bbprop.hasDynTarget();
}

constexpr bool IsAmbiguousIndirectJump(const auto &ICFG, auto bb) {
  auto &bbprop = ICFG[bb];

  assert(bbprop.Term.Type == TERMINATOR::INDIRECT_JUMP); /* catch bugs */
  return bbprop.hasDynTarget() && ICFG.out_degree(bb) > 0;
}

constexpr bool IsExitBlock(const auto &ICFG, auto bb) {
  auto T = ICFG[bb].Term.Type;

  return T == TERMINATOR::RETURN ||
        (T == TERMINATOR::INDIRECT_JUMP &&
         IsDefinitelyTailCall(ICFG, bb));
}

//
// encounter new basic block retbb that RETURNS:
//   for each f s.t. retbb \in f:
//     => f returns
//     for each caller of f:
//       if tail:
//         => is exit block
//         for each _f s.t. caller \in _f:
//           => _f returns
//           ...
//       else:
//         => caller returns
//           => new code
//           ...
//
// encounter dynamic target that returns
//   if tail:
//     => is exit block
//     for each _f s.t. caller \in _f:
//       => _f returns
//       ...
//   else:
//     => caller returns
//       => new code
//       ...
//
typedef std::pair<binary_index_t, taddr_t> caller_t;

template <bool MT, bool MinSize>
constexpr block_t block_for_caller_in_binary(const caller_t &caller,
                                             const binary_base_t<MT, MinSize> &caller_b,
                                             const jv_base_t<MT, MinSize> &jv) {
  const binary_index_t BIdx = caller.first;

  assert(is_binary_index_valid(BIdx));

  const binary_base_t<MT, MinSize> &b = jv.Binaries.at(BIdx);
  const basic_block_index_t BBIdx = ({
    auto s_lck_bbmap = b.BBMap.shared_access();

    index_of_basic_block_at_address(caller.second, b);
  });

  return block_t(BIdx, BBIdx);
}

struct ip_call_graph_node_properties_t : public ip_mt_base_rw_accessible_spin {
  dynamic_target_t X;
};

template <bool MT>
using ip_call_graph_base_t =
    ip_adjacency_list<MT,
                      false /* !Spin */,
                      true /* PointUnique */,
                      boost::setS_ip,                  /* OutEdgeList */
                      boost::dequeS_ip,                /* VertexList */
                      boost::directedS,                /* Directed */
                      ip_call_graph_node_properties_t, /* VertexProperties */
                      boost::no_property,              /* EdgeProperties */
                      boost::no_property,              /* GraphProperties */
                      boost::vecS_ip>;                 /* EdgeList */

//
// until we come up with a cleaner source code patch for boost-graph (to make it
// work with boost interprocess (stateful) allocators), we need to do this for
// now XXX FIXME
//
template <bool MT, bool Spin, bool PointUnique, typename... Args>
static inline void hack_interprocess_graph(
    ip_adjacency_list<MT, Spin, PointUnique, Args...> &ip_adj) {
  auto &x = ip_adj.container();

  __builtin_memset_inline(&x.m_property, 0, sizeof(x.m_property));
}

template <bool MT, bool MinSize>
using Callers_t = PossiblyConcurrentNodeOrFlatSet_t<MT, MinSize, caller_t>;

struct function_t {
  bool Speculative = false;

  binary_index_t BIdx = invalid_binary_index;
  function_index_t Idx = invalid_function_index;
  basic_block_index_t Entry = invalid_basic_block_index;

  AtomicOffsetPtr<void> pCallers;
  boost::interprocess::offset_ptr<segment_manager_t> sm_ = nullptr;

  bool hasCaller(void) const noexcept {
    return !!pCallers.Load(std::memory_order_relaxed);
  }

  template <bool MT, bool MinSize>
  unsigned numCallers(const jv_base_t<MT, MinSize> &) const noexcept {
    using OurCallers_t = Callers_t<MT, MinSize>;

    if (void *const p = pCallers.Load(std::memory_order_relaxed)) {
      uintptr_t p_addr = reinterpret_cast<uintptr_t>(p);
      bool TheMT      = !!(p_addr & 1u);
      bool TheMinSize = !!(p_addr & 2u);
      p_addr &= ~3ULL;

      assert(TheMT == MT);
      assert(TheMinSize == MinSize);

      const OurCallers_t &Callers = *reinterpret_cast<OurCallers_t *>(p_addr);
      return Callers.size();
    }

    return 0;
  }

  template <bool MT, bool MinSize>
  bool AddCaller(jv_file_t &, const caller_t &) noexcept;

  template <bool MT, bool MinSize>
  bool AddCaller(jv_file_t &jv_file,
		 const jv_base_t<MT, MinSize> &,
                 const caller_t &caller) noexcept {
    return AddCaller<MT, MinSize>(jv_file, caller);
  }

  template <bool MT, bool MinSize, class _ExecutionPolicy>
  void
  ForEachCaller(_ExecutionPolicy &&__exec,
		const jv_base_t<MT, MinSize> &,
                std::function<void(const caller_t &)> proc) const noexcept {
    using OurCallers_t = Callers_t<MT, MinSize>;

    if (void *const p = pCallers.Load(std::memory_order_relaxed)) {
      uintptr_t p_addr = reinterpret_cast<uintptr_t>(p);
      bool TheMT      = !!(p_addr & 1u);
      bool TheMinSize = !!(p_addr & 2u);
      p_addr &= ~3ULL;

      assert(TheMT == MT);
      assert(TheMinSize == MinSize);

      const OurCallers_t &Callers = *reinterpret_cast<OurCallers_t *>(p_addr);
      Callers.ForEach(std::forward<_ExecutionPolicy>(__exec), proc);
    }
  }

  template <bool MT, bool MinSize>
  void
  ForEachCaller(const jv_base_t<MT, MinSize> &jv,
                std::function<void(const caller_t &)> proc) const noexcept {
    ForEachCaller(std::execution::seq, jv, proc);
  }

  struct ReverseCGVertHolder_t : public ip_mt_base_accessible_spin {
    std::atomic<call_graph_index_t> Idx = invalid_call_graph_index;

    ReverseCGVertHolder_t() noexcept = default;

    explicit ReverseCGVertHolder_t(ReverseCGVertHolder_t &&other) noexcept {
      moveFrom(std::move(other));
    }

    ReverseCGVertHolder_t &operator=(ReverseCGVertHolder_t &&other) noexcept {
      if (this != &other)
        moveFrom(std::move(other));
      return *this;
    }

  private:
    void moveFrom(ReverseCGVertHolder_t &&other) noexcept {
      Idx.store(other.Idx.load(std::memory_order_relaxed),
                std::memory_order_relaxed);
      other.Idx.store(invalid_call_graph_index, std::memory_order_relaxed);
    }
  } ReverseCGVertIdxHolder;

  template <bool MT, bool MinSize>
  ip_call_graph_base_t<MT>::vertex_descriptor
  ReverseCGVert(jv_base_t<MT, MinSize> &);

  struct Analysis_t {
    tcg_global_set_t args;
    tcg_global_set_t rets;

    std::atomic<bool> Stale = true;

    Analysis_t() noexcept = default;

    Analysis_t(Analysis_t &&other) noexcept
        : args(other.args), rets(other.rets) {
      moveFrom(std::move(other));
    }

    Analysis_t &operator=(Analysis_t &&other) noexcept {
      moveFrom(std::move(other));
      return *this;
    }

private:
    void moveFrom(Analysis_t &&other) {
      args = other.args;
      rets = other.rets;

      Stale.store(other.Stale.load(std::memory_order_relaxed),
                  std::memory_order_relaxed);
    }

  } Analysis;

  bool IsABI = false;
  bool IsSignalHandler = false;
  bool Returns = false;

  void InvalidateAnalysis(void) {
    this->Analysis.Stale.store(true, std::memory_order_relaxed);
  }

  template <bool MT, bool MinSize>
  explicit function_t(binary_base_t<MT, MinSize> &, function_index_t) noexcept;
  explicit function_t(segment_manager_t *) noexcept; /* XXX used by serialize */
  explicit function_t() = delete;

  explicit function_t(function_t &&) noexcept = default;
  function_t &operator=(function_t &&) noexcept = default;

  ~function_t() noexcept;

  explicit function_t(const function_t &) = delete;
  function_t &operator=(const function_t &) = delete;
};

#include "jove/objdump.h.inc"

template <bool MT>
struct FunctionIndexVecs {
  ip_func_index_vec_set<MT> FIdxVecs;

  explicit FunctionIndexVecs(segment_manager_t *sm) noexcept : FIdxVecs(sm) {}

  template <bool MT2>
  explicit FunctionIndexVecs(FunctionIndexVecs<MT2> &&other) noexcept
      : FIdxVecs(std::move(other.FIdxVecs)) {}

  template <bool MT2>
  FunctionIndexVecs &operator=(FunctionIndexVecs<MT2> &&other) noexcept {
    if constexpr (MT == MT2) {
      if (this == &other)
        return *this;
    }

    FIdxVecs = std::move(other.FIdxVecs);
    return *this;
  }

  const ip_func_index_vec &Add(ip_func_index_vec &&vec) noexcept {
    if constexpr (MT) {
      const ip_func_index_vec *vecptr = nullptr;
      auto grab = [&](const ip_func_index_vec &vec) -> void { vecptr = &vec; };

      FIdxVecs.insert_and_cvisit(boost::move(vec), grab, grab);

      assert(vecptr);
      return *vecptr;
    } else {
      return *FIdxVecs.insert(boost::move(vec)).first;
    }
  }
};

template <bool MT, bool MinSize>
struct binary_analysis_t {
  using bb_t = typename ip_icfg_base_t<MT>::vertex_descriptor;
  using bb_vec_t = std::vector<bb_t>;

  boost::interprocess::offset_ptr<segment_manager_t> sm_ = nullptr;

  function_index_t EntryFunction = invalid_function_index;

  //
  // references to function_t will never be invalidated.
  //
  ip_deque<function_t,
           boost::interprocess::private_node_allocator<function_t,
                                                       segment_manager_t>,
           MT, true, true>
      Functions;

  //
  // references to bbprop_t will never be invalidated
  // (although their fields are subject to change: see explorer_t::split() in
  //  core/explore.cpp)
  ip_icfg_base_t<MT> ICFG;

  binary_analysis_t() = delete;
  binary_analysis_t(const binary_analysis_t &) = delete;
  binary_analysis_t &operator=(const binary_analysis_t &) = delete;

  explicit binary_analysis_t(jv_file_t &jv_file) noexcept
      : sm_(jv_file.get_segment_manager()),
        Functions(jv_file),
        ICFG(jv_file),
        objdump(jv_file.get_segment_manager()) {
    hack_interprocess_graph(ICFG);
  }

  template <bool MT2>
  explicit binary_analysis_t(binary_analysis_t<MT2, MinSize> &&other) noexcept
      : sm_(other.sm_),
        EntryFunction(std::move(other.EntryFunction)),
        Functions(std::move(other.Functions)),
        ICFG(std::move(other.ICFG)),
        objdump(std::move(other.objdump)) {
    hack_interprocess_graph(ICFG);

    if constexpr (MT != MT2)
      move_stuff();
  }

  template <bool MT2>
  binary_analysis_t<MT, MinSize> &
  operator=(binary_analysis_t<MT2, MinSize> &&other) noexcept {
    if constexpr (MT == MT2) {
      if (this == &other)
        return *this;
    }

    sm_ = other.sm_;
    EntryFunction = other.EntryFunction;
    Functions = std::move(other.Functions);
    ICFG = std::move(other.ICFG);
    objdump = std::move(other.objdump);

    if constexpr (MT != MT2)
      move_stuff();

    return *this;
  }

  /*** may have use in future ***/
  void addSymDynTarget(const std::string &sym, dynamic_target_t X) {}
  void addRelocDynTarget(taddr_t A, dynamic_target_t X) {}
  void addIFuncDynTarget(taddr_t A, dynamic_target_t X) {}

  typedef objdump_output_t<boost::interprocess::allocator<
      unsigned long /* FIXME */, segment_manager_t>>
      objdump_output_type;

  objdump_output_type objdump;

private:
  void move_stuff(void) noexcept;
  void move_callers(void) noexcept;
  void move_dyn_targets(void) noexcept;
};

template <bool MT, bool MinSize>
struct binary_base_t {
  using bb_t = typename ip_icfg_base_t<MT>::vertex_descriptor;
  using bb_vec_t = std::vector<bb_t>;

  binary_index_t Idx = invalid_binary_index;

  bbbmap_t<MT, MinSize> bbbmap;

  BBMap_t<MT> BBMap;
  fnmap_t<MT, MinSize> fnmap;

  ip_string Name;
  ip_string Data;
  hash_t Hash;

  bool IsDynamicLinker = false;
  bool IsExecutable = false;
  bool IsVDSO = false;
  bool IsPIC = false;
  bool IsDynamicallyLoaded = false;

  ip_unique_ptr<ip_func_index_vec> EmptyFIdxVec;
  FunctionIndexVecs<MT> FIdxVecs;

  binary_analysis_t<MT, MinSize> Analysis;

  void InvalidateBasicBlockAnalyses(void);

  //
  // we thought this was a goto, but now we know it's definitely a tail
  // call. translate all sucessors as functions, then store them into the
  // dynamic targets set for this bb. afterwards, delete the edges in the
  // ICFG that would originate from this basic block.
  //
  bool FixAmbiguousIndirectJump(taddr_t TermAddr,
                                explorer_t<MT, MinSize> &,
                                llvm::object::Binary &,
                                jv_file_t &,
                                jv_base_t<MT, MinSize> &);

  std::string_view data(void) const {
    return std::string_view(Data.data(), Data.size());
  }

  std::string name_str(void) const {
    return un_ips(Name);
  }

  const char *path(void) const {
    assert(is_file());

    return Name.c_str();
  }

  std::string path_str(void) const {
    assert(is_file());

    return un_ips(Name);
  }

  bool is_file(void) const {
    return !Name.empty() && Name.front() == '/';
  }

  bool is_anonymous_mapping(void) const {
    return Name.empty();
  }

  bool is_special_mapping(void) const {
    return !Name.empty() && Name.front() == '[' && Name.back() == ']';
  }

  segment_manager_t *get_segment_manager(void) const {
    return Analysis.Functions.container().get_allocator().get_segment_manager();
  }

  explicit binary_base_t(jv_file_t &jv_file,
                         binary_index_t Idx = invalid_binary_index) noexcept
      : Idx(Idx),
        bbbmap(jv_file.get_segment_manager()),
        BBMap(jv_file),
        fnmap(jv_file.get_segment_manager()),
        Name(jv_file.get_segment_manager()),
        Data(jv_file.get_segment_manager()),
        EmptyFIdxVec(boost::interprocess::make_managed_unique_ptr(
            jv_file.construct<ip_func_index_vec>(
                boost::interprocess::anonymous_instance)(
                jv_file.get_segment_manager()),
            jv_file)),
        FIdxVecs(jv_file.get_segment_manager()),
        Analysis(jv_file) {}

  template <bool MT2>
  explicit binary_base_t(binary_base_t<MT2, MinSize> &&other) noexcept
      : Idx(other.Idx),

        bbbmap(std::move(other.bbbmap)),
        BBMap(std::move(other.BBMap)),
        fnmap(std::move(other.fnmap)),

        Name(std::move(other.Name)),
        Data(std::move(other.Data)),
        Hash(std::move(other.Hash)),

        IsDynamicLinker(other.IsDynamicLinker),
        IsExecutable(other.IsExecutable),
        IsVDSO(other.IsVDSO),
        IsPIC(other.IsPIC),
        IsDynamicallyLoaded(other.IsDynamicallyLoaded),

        EmptyFIdxVec(std::move(other.EmptyFIdxVec)),
        FIdxVecs(std::move(other.FIdxVecs)),

        Analysis(std::move(other.Analysis)) {}

  template <bool MT2>
  binary_base_t &operator=(binary_base_t<MT2, MinSize> &&other) noexcept {
    if constexpr (MT == MT2) {
      if (this == &other)
        return *this;
    }

    Idx = other.Idx;

    bbbmap = std::move(other.bbbmap);
    BBMap = std::move(other.BBMap);
    fnmap = std::move(other.fnmap);

    Name = std::move(other.Name);
    Data = std::move(other.Data);
    Hash = other.Hash;

    IsDynamicLinker = other.IsDynamicLinker;
    IsExecutable = other.IsExecutable;
    IsVDSO = other.IsVDSO;
    IsPIC = other.IsPIC;
    IsDynamicallyLoaded = other.IsDynamicallyLoaded;

    EmptyFIdxVec = std::move(other.EmptyFIdxVec);
    FIdxVecs = std::move(other.FIdxVecs);

    Analysis = std::move(other.Analysis);

    return *this;
  }

  explicit binary_base_t() = delete;
  explicit binary_base_t(const binary_base_t &) = delete;
  binary_base_t &operator=(const binary_base_t &) = delete;
};

struct objdump_exception {
  taddr_t Addr;
  objdump_exception(taddr_t Addr) : Addr(Addr) {}
};

template <bool MT, bool MinSize>
allocates_basic_block_t::allocates_basic_block_t(binary_base_t<MT, MinSize> &b,
                                                 basic_block_index_t &store,
                                                 taddr_t Addr) noexcept {
#if 0
  if (unlikely(b.Analysis.objdump.is_addr_bad(Addr)))
    throw objdump_exception(Addr);
#endif

  auto &ICFG = b.Analysis.ICFG;

  basic_block_index_t Idx = ICFG.index_of_add_vertex(b.get_segment_manager());
  auto &bbprop = ICFG[ICFG.template vertex<false>(Idx)];
  bbprop.Addr = Addr;
  bbprop.Parents.template set<false>(*b.EmptyFIdxVec);

  if constexpr (MT) {
    bool success;
    success = bbprop.pub.mtx.try_lock();
    rassert(success && "allocates_basic_block_t: BUG1");

    success = bbprop.mtx.try_lock();
    rassert(success && "allocates_basic_block_t: BUG2");
  }

  store = Idx;
  BBIdx = Idx;
}

template <bool MT, bool MinSize>
allocates_function_t::allocates_function_t(binary_base_t<MT, MinSize> &b,
                                           function_index_t &store) noexcept {
  auto &Functions = b.Analysis.Functions;

  {
    auto e_lck = Functions.exclusive_access();

    auto &x = Functions.container();

    FIdx = x.size();
    x.emplace_back(b, FIdx);
  }

  store = FIdx;
}

typedef std::function<std::string_view(void)> get_data_t;

struct AddOptions_t;

struct adds_binary_t {
  binary_index_t BIdx = invalid_basic_block_index;

  explicit adds_binary_t() noexcept = default;
  explicit adds_binary_t(binary_index_t BIdx) noexcept : BIdx(BIdx) {
    assert(is_binary_index_valid(BIdx));
  }

  // adds new binary, stores index
  template <bool MT, bool MinSize>
  explicit adds_binary_t(binary_index_t &out,
                         jv_file_t &,
                         jv_base_t<MT, MinSize> &,
                         const explorer_t<MT, MinSize> &,
                         get_data_t get_data,
                         const hash_t &,
                         const char *name,
                         const AddOptions_t &) noexcept(false);

  // adds new binary, stores index
  template <bool MT, bool MinSize>
  explicit adds_binary_t(binary_index_t &out,
                         jv_file_t &,
                         jv_base_t<MT, MinSize> &,
                         binary_base_t<MT, MinSize> &&) noexcept;

  explicit operator binary_index_t() const { return BIdx; }
};

struct JoveBinaryHash {
  using is_avalanching = std::true_type;

  std::size_t operator()(const hash_t &x) const noexcept {
    static_assert(sizeof(std::size_t) <= sizeof(hash_t));

    return *reinterpret_cast<const std::size_t *>(&x);
  }
};

struct cached_hash_t {
  hash_t h;

  struct {
    int64_t sec = 0, nsec = 0;
  } mtime;

  cached_hash_t(const char *path, std::string &file_contents, hash_t &out);

  void Update(const char *path, std::string &file_contents);
};

template <bool MT, bool Node>
using ip_cached_hashes_type =
    possibly_concurrent_node_or_flat_map<MT, Node, std::false_type /* !Spin */,
                                         ip_string, cached_hash_t,
                                         ip_string_hash_t, ip_string_equal_t>;

template <bool MT, bool Node>
using ip_hash_to_binary_map_type =
    possibly_concurrent_node_or_flat_map<MT, Node, std::false_type /* !Spin */,
                                         hash_t, adds_binary_t, JoveBinaryHash,
                                         std::equal_to<hash_t>>;

template <bool MT, bool Node>
using ip_name_to_binaries_map_type =
    possibly_concurrent_node_or_flat_map<MT, Node, std::false_type /* !Spin */,
                                         ip_string, ip_binary_index_set,
                                         ip_string_hash_t, ip_string_equal_t>;

template <bool MT, bool MinSize>
using on_newbin_proc_t = std::function<void(binary_base_t<MT, MinSize> &)>;

struct AddOptions_t {
  bool Objdump = false;
  unsigned VerbosityLevel = 0;

  bool IsVerbose(void) const { return VerbosityLevel >= 1; };
  bool IsVeryVerbose(void) const { return VerbosityLevel >= 2; };
};

template <bool MT, bool MinSize>
using ip_binary_deque_t =
    ip_deque<binary_base_t<MT, MinSize>,
             boost::interprocess::private_node_allocator<
                 binary_base_t<MT, MinSize>, segment_manager_t>,
             MT, true, true>;

template <bool MT, bool MinSize>
using ip_binary_table_t = table_t<binary_base_t<MT, MinSize>, MaxBinaries>;

template <bool MT, bool MinSize>
struct jv_base_t {
  using jv_t = jv_base_t<MT, MinSize>;
  using binary_t = binary_base_t<MT, MinSize>;
  using bb_t = typename ip_icfg_base_t<MT>::vertex_descriptor;

  boost::interprocess::offset_ptr<segment_manager_t> sm_ = nullptr;

  //
  // references to binary_t will never be invalidated.
  //
  std::conditional_t<MinSize,
    ip_binary_deque_t<MT, MinSize>,
    ip_binary_table_t<MT, MinSize>> Binaries;

  struct Analysis_t {
    ip_call_graph_base_t<MT> ReverseCallGraph;

    explicit Analysis_t(jv_file_t &jv_file) noexcept
        : ReverseCallGraph(jv_file) {
      hack_interprocess_graph(ReverseCallGraph);
    }

    explicit Analysis_t(Analysis_t &&other) noexcept
        : ReverseCallGraph(std::move(other.ReverseCallGraph)) {
      hack_interprocess_graph(ReverseCallGraph);
    }

    explicit Analysis_t(
        typename jv_base_t<!MT, MinSize>::Analysis_t &&other) noexcept
        : ReverseCallGraph(std::move(other.ReverseCallGraph)) {
      hack_interprocess_graph(ReverseCallGraph);
    }
  } Analysis;

  ip_hash_to_binary_map_type<MT, MinSize> hash_to_binary;
  ip_cached_hashes_type<MT, MinSize> cached_hashes; /* NOT serialized */

  ip_name_to_binaries_map_type<MT, MinSize> name_to_binaries;

  template <typename Proc>
  void ForEachNameToBinaryEntry(Proc proc) const {
    if constexpr (MT)
      name_to_binaries.cvisit_all(proc);
    else
      std::for_each(name_to_binaries.begin(),
                    name_to_binaries.end(),
                    proc);
  }

  template <typename... Args>
  bool TryHashToBinaryEmplace(Args &&...args) {
    if constexpr (MT)
      return hash_to_binary.try_emplace(std::forward<Args>(args)...);
    else
      return hash_to_binary.try_emplace(std::forward<Args>(args)...).second;
  }

  template <typename... Args>
  bool TryNameToBinariesEmplace(Args &&...args) {
    if constexpr (MT)
      return name_to_binaries.try_emplace(std::forward<Args>(args)...);
    else
      return name_to_binaries.try_emplace(std::forward<Args>(args)...).second;
  }

  void InvalidateFunctionAnalyses(void);

  void clear(bool everything = false);

  segment_manager_t *get_segment_manager(void) const {
    assert(sm_);
    return sm_.get();
  }

  explicit jv_base_t(jv_file_t &jv_file) noexcept
      : sm_(jv_file.get_segment_manager()),
        Binaries(jv_file),
        Analysis(jv_file),
        hash_to_binary(jv_file.get_segment_manager()),
        cached_hashes(jv_file.get_segment_manager()),
        name_to_binaries(jv_file.get_segment_manager()) {}

  explicit jv_base_t(jv_base_t<MT, MinSize> &&other,
                     jv_file_t &jv_file) noexcept
      : sm_(jv_file.get_segment_manager()),
        Binaries(std::move(other.Binaries)),
        Analysis(std::move(other.Analysis)),
        hash_to_binary(std::move(other.hash_to_binary)),
        cached_hashes(std::move(other.cached_hashes)),
        name_to_binaries(std::move(other.name_to_binaries)) {}

  explicit jv_base_t(jv_base_t<!MT, MinSize> &&other,
                     jv_file_t &jv_file) noexcept;

  explicit jv_base_t() = delete;
  explicit jv_base_t(const jv_base_t &) = delete;
  jv_base_t &operator=(const jv_base_t &) = delete;
  jv_base_t &operator=(jv_base_t &&) = delete;

  ~jv_base_t() noexcept = default;

  std::optional<binary_index_t> LookupByHash(const hash_t &h);
  bool LookupByName(const char *name, binary_index_set &out);

  template <bool ValidatePath = true>
  std::pair<binary_index_t, bool> AddFromPath(
      const explorer_t<MT, MinSize> &,
      jv_file_t &,
      const char *path,
      on_newbin_proc_t<MT, MinSize> on_newbin = [](binary_t &) {},
      const AddOptions_t &Options = AddOptions_t());

  std::pair<binary_index_t, bool>
  Add(jv_file_t &, binary_t &&, on_newbin_proc_t<MT, MinSize> on_newbin = [](binary_t &) {});

  std::pair<binary_index_t, bool>
  AddFromData(const explorer_t<MT, MinSize> &,
              jv_file_t &,
              std::string_view data,
              const char *name = nullptr,
              on_newbin_proc_t<MT, MinSize> on_newbin = [](binary_t &) {},
              const AddOptions_t &Options = AddOptions_t());

  unsigned NumBinaries(void) {
    return Binaries.size();
  }

private:
  void LookupAndCacheHash(hash_t &out, const char *path,
                          std::string &file_contents);

  std::pair<binary_index_t, bool>
  AddFromDataWithHash(const explorer_t<MT, MinSize> &,
                      jv_file_t &,
                      get_data_t,
                      const hash_t &,
                      const char *name,
                      on_newbin_proc_t<MT, MinSize>,
                      const AddOptions_t &);

  void initialize_all_binary_indices(void) noexcept {
    if constexpr (MinSize) {
      auto first = boost::iterators::counting_iterator<std::size_t>(0);
      auto last  = boost::iterators::counting_iterator<std::size_t>(Binaries.size());

      std::for_each(maybe_par_unseq,
                    first,
                    last,
                    [&](size_t i) { Binaries.at(i).Idx = i; });
    } else {
      std::for_each(maybe_par_unseq,
                    Binaries.begin(),
                    Binaries.begin() + MaxBinaries, [&](auto &b) {
                      b.Idx = &b - Binaries.begin();
                    });
    }
  }

public:
  template <bool MT2, bool MinSize2>
  void DoAdd(binary_base_t<MT2, MinSize2> &,
             explorer_t<MT2, MinSize2> &,
             llvm::object::Binary &,
             const AddOptions_t &);

  friend adds_binary_t;

  void fixup(jv_file_t &);
  void fixup_binary(jv_file_t &, const binary_index_t);
};

static inline std::string description_of_block(const bbprop_t &bbprop,
                                               bool zero_padded = true) {
  std::string res;

  res += "[";
  res += taddr2str(bbprop.Addr, zero_padded);
  res += ", ";
  res += taddr2str(bbprop.Addr + bbprop.Size, zero_padded);
  res += ")";

  return res;
}

template <bool MT>
constexpr auto basic_block_of_index(basic_block_index_t BBIdx,
                                    const ip_icfg_base_t<MT> &ICFG) {
  if (unlikely(!is_basic_block_index_valid(BBIdx)))
    throw std::runtime_error("basic_block_of_index: invalid index");

  if (unlikely(BBIdx >= ICFG.num_vertices()))
    throw std::runtime_error("basic_block_of_index: out-of-range index");

  return ICFG.vertex(BBIdx);
}

template <bool MT, bool MinSize>
constexpr auto basic_block_of_index(basic_block_index_t BBIdx,
                                    const binary_base_t<MT, MinSize> &b) {
  const auto &ICFG = b.Analysis.ICFG;
  return basic_block_of_index(BBIdx, ICFG);
}

static inline bbmap_t::iterator bbmap_find(bbmap_t &bbmap, addr_intvl intvl) {
  return intvl_map_find(bbmap, intvl);
}

static inline bbmap_t::const_iterator bbmap_find(const bbmap_t &bbmap, addr_intvl intvl) {
  return intvl_map_find(bbmap, intvl);
}

static inline bbmap_t::iterator bbmap_find(bbmap_t &bbmap, taddr_t Addr) {
  return intvl_map_find(bbmap, Addr);
}

static inline bbmap_t::const_iterator bbmap_find(const bbmap_t &bbmap,
                                                 taddr_t Addr) {
  return intvl_map_find(bbmap, Addr);
}

constexpr bool bbmap_contains(bbmap_t &bbmap, addr_intvl intvl) {
  return intvl_map_contains(bbmap, intvl);
}

constexpr bool bbmap_contains(bbmap_t &bbmap, taddr_t Addr) {
  return intvl_map_contains(bbmap, Addr);
}

template <typename Value>
constexpr auto bbmap_add(bbmap_t &bbmap,
                         addr_intvl intvl,
                         Value &&val) {
  return intvl_map_add(bbmap, intvl, std::move(val));
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Proc>
constexpr
void for_each_binary(_ExecutionPolicy &&__exec,
                     jv_base_t<MT, MinSize> &jv,
                     Proc proc) {
  std::for_each(std::forward<_ExecutionPolicy>(__exec),
                jv.Binaries.begin(),
                jv.Binaries.end(),
                proc);
}

template <bool MT, bool MinSize, class Proc>
constexpr void for_each_binary(jv_base_t<MT, MinSize> &jv, Proc proc) {
  std::for_each(jv.Binaries.begin(),
                jv.Binaries.end(),
                proc);
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Proc>
constexpr
void for_each_binary(_ExecutionPolicy &&__exec,
                     const jv_base_t<MT, MinSize> &jv,
                     Proc proc) {
  std::for_each(std::forward<_ExecutionPolicy>(__exec),
                jv.Binaries.begin(),
                jv.Binaries.end(),
                proc);
}

template <bool MT, bool MinSize, class Proc>
constexpr void for_each_binary(const jv_base_t<MT, MinSize> &jv, Proc proc) {
  std::for_each(jv.Binaries.begin(),
                jv.Binaries.end(),
                proc);
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Pred, class Proc>
constexpr
void for_each_binary_if(_ExecutionPolicy &&__exec,
                        jv_base_t<MT, MinSize> &jv,
                        Pred pred,
                        Proc proc) {
  for_each_if(std::forward<_ExecutionPolicy>(__exec),
              jv.Binaries.begin(),
              jv.Binaries.end(),
              pred, proc);
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Pred, class Proc>
constexpr
void for_each_binary_if(_ExecutionPolicy &&__exec,
                        const jv_base_t<MT, MinSize> &jv,
                        Pred pred,
                        Proc proc) {
  for_each_if(std::forward<_ExecutionPolicy>(__exec),
              jv.Binaries.begin(),
              jv.Binaries.end(),
              pred, proc);
}

template <bool MT, bool MinSize, class Pred, class Proc>
constexpr
void for_each_binary_if(jv_base_t<MT, MinSize> &jv, Pred pred, Proc proc) {
  for_each_if(jv.Binaries.begin(),
              jv.Binaries.end(),
              pred, proc);
}

template <bool MT, bool MinSize, class Pred, class Proc>
constexpr
void for_each_binary_if(const jv_base_t<MT, MinSize> &jv, Pred pred, Proc proc) {
  for_each_if(jv.Binaries.begin(),
              jv.Binaries.end(),
              pred, proc);
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Proc>
constexpr
void for_each_function(_ExecutionPolicy &&__exec,
                       jv_base_t<MT, MinSize> &jv,
                       Proc proc) {
  for_each_binary(std::forward<_ExecutionPolicy>(__exec),
                  jv,
                  [&__exec, proc](auto &b) {
    std::for_each(std::forward<_ExecutionPolicy>(__exec),
                  b.Analysis.Functions.begin(),
                  b.Analysis.Functions.end(),
                  [&b, proc](auto &f) { proc(f, b); });
  });
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Proc>
constexpr
void for_each_function(_ExecutionPolicy &&__exec,
                       const jv_base_t<MT, MinSize> &jv,
                       Proc proc) {
  for_each_binary(std::forward<_ExecutionPolicy>(__exec),
                  jv,
                  [&__exec, proc](auto &b) {
    std::for_each(std::forward<_ExecutionPolicy>(__exec),
                  b.Analysis.Functions.begin(),
                  b.Analysis.Functions.end(),
                  [&b, proc](auto &f) { proc(f, b); });
  });
}

template <bool MT, bool MinSize, class Proc>
constexpr void for_each_function(jv_base_t<MT, MinSize> &jv, Proc proc) {
  for_each_binary(jv,
                  [proc](auto &b) {
    std::for_each(b.Analysis.Functions.begin(),
                  b.Analysis.Functions.end(),
                  [&b, proc](auto &f) { proc(f, b); });
  });
}

template <bool MT, bool MinSize, class Proc>
constexpr void for_each_function(const jv_base_t<MT, MinSize> &jv, Proc proc) {
  for_each_binary(jv,
                  [proc](auto &b) {
    std::for_each(b.Analysis.Functions.begin(),
                  b.Analysis.Functions.end(),
                  [&b, proc](auto &f) { proc(f, b); });
  });
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Pred, class Proc>
constexpr void for_each_function_if_in_binary(_ExecutionPolicy &&__exec,
                                              binary_base_t<MT, MinSize> &b,
                                              Pred pred, Proc proc) {
  for_each_if(std::forward<_ExecutionPolicy>(__exec),
              b.Analysis.Functions.begin(),
              b.Analysis.Functions.end(), pred, proc);
}

template <bool MT, bool MinSize, class Pred, class Proc>
constexpr
void for_each_function_if_in_binary(binary_base_t<MT, MinSize> &b,
                                    Pred pred,
                                    Proc proc) {
  for_each_if(b.Analysis.Functions.begin(),
              b.Analysis.Functions.end(), pred, proc);
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Pred, class Proc>
constexpr void for_each_function_if_in_binary(_ExecutionPolicy &&__exec,
                                              const binary_base_t<MT, MinSize> &b,
                                              Pred pred, Proc proc) {
  for_each_if(std::forward<_ExecutionPolicy>(__exec),
              b.Analysis.Functions.begin(),
              b.Analysis.Functions.end(), pred, proc);
}

template <bool MT, bool MinSize, class Pred, class Proc>
constexpr
void for_each_function_if_in_binary(const binary_base_t<MT, MinSize> &b,
                                    Pred pred,
                                    Proc proc) {
  for_each_if(b.Analysis.Functions.begin(),
              b.Analysis.Functions.end(), pred, proc);
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Proc>
constexpr void for_each_function_in_binary(_ExecutionPolicy &&__exec,
                                           binary_base_t<MT, MinSize> &b,
                                           Proc proc) {
  std::for_each(std::forward<_ExecutionPolicy>(__exec),
                b.Analysis.Functions.begin(),
                b.Analysis.Functions.end(), proc);
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Proc>
constexpr void for_each_function_in_binary(_ExecutionPolicy &&__exec,
                                           const binary_base_t<MT, MinSize> &b,
                                           Proc proc) {
  std::for_each(std::forward<_ExecutionPolicy>(__exec),
                b.Analysis.Functions.begin(),
                b.Analysis.Functions.end(), proc);
}

template <bool MT, bool MinSize, class Proc>
constexpr void for_each_function_in_binary(binary_base_t<MT, MinSize> &b,
                                           Proc proc) {
  std::for_each(b.Analysis.Functions.begin(),
                b.Analysis.Functions.end(), proc);
}

template <bool MT, bool MinSize, class Proc>
constexpr
void for_each_function_in_binary(const binary_base_t<MT, MinSize> &b,
                                 Proc proc) {
  std::for_each(b.Analysis.Functions.begin(),
                b.Analysis.Functions.end(), proc);
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Proc>
constexpr void
for_each_function_in_binary(_ExecutionPolicy &&__exec,
                            binary_analysis_t<MT, MinSize> &Analysis,
                            Proc proc) {
  std::for_each(std::forward<_ExecutionPolicy>(__exec),
                Analysis.Functions.begin(),
                Analysis.Functions.end(), proc);
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Proc>
constexpr void
for_each_function_in_binary(_ExecutionPolicy &&__exec,
                            const binary_analysis_t<MT, MinSize> &Analysis,
                            Proc proc) {
  std::for_each(std::forward<_ExecutionPolicy>(__exec),
                Analysis.Functions.begin(),
                Analysis.Functions.end(), proc);
}

template <bool MT, bool MinSize, class Proc>
constexpr void
for_each_function_in_binary(binary_analysis_t<MT, MinSize> &Analysis,
                            Proc proc) {
  std::for_each(Analysis.Functions.begin(),
                Analysis.Functions.end(), proc);
}

template <bool MT, bool MinSize, class Proc>
constexpr
void for_each_function_in_binary(const binary_analysis_t<MT, MinSize> &Analysis,
                                 Proc proc) {
  std::for_each(Analysis.Functions.begin(),
                Analysis.Functions.end(), proc);
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Pred, class Proc>
constexpr void for_each_function_if(_ExecutionPolicy &&__exec,
                                    jv_base_t<MT, MinSize> &jv,
                                    Pred pred,
                                    Proc proc) {
  for_each_binary(std::forward<_ExecutionPolicy>(__exec), jv,
                  [&__exec, pred, proc](auto &b) {
                    for_each_if(std::forward<_ExecutionPolicy>(__exec),
                                b.Analysis.Functions.begin(),
                                b.Analysis.Functions.end(), pred,
                                [&b, proc](auto &f) { proc(f, b); });
                  });
}

template <bool MT, bool MinSize, class Pred, class Proc>
constexpr void for_each_function_if(jv_base_t<MT, MinSize> &jv,
                                    Pred pred,
                                    Proc proc) {
  for_each_binary(jv, [pred, proc](auto &b) {
    for_each_if(b.Analysis.Functions.begin(),
                b.Analysis.Functions.end(), pred,
                [&b, proc](auto &f) { proc(f, b); });
  });
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Proc>
constexpr void for_each_basic_block(_ExecutionPolicy &&__exec,
                                    jv_base_t<MT, MinSize> &jv, Proc proc) {
  for_each_binary(
      std::forward<_ExecutionPolicy>(__exec),
      jv, [&__exec, proc](auto &b) {
        auto it_pair = b.Analysis.ICFG.vertices();

        std::for_each(std::forward<_ExecutionPolicy>(__exec), it_pair.first,
                      it_pair.second, [&b, proc](auto bb) { proc(b, bb); });
      });
}

template <bool MT, bool MinSize, class Proc>
constexpr void for_each_basic_block(jv_base_t<MT, MinSize> &jv, Proc proc) {
  for_each_binary(jv, [proc](auto &b) {
    auto it_pair = b.Analysis.ICFG.vertices();

    std::for_each(it_pair.first,
                  it_pair.second,
                  [&b, proc](auto bb) { proc(b, bb); });
  });
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Proc>
static inline
void for_each_basic_block_in_binary(_ExecutionPolicy &&__exec,
                                    binary_base_t<MT, MinSize> &b,
                                    Proc proc) {
  auto it_pair = b.Analysis.ICFG.vertices();

  std::for_each(std::forward<_ExecutionPolicy>(__exec),
                it_pair.first,
                it_pair.second, [proc](auto bb) { proc(bb); });
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Proc>
static inline
void for_each_basic_block_in_binary(_ExecutionPolicy &&__exec,
                                    const binary_base_t<MT, MinSize> &b,
                                    Proc proc) {
  auto it_pair = b.Analysis.ICFG.vertices();

  std::for_each(std::forward<_ExecutionPolicy>(__exec),
                it_pair.first,
                it_pair.second, [proc](auto bb) { proc(bb); });
}

template <bool MT, bool MinSize, class Proc>
static inline
void for_each_basic_block_in_binary(binary_base_t<MT, MinSize> &b, Proc proc) {
  auto it_pair = b.Analysis.ICFG.vertices();

  std::for_each(it_pair.first,
                it_pair.second,
                [proc](auto bb) { proc(bb); });
}

template <bool MT, bool MinSize, class Proc>
static inline void
for_each_basic_block_in_binary(const binary_base_t<MT, MinSize> &b, Proc proc) {
  auto it_pair = b.Analysis.ICFG.vertices();

  std::for_each(it_pair.first,
                it_pair.second,
                [proc](auto bb) { proc(bb); });
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Proc>
static inline void
for_each_basic_block_in_binary(_ExecutionPolicy &&__exec,
                               const binary_analysis_t<MT, MinSize> &Analysis,
                               Proc proc) {
  auto it_pair = Analysis.ICFG.vertices();

  std::for_each(std::forward<_ExecutionPolicy>(__exec),
                it_pair.first,
                it_pair.second, [proc](auto bb) { proc(bb); });
}

template <bool MT, bool MinSize, class Proc>
static inline void
for_each_basic_block_in_binary(binary_analysis_t<MT, MinSize> &Analysis,
                               Proc proc) {
  auto it_pair = Analysis.ICFG.vertices();

  std::for_each(it_pair.first,
                it_pair.second,
                [proc](auto bb) { proc(bb); });
}

template <bool MT, bool MinSize, class Proc>
static inline void
for_each_basic_block_in_binary(const binary_analysis_t<MT, MinSize> &Analysis,
                               Proc proc) {
  auto it_pair = Analysis.ICFG.vertices();

  std::for_each(it_pair.first,
                it_pair.second,
                [proc](auto bb) { proc(bb); });
}

template <bool MT>
constexpr basic_block_index_t
index_of_basic_block(const ip_icfg_base_t<MT> &ICFG, auto bb) {
  return ICFG.index(bb);
}

template <bool MT, bool MinSize>
constexpr basic_block_index_t
index_of_basic_block(const binary_base_t<MT, MinSize> &b, auto bb) {
  return index_of_basic_block(b.Analysis.ICFG, bb);
}

constexpr binary_index_t binary_index_of_function(const function_t &f) {
  binary_index_t res = f.BIdx;
  assert(is_binary_index_valid(res));
  return res;
}

template <bool MT, bool MinSize>
[[deprecated]] /* use binary_index_of_function(f) */
constexpr binary_index_t
binary_index_of_function(const function_t &f,
                         const jv_base_t<MT, MinSize> &jv) {
  return binary_index_of_function(f);
}

template <bool MT, bool MinSize>
constexpr binary_index_t index_of_binary(const binary_base_t<MT, MinSize> &b) {
  binary_index_t res = b.Idx;
  assert(is_binary_index_valid(res));
  return res;
}

template <bool MT, bool MinSize>
[[deprecated]] /* use index_of_binary(b) */
constexpr binary_index_t
index_of_binary(const binary_base_t<MT, MinSize> &b,
                const jv_base_t<MT, MinSize> &jv) {
  return index_of_binary(b);
}

constexpr function_index_t index_of_function(const function_t &f) {
  function_index_t res = f.Idx;
  assert(is_function_index_valid(res));
  return res;
}

template <bool MT, bool MinSize>
[[deprecated]] /* use index_of_function(f) */
constexpr function_index_t
index_of_function_in_binary(const function_t &f,
                            const binary_base_t<MT, MinSize> &b) {
  return index_of_function(f);
}

template <bool MT, bool MinSize>
constexpr const binary_base_t<MT, MinSize> &
binary_of_function(const function_t &f, const jv_base_t<MT, MinSize> &jv) {
  binary_index_t BIdx = f.BIdx;
  assert(is_binary_index_valid(BIdx));
  return jv.Binaries.at(BIdx);
}

template <bool MT, bool MinSize>
constexpr binary_base_t<MT, MinSize> &
binary_of_function(function_t &f, jv_base_t<MT, MinSize> &jv) {
  binary_index_t BIdx = f.BIdx;
  assert(is_binary_index_valid(BIdx));
  return jv.Binaries.at(BIdx);
}

template <bool MT, bool MinSize>
constexpr const function_t &
function_of_target(dynamic_target_t X, const jv_base_t<MT, MinSize> &jv) {
  return jv.Binaries.at(X.first).Analysis.Functions.at(X.second);
}

template <bool MT, bool MinSize>
constexpr function_t &function_of_target(dynamic_target_t X,
                                         jv_base_t<MT, MinSize> &jv) {
  return jv.Binaries.at(X.first).Analysis.Functions.at(X.second);
}

constexpr dynamic_target_t target_of_function(const function_t &f) {
  return {binary_index_of_function(f), index_of_function(f)};
}

template <bool MT, bool MinSize>
static inline void basic_blocks_of_function_at_block(
    typename ip_icfg_base_t<MT>::vertex_descriptor entry,
    const binary_base_t<MT, MinSize> &b,
    std::vector<typename ip_icfg_base_t<MT>::vertex_descriptor> &out) {
  const auto &ICFG = b.Analysis.ICFG;

  struct bb_visitor : public boost::default_dfs_visitor {
    std::vector<typename ip_icfg_base_t<MT>::vertex_descriptor> &out;

    bb_visitor(
        std::vector<typename ip_icfg_base_t<MT>::vertex_descriptor>
            &out)
        : out(out) {}

    void
    discover_vertex(typename ip_icfg_base_t<MT>::vertex_descriptor bb,
                    const typename ip_icfg_base_t<MT>::type &) const {
      out.push_back(bb);
    }
  };

  out.clear();
  out.reserve(ICFG.num_vertices());

  bb_visitor vis(out);
  ICFG.depth_first_visit(entry, vis);
}

template <bool MT, bool MinSize>
static inline void basic_blocks_of_function(
    const function_t &f,
    const binary_base_t<MT, MinSize> &b,
    std::vector<typename ip_icfg_base_t<MT>::vertex_descriptor> &out) {

  const auto &ICFG = b.Analysis.ICFG;

  basic_blocks_of_function_at_block(basic_block_of_index(f.Entry, ICFG), b, out);
}

template <bool MT, bool MinSize>
static inline void exit_basic_blocks_of_function(
    const function_t &f,
    const binary_base_t<MT, MinSize> &b,
    const std::vector<typename ip_icfg_base_t<MT>::vertex_descriptor> &bbvec,
    std::vector<typename ip_icfg_base_t<MT>::vertex_descriptor> &out) {
  const auto &ICFG = b.Analysis.ICFG;

  out.reserve(bbvec.size());

  std::copy_if(
      bbvec.begin(),
      bbvec.end(), std::back_inserter(out),
      [&](typename ip_icfg_base_t<MT>::vertex_descriptor bb) -> bool {
        return IsExitBlock(ICFG, bb);
      });
}

template <bool MT, bool MinSize>
static inline bool does_function_return_fast(
    const ip_icfg_base_t<MT> &ICFG,
    const std::vector<typename ip_icfg_base_t<MT>::vertex_descriptor>
        &bbvec) {
  return std::any_of(
      bbvec.begin(),
      bbvec.end(),
      [&](typename ip_icfg_base_t<MT>::vertex_descriptor bb) -> bool {
        return IsExitBlock(ICFG, bb);
      });
}

template <bool MT, bool MinSize>
static inline bool does_function_at_block_return(
    typename ip_icfg_base_t<MT>::vertex_descriptor entry,
    const binary_base_t<MT, MinSize> &b) {
  std::vector<typename ip_icfg_base_t<MT>::vertex_descriptor> bbvec;
  basic_blocks_of_function_at_block(entry, b, bbvec);

  const auto &ICFG = b.Analysis.ICFG;

  return std::any_of(
      bbvec.begin(),
      bbvec.end(),
      [&](typename ip_icfg_base_t<MT>::vertex_descriptor bb) -> bool {
        return IsExitBlock(ICFG, bb);
      });
}

template <bool MT, bool MinSize>
static inline bool does_function_return(const function_t &f,
                                        const binary_base_t<MT, MinSize> &b) {
  return does_function_at_block_return(basic_block_of_index(f.Entry, b), b);
}

template <bool MT, bool MinSize>
static inline bool IsLeafFunction(
    const function_t &f,
    const binary_base_t<MT, MinSize> &b,
    const std::vector<typename ip_icfg_base_t<MT>::vertex_descriptor>
        &bbvec,
    const std::vector<typename ip_icfg_base_t<MT>::vertex_descriptor>
        &exit_bbvec) {
  const auto &ICFG = b.Analysis.ICFG;

  if (!std::none_of(bbvec.begin(),
                    bbvec.end(),
                    [&](typename ip_icfg_base_t<MT>::vertex_descriptor bb) -> bool {
                      auto T = ICFG[bb].Term.Type;
                      return (T == TERMINATOR::INDIRECT_JUMP &&
                              ICFG.out_degree(bb) == 0)
                           || T == TERMINATOR::INDIRECT_CALL
                           || T == TERMINATOR::CALL;
                    }))
    return false;

  return std::all_of(
      exit_bbvec.begin(),
      exit_bbvec.end(),
      [&](typename ip_icfg_base_t<MT>::vertex_descriptor bb) -> bool {
        auto T = ICFG[bb].Term.Type;
        return T == TERMINATOR::RETURN || T == TERMINATOR::UNREACHABLE;
      });
}

template <bool MT, bool MinSize>
static inline bool IsFunctionSetjmp(
    const function_t &f,
    const binary_base_t<MT, MinSize> &b,
    const std::vector<typename ip_icfg_base_t<MT>::vertex_descriptor>
        &bbvec) {
  const auto &ICFG = b.Analysis.ICFG;

  return std::any_of(
      bbvec.begin(),
      bbvec.end(),
      [&](typename ip_icfg_base_t<MT>::vertex_descriptor bb) -> bool {
        return ICFG[bb].Sj;
      });
}

template <bool MT, bool MinSize>
static inline bool IsFunctionLongjmp(
    const function_t &f,
    const binary_base_t<MT, MinSize> &b,
    const std::vector<typename ip_icfg_base_t<MT>::vertex_descriptor>
        &bbvec) {
  const auto &ICFG = b.Analysis.ICFG;

  return std::any_of(
      bbvec.begin(),
      bbvec.end(),
      [&](typename ip_icfg_base_t<MT>::vertex_descriptor bb) -> bool {
        auto &Term = ICFG[bb].Term;
        return Term.Type == TERMINATOR::INDIRECT_JUMP &&
               Term._indirect_jump.IsLj;
      });
}

template <bool MT, bool MinSize>
static inline basic_block_index_t
index_of_basic_block_at_address(taddr_t Addr,
                                const binary_base_t<MT, MinSize> &b) {
  bbmap_t *pmap = b.BBMap.map.get();
  assert(pmap);
  bbmap_t &bbmap = *pmap;
  auto it = bbmap_find(bbmap, Addr);
  if (unlikely(it == bbmap.end()))
    throw std::runtime_error("index_of_basic_block_at_address: no block @ " + taddr2str(Addr));
  return (*it).second;
}

template <bool MT, bool MinSize>
static inline basic_block_index_t
index_of_basic_block_starting_at_address(taddr_t Addr,
                                         const binary_base_t<MT, MinSize> &b) {
  basic_block_index_t res = invalid_basic_block_index;
  bool found;
  if constexpr (MT) {
    found = b.bbbmap.cvisit(Addr, [&](const auto &x) {
      res = static_cast<basic_block_index_t>(x.second);
    });
  } else {
    auto it = b.bbbmap.find(Addr);
    found = it != b.bbbmap.end();
    if (found)
      res = static_cast<basic_block_index_t>((*it).second);
  }

  if (unlikely(!found))
    throw std::runtime_error("index_of_basic_block_starting_at_address: no block @ " + taddr2str(Addr));

  return res;
}

template <bool MT, bool MinSize>
static inline typename ip_icfg_base_t<MT>::vertex_descriptor
basic_block_starting_at_address(taddr_t Addr,
                                const binary_base_t<MT, MinSize> &b) {
  return basic_block_of_index(index_of_basic_block_starting_at_address(Addr, b), b);
}

template <bool MT, bool MinSize>
static inline typename ip_icfg_base_t<MT>::vertex_descriptor
basic_block_at_address(taddr_t Addr, const binary_base_t<MT, MinSize> &b) {
  return basic_block_of_index(index_of_basic_block_at_address(Addr, b), b);
}

template <bool MT, bool MinSize>
static inline bool
exists_basic_block_at_address(taddr_t Addr,
                              const binary_base_t<MT, MinSize> &b) {
  bbmap_t *const pbbmap = b.BBMap.map.get();
  assert(pbbmap);
  bbmap_t &bbmap = *pbbmap;

  return bbmap_contains(bbmap, Addr);
}

template <bool MT, bool MinSize>
static inline bool
exists_basic_block_starting_at_address(taddr_t Addr,
                                       const binary_base_t<MT, MinSize> &b) {
  return b.bbbmap.contains(Addr);
}

template <bool MT, bool MinSize>
static inline function_index_t
index_of_function_at_address(const binary_base_t<MT, MinSize> &b,
                             taddr_t Addr) {
  function_index_t FIdx = invalid_function_index;
  if constexpr (MT) {
    b.fnmap.cvisit(Addr, [&](const auto &x) { FIdx = static_cast<function_index_t>(x.second); });
  } else {
    auto it = b.fnmap.find(Addr);
    if (it != b.fnmap.end())
      FIdx = static_cast<function_index_t>((*it).second);
  }
  assert(is_function_index_valid(FIdx));

  return FIdx;
}

template <bool MT, bool MinSize>
static inline const function_t &
function_at_address(const binary_base_t<MT, MinSize> &b, taddr_t Addr) {
  return b.Analysis.Functions.at(index_of_function_at_address(b, Addr));
}

template <bool MT, bool MinSize>
static inline function_t &function_at_address(binary_base_t<MT, MinSize> &b,
                                              taddr_t Addr) {
  return b.Analysis.Functions.at(index_of_function_at_address(b, Addr));
}

template <bool MT, bool MinSize>
static inline bool
exists_function_at_address(const binary_base_t<MT, MinSize> &b, taddr_t Addr) {
  return b.fnmap.contains(Addr);
}

// NOTE: this function excludes tail calls.
template <bool MT, bool MinSize>
static inline bool
exists_indirect_jump_at_address(taddr_t Addr,
                                const binary_base_t<MT, MinSize> &binary) {
  if (exists_basic_block_at_address(Addr, binary)) {
    const auto &ICFG = binary.Analysis.ICFG;
    typename ip_icfg_base_t<MT>::vertex_descriptor bb =
        basic_block_at_address(Addr, binary);
    if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP &&
        !ICFG[bb].hasDynTarget())
      return true;
  }

  return false;
}

template <bool MT, bool MinSize>
static inline taddr_t address_of_basic_block(
    typename ip_icfg_base_t<MT>::vertex_descriptor bb,
    const ip_icfg_base_t<MT> &ICFG) {
  return ICFG[bb].Addr;
}

template <bool MT, bool MinSize>
static inline taddr_t address_of_basic_block(
    typename ip_icfg_base_t<MT>::vertex_descriptor bb,
    const binary_base_t<MT, MinSize> &b) {
  return address_of_basic_block(bb, b.Analysis.ICFG);
}

template <bool MT, bool MinSize>
static inline taddr_t address_of_basic_block_terminator(
    typename ip_icfg_base_t<MT>::vertex_descriptor bb,
    const ip_icfg_base_t<MT> &ICFG) {
  return ICFG[bb].Term.Addr;
}

template <bool MT, bool MinSize>
static inline taddr_t address_of_basic_block_terminator(
    typename ip_icfg_base_t<MT>::vertex_descriptor bb,
    const binary_base_t<MT, MinSize> &b) {
  return address_of_basic_block_terminator(bb, b.Analysis.ICFG);
}

template <bool MT, bool MinSize>
static inline taddr_t
entry_address_of_function(const function_t &f,
                          const binary_base_t<MT, MinSize> &binary) {
  const auto &ICFG = binary.Analysis.ICFG;
  return ICFG[basic_block_of_index(f.Entry, binary)].Addr;
}

template <bool MT, bool MinSize>
static inline taddr_t
address_of_block_in_binary(basic_block_index_t BBIdx,
                           const binary_base_t<MT, MinSize> &b) {
  return b.Analysis.ICFG[basic_block_of_index(BBIdx, b)].Addr;
}

template <bool MT, bool MinSize>
static inline taddr_t address_of_block(const block_t &block,
                                       const jv_base_t<MT, MinSize> &jv) {
  const binary_base_t<MT, MinSize> &b = jv.Binaries.at(block.first);
  return address_of_block_in_binary(block.second, b);
}

template <bool MT, bool MinSize>
static inline taddr_t
address_of_block_terminator(const block_t &Block,
                            const jv_base_t<MT, MinSize> &jv) {
  const binary_base_t<MT, MinSize> &b = jv.Binaries.at(Block.first);
  return b.Analysis.ICFG[basic_block_of_index(Block.second, b)].Term.Addr;
}

template <bool MT, bool MinSize>
static inline void construct_bbmap(const jv_base_t<MT, MinSize> &jv,
                                   const binary_base_t<MT, MinSize> &b,
                                   bbmap_t &out) {
  auto &ICFG = b.Analysis.ICFG;

  for_each_basic_block_in_binary(
      b, [&](typename ip_icfg_base_t<MT>::vertex_descriptor bb) {
        const auto &bbprop = ICFG[bb];

        bbmap_add(out, addr_intvl(bbprop.Addr, bbprop.Size), ICFG.index(bb));
      });
}

template <bool MT, bool MinSize>
static inline const binary_base_t<MT, MinSize> &
get_dynl(const jv_base_t<MT, MinSize> &jv) {
  for (auto &b : jv.Binaries) {
    if (b.IsDynamicLinker)
      return b;
  }

  throw std::runtime_error(std::string(__func__) + ": not found!");
}

template <bool MT, bool MinSize>
static inline const binary_base_t<MT, MinSize> &
get_vdso(const jv_base_t<MT, MinSize> &jv) {
  for (auto &b : jv.Binaries) {
    if (b.IsVDSO)
      return b;
  }

  throw std::runtime_error(std::string(__func__) + ": not found!");
}

//
// until we come up with a cleaner source code patch for boost-graph (to make it
// work with boost interprocess (stateful) allocators), we need to do this for
// now XXX FIXME
//
template <bool MT, bool MinSize>
static inline void hack_interprocess_graphs(jv_base_t<MT, MinSize> &jv) {
  for_each_binary(maybe_par_unseq, jv,
                  [&](auto &b) { hack_interprocess_graph(b.Analysis.ICFG); });
}

#include "jove/state.h.inc"

} /* namespace jove */

#endif /* __cplusplus */

#undef IN_JOVE_H
#endif /* JOVE_H */
