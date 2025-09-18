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
#include "jove/verbose.h"

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

#include "jove/assert.h"

namespace llvm {
namespace object {
class Binary;
}
}

namespace jove {

#include "jove/host.h.inc"
#include "jove/target.h.inc"

template <bool MT, bool MinSize>
class explorer_t;
template <bool MT, bool MinSize>
struct jv_base_t;
template <bool MT, bool MinSize>
struct binary_base_t;

#include "jove/addr.h.inc"
#include "jove/terminator.h.inc"
#include "jove/mt.h.inc"
#include "jove/possibly_concurrent.h.inc"
#include "jove/index.h.inc"
#include "jove/deque.h.inc"
#include "jove/adjacency_list.h.inc"
#include "jove/table.h.inc"
#include "jove/addr_intvl.h.inc"
#include "jove/ip.h.inc"

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
        map(ip_construct<bbmap_t>(*jv_file.get_segment_manager(),
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
    auto e_lck_us = this->exclusive_access();

    if (bbmap_t *const bbmap = map.get())
      ip_destroy(get_segment_manager(), bbmap);
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

  segment_manager_t &get_segment_manager(void) const {
    segment_manager_t *const sm = sm_.get();
    assert(sm);
    return *sm;
  }
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
};

template <bool MT, bool MinSize>
void UnserializeJV(jv_base_t<MT, MinSize> &out, jv_file_t &, std::istream &, bool text);
struct UnlockTool;

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
#if defined(TARGET_X86_64) || defined(TARGET_I386)
      //
      // is this a string‐manipulation instruction?
      //
      bool String = false;
#endif
    } _conditional_jump;

    struct {
    } _indirect_call;

    struct {
      bool Returns = false;
    } _return;
  } Term;

  atomic_offset_ptr<void> pDynTargets = nullptr;
  boost::interprocess::offset_ptr<segment_manager_t> sm_ = nullptr;

  bool Sj = false;
  bb_analysis_t Analysis;

  template <bool MT, bool MinSize>
  boost::optional<const DynTargets_t<MT, MinSize> &>
  getDynamicTargets(void) const {
    if (const void *const p = pDynTargets.load(MT ? std::memory_order_acquire :
                                                    std::memory_order_relaxed)) {
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
    atomic_offset_ptr<const ip_func_index_vec> _p = nullptr;

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
      _p.store(&x, MT ? std::memory_order_release : std::memory_order_relaxed);
    }

  public:
    template <bool MT>
    const ip_func_index_vec &get(void) const {
      const ip_func_index_vec *res =
          _p.load(MT ? std::memory_order_acquire : std::memory_order_relaxed);
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
    return !!pDynTargets.load(std::memory_order_relaxed);
  }

  template <bool MT, bool MinSize>
  bool insertDynTarget(binary_index_t ThisBIdx,
                       const dynamic_target_t &,
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
  bool doInsertDynTarget(const dynamic_target_t &);
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
                      boost::setS_ip, /* no parallel edges! */ /* OutEdgeList */
                      boost::dequeS_ip,                        /* VertexList */
                      boost::directedS,                        /* Directed */
                      ip_call_graph_node_properties_t,         /* VertexProperties */
                      boost::no_property,                      /* EdgeProperties */
                      boost::no_property,                      /* GraphProperties */
                      boost::vecS_ip>;                         /* EdgeList */

template <bool MT, bool MinSize>
using Callers_t = PossiblyConcurrentNodeOrFlatSet_t<MT, MinSize, caller_t>;

struct function_analysis_t {
  boost::interprocess::offset_ptr<segment_manager_t> sm_ = nullptr;

  tcg_global_set_t args;
  tcg_global_set_t rets;

  std::atomic<bool> Stale = true;

  atomic_offset_ptr<void> pCallers = nullptr;

  bool IsLeaf = false;
  bool IsSj = false;
  bool IsLj = false;

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

  segment_manager_t *get_segment_manager(void) const {
    segment_manager_t *const sm = sm_.get();
    assert(sm);
    return sm;
  }

  bool hasCaller(void) const noexcept {
    return !!pCallers.load(std::memory_order_relaxed);
  }

  template <bool MT, bool MinSize>
  unsigned numCallers(void) const noexcept {
    using OurCallers_t = Callers_t<MT, MinSize>;

    if (void *const p = pCallers.load(MT ? std::memory_order_acquire
                                         : std::memory_order_relaxed)) {
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
  unsigned numCallers(const jv_base_t<MT, MinSize> &) const noexcept {
    return numCallers<MT, MinSize>();
  }

  template <bool MT, bool MinSize>
  bool AddCaller(const caller_t &) noexcept;

  template <bool MT, bool MinSize>
  bool AddCaller(const jv_base_t<MT, MinSize> &,
                 const caller_t &caller) noexcept {
    return AddCaller<MT, MinSize>(caller);
  }

  template <bool MT, bool MinSize, class _ExecutionPolicy>
  void
  ForEachCaller(_ExecutionPolicy &&__exec,
                std::function<void(const caller_t &)> proc) const noexcept {
    using OurCallers_t = Callers_t<MT, MinSize>;

    if (void *const p = pCallers.load(MT ? std::memory_order_acquire
                                         : std::memory_order_relaxed)) {
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
  ForEachCaller(const jv_base_t<MT, MinSize> &,
                std::function<void(const caller_t &)> proc) const noexcept {
    ForEachCaller<MT, MinSize>(std::execution::seq, proc);
  }

  template <bool MT, bool MinSize>
  ip_call_graph_base_t<MT>::vertex_descriptor
  ReverseCGVert(jv_base_t<MT, MinSize> &);

  explicit function_analysis_t(segment_manager_t *sm) noexcept : sm_(sm) {}
  explicit function_analysis_t() = delete;

  explicit function_analysis_t(function_analysis_t &&other) noexcept
      : sm_(other.sm_),
        args(other.args),
        rets(other.rets),
        ReverseCGVertIdxHolder(std::move(other.ReverseCGVertIdxHolder)) {
    Stale.store(other.Stale.load(std::memory_order_relaxed),
                std::memory_order_relaxed);

    pCallers.store(other.pCallers.load(std::memory_order_relaxed),
                   std::memory_order_relaxed);
    other.pCallers.store(nullptr, std::memory_order_relaxed);
  }

  function_analysis_t &operator=(function_analysis_t &&other) noexcept {
    sm_ = other.sm_;
    args = other.args;
    rets = other.rets;
    ReverseCGVertIdxHolder = std::move(other.ReverseCGVertIdxHolder);

    Stale.store(other.Stale.load(std::memory_order_relaxed),
                std::memory_order_relaxed);

    pCallers.store(other.pCallers.load(std::memory_order_relaxed),
                   std::memory_order_relaxed);
    other.pCallers.store(nullptr, std::memory_order_relaxed);
    return *this;
  }

  void Invalidate(void) { this->Stale.store(true, std::memory_order_relaxed); }

  explicit function_analysis_t(const function_analysis_t &) = delete;
  function_analysis_t &operator=(const function_analysis_t &) = delete;

  ~function_analysis_t() noexcept;
};

struct function_t {
  bool Speculative = false;

  binary_index_t BIdx = invalid_binary_index;
  function_index_t Idx = invalid_function_index;
  basic_block_index_t Entry = invalid_basic_block_index;

  bool IsABI = false;
  bool IsSignalHandler = false;
  bool Returns = false;

  function_analysis_t Analysis;

  segment_manager_t *get_segment_manager(void) const {
    return Analysis.get_segment_manager();
  }

  void InvalidateAnalysis(void) {
    this->Analysis.Invalidate();
  }

  template <bool MT, bool MinSize>
  explicit function_t(binary_base_t<MT, MinSize> &, function_index_t) noexcept;
  explicit function_t(segment_manager_t *) noexcept; /* XXX used by serialize */
  explicit function_t() = delete;

  explicit function_t(function_t &&) noexcept = default;
  function_t &operator=(function_t &&) noexcept = default;

  explicit function_t(const function_t &) = delete;
  function_t &operator=(const function_t &) = delete;
};

#include "jove/objdump.h.inc"

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
        objdump_thinks(jv_file.get_segment_manager()) {
    hack_interprocess_graph(ICFG);
  }

  template <bool MT2>
  explicit binary_analysis_t(binary_analysis_t<MT2, MinSize> &&other) noexcept
      : sm_(other.sm_),
        EntryFunction(std::move(other.EntryFunction)),
        Functions(std::move(other.Functions)),
        ICFG(std::move(other.ICFG)),
        objdump_thinks(std::move(other.objdump_thinks)) {
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
    objdump_thinks = std::move(other.objdump_thinks);

    if constexpr (MT != MT2)
      move_stuff();

    return *this;
  }

#if 0
  void addSymDynTarget(const std::string &sym, dynamic_target_t X) {}
  void addRelocDynTarget(taddr_t A, dynamic_target_t X) {}
  void addIFuncDynTarget(taddr_t A, dynamic_target_t X) {}
#endif

  objdump_thinks_t<boost::interprocess::allocator<unsigned long /* FIXME */,
                                                  segment_manager_t>,
                   MT>
      objdump_thinks;

  segment_manager_t *get_segment_manager(void) const {
    segment_manager_t *const sm = sm_.get();
    assert(sm);
    return sm;
  }

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
    return Analysis.get_segment_manager();
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

struct AddOptions_t : public VerboseThing {
  bool Objdump = false;
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

  void hack_interprocess_graphs(void) noexcept {
    for_each_binary(
        std::execution::seq /* XXX FIXME? maybe_par_unseq */, *this,
        [&](binary_t &b) { hack_interprocess_graph(b.Analysis.ICFG); });
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

#include "jove/convenience.h.inc"
#include "jove/state.h.inc"

} /* namespace jove */

#endif /* __cplusplus */

#undef IN_JOVE_H
#endif /* JOVE_H */
