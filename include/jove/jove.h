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
#include <boost/unordered/unordered_node_set.hpp>
#include <boost/unordered/unordered_flat_map.hpp>
#include <boost/unordered/unordered_flat_set.hpp>
#include <boost/unordered/concurrent_flat_map.hpp>
#include <boost/unordered/concurrent_flat_set.hpp>
#include <boost/unordered/concurrent_node_set.hpp>
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

#include <algorithm>
#include <atomic>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <execution>
#include <functional>
#include <iomanip>
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

template <bool MT>
class explorer_t;
template <bool MT>
struct jv_base_t;

#include "jove/target.h.inc"
#include "jove/terminator.h.inc"
#include "jove/mt.h.inc"
#include "jove/possibly_concurrent.h.inc"
#include "jove/index.h.inc"
#include "jove/deque.h.inc"
#include "jove/adjacency_list.h.inc"
#include "jove/table.h.inc"
#include "jove/addr_intvl.h.inc"

template <bool MT>
struct binary_base_t;

struct allocates_basic_block_t {
  basic_block_index_t BBIdx = invalid_basic_block_index;

  explicit allocates_basic_block_t () noexcept = default;

  // allocates (creates) new basic block in binary, stores index
  template <bool MT>
  explicit inline allocates_basic_block_t(binary_base_t<MT> &b,
                                          basic_block_index_t &store,
                                          taddr_t Addr) noexcept;

  explicit operator basic_block_index_t() const { return BBIdx; }
};

template <bool MT>
using bbbmap_t = possibly_concurrent_flat_map<
    MT, std::true_type /* Spin */, taddr_t, allocates_basic_block_t,
    boost::hash<taddr_t>, std::equal_to<taddr_t>,
    boost::interprocess::allocator<
        std::pair<const taddr_t, allocates_basic_block_t>, segment_manager_t>>;

typedef boost::interprocess::map<
    addr_intvl, basic_block_index_t, addr_intvl_cmp,
    boost::interprocess::private_adaptive_pool<
        std::pair<const addr_intvl, basic_block_index_t>, segment_manager_t>>
    bbmap_t; /* _private_ adaptive pool because of heavyweight bbmap_lock */

template <bool MT>
struct BBMap_t : public ip_base_rw_accessible_nospin<MT> {
  ip_unique_ptr<bbmap_t::allocator_type> alloc;
  bbmap_t map;

  BBMap_t() = delete;
  BBMap_t(jv_file_t &jv_file) noexcept
      : alloc(boost::interprocess::make_managed_unique_ptr(
            jv_file.construct<bbmap_t::allocator_type>(
                boost::interprocess::anonymous_instance)(
                jv_file.get_segment_manager()),
            jv_file)),
        map(jv_file.get_segment_manager()) {}

  template <bool MT2>
  BBMap_t(BBMap_t<MT2> &&other) noexcept
      : alloc(std::move(other.alloc)), map(std::move(other.map), *alloc) {}

  template <bool MT2>
  BBMap_t &operator=(BBMap_t<MT2> &&other) noexcept {
    if constexpr (MT == MT2) {
      if (this == &other)
        return *this;
    }

    alloc = std::move(other.alloc);
    std::swap(map, other.map);

    return *this;
  }

  BBMap_t(const BBMap_t &) = delete;
  BBMap_t &operator=(const BBMap_t &) = delete;
};

struct allocates_function_t {
  function_index_t FIdx = invalid_function_index;

  explicit allocates_function_t() noexcept = default;

  // allocates (creates) new function in binary, stores index
  template <bool MT>
  explicit allocates_function_t(binary_base_t<MT> &b,
                                function_index_t &store) noexcept;

  explicit operator function_index_t() const { return FIdx; }
};

template <bool MT>
using fnmap_t = possibly_concurrent_flat_map<
    MT, std::true_type /* Spin */, taddr_t, allocates_function_t,
    boost::hash<taddr_t>, std::equal_to<taddr_t>,
    boost::interprocess::allocator<
        std::pair<const taddr_t, allocates_function_t>, segment_manager_t>>;

size_t jvDefaultInitialSize(void);

#include "jove/atomic.h.inc"

struct basic_block_properties_t : public ip_mt_base_rw_accessible_nospin {
  struct pub_t : public ip_mt_base_rw_accessible_nospin {
    std::atomic<bool> is = false;
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

  struct {
    AtomicOffsetPtr<ip_dynamic_target_set<>> _p; /* TODO atomic ip_unique_ptr.. */
    boost::interprocess::offset_ptr<segment_manager_t> _sm = nullptr;
    bool Complete = false;
  } DynTargets;

  bool Sj = false;

  struct Analysis_t {
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

    Analysis_t() noexcept = default;

    Analysis_t(tcg_global_set_t live_def, tcg_global_set_t live_use,
               tcg_global_set_t reach_def) noexcept
        : live{.def = live_def, .use = live_use}, reach{.def = reach_def} {}

    Analysis_t(const Analysis_t &other) noexcept
        : live(other.live), reach(other.reach) {
      Stale.store(other.Stale.load(std::memory_order_relaxed),
                  std::memory_order_relaxed);
    }

    Analysis_t(Analysis_t &&other) noexcept
        : live(other.live), reach(other.reach) {
      Stale.store(other.Stale.load(std::memory_order_relaxed),
                  std::memory_order_relaxed);
    }

    Analysis_t &operator=(Analysis_t &&other) noexcept {
      live = other.live;
      reach = other.reach;
      Stale.store(other.Stale.load(std::memory_order_relaxed),
                  std::memory_order_relaxed);
      return *this;
    }

    Analysis_t &operator=(const Analysis_t &other) noexcept {
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
    void moveFrom(Analysis_t &&other) {
      live = other.live;
      reach = other.reach;

      Stale.store(other.Stale.load(std::memory_order_relaxed),
                  std::memory_order_relaxed);
    }
  } Analysis;

  class Parents_t {
    AtomicOffsetPtr<const ip_func_index_vec> _p;

    friend UnlockTool;
    friend basic_block_properties_t;
    friend allocates_basic_block_t;

    template <bool MT>
    friend void UnserializeJV(jv_base_t<MT> &, jv_file_t &, std::istream &, bool);

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

    template <bool MT>
    void insert(function_index_t, binary_base_t<MT> &);
  } Parents;

  bool hasDynTarget(void) const {
    if (auto *p = DynTargets._p.Load(std::memory_order_relaxed)) {
      assert(!p->empty());
      return true;
    }

    return false;
  }
  unsigned getNumDynTargets(void) const {
    if (auto *p = DynTargets._p.Load(std::memory_order_relaxed))
      return p->size();

    return 0;
  }

  bool doInsertDynTarget(const dynamic_target_t &, jv_file_t &);

  template <bool MT>
  bool insertDynTarget(binary_index_t ThisBIdx,
                       const dynamic_target_t &,
                       jv_file_t &, jv_base_t<MT> &);

  template <class _ExecutionPolicy>
  void DynTargetsForEach(_ExecutionPolicy &&__exec,
                         std::function<void(const dynamic_target_t &)> proc) const {
    if (auto *p = DynTargets._p.Load(std::memory_order_relaxed))
      p->cvisit_all(std::forward<_ExecutionPolicy>(__exec), proc);
  }
  void DynTargetsForEach(std::function<void(const dynamic_target_t &)> proc) const {
    DynTargetsForEach(std::execution::seq, proc);
  }
  void DynTargetsForEachWhile(std::function<bool(const dynamic_target_t &)> proc) const {
    ip_dynamic_target_set<> *const p =
        DynTargets._p.Load(std::memory_order_relaxed);
    if (!p)
      return;

    bool res = false;
    p->cvisit_while([&](const dynamic_target_t &X) -> bool {
      if (proc(X)) {
        res = true;
        return false;
      }
      return true;
    });
  }
  bool DynTargetsAnyOf(std::function<bool(const dynamic_target_t &)> proc) const {
    ip_dynamic_target_set<> *const p =
        DynTargets._p.Load(std::memory_order_relaxed);
    if (!p)
      return false;

    bool res = false;
    p->cvisit_while([&](const dynamic_target_t &X) -> bool {
      if (proc(X)) {
        res = true;
        return false;
      }
      return true;
    });
    return res;
  }
  bool DynTargetsAllOf(std::function<bool(const dynamic_target_t &)> proc) const {
    ip_dynamic_target_set<> *const p =
        DynTargets._p.Load(std::memory_order_relaxed);
    if (!p)
      return true;

    bool res = true;
    p->cvisit_while([&](const dynamic_target_t &X) -> bool {
      if (!proc(X)) {
        res = false;
        return false;
      }
      return true;
    });
    return res;
  }
  dynamic_target_t DynTargetsFront(void) const {
    dynamic_target_t res = invalid_dynamic_target;

    ip_dynamic_target_set<> *const p =
        DynTargets._p.Load(std::memory_order_relaxed);
    if (!p)
      return res;


    p->cvisit_while([&](const dynamic_target_t &X) -> bool {
      res = X;
      return false;
    });

    assert(is_dynamic_target_valid(res));
    return res;
  }

  template <class T, class BinaryOperation>
  T DynTargetsAccumulate(T init, BinaryOperation op) const {
    if (auto *p = DynTargets._p.Load(std::memory_order_relaxed))
      p->cvisit_all(
          [&](dynamic_target_t X) -> void { init = op(std::move(init), X); });

    return init;
  }


  bool IsSingleInstruction(void) const { return Addr == Term.Addr; }

  template <bool MT>
  void InvalidateAnalysis(jv_base_t<MT> &, binary_base_t<MT> &);

  explicit basic_block_properties_t() noexcept = default;

  explicit basic_block_properties_t(basic_block_properties_t &&other) noexcept {
    moveFrom(std::move(other));
  }

  basic_block_properties_t &
  operator=(basic_block_properties_t &&other) noexcept {
    if (this != &other)
      moveFrom(std::move(other));

    return *this;
  }

  ~basic_block_properties_t() noexcept {
    if (auto *p = DynTargets._p.Load(std::memory_order_relaxed)) {
      assert(DynTargets._sm);
      DynTargets._sm->destroy_ptr(p); /* (boost/ipc/smart_ptr/deleter.hpp) */
    }
  }

  explicit basic_block_properties_t(const basic_block_properties_t &) = delete;
  basic_block_properties_t &operator=(const basic_block_properties_t &) = delete;

private:
  void moveFrom(basic_block_properties_t &&other) noexcept {
    pub.is.store(other.pub.is.load(std::memory_order_relaxed),
                 std::memory_order_relaxed);
    other.pub.is.store(false, std::memory_order_relaxed);

    Speculative = other.Speculative;
    Addr = other.Addr;
    Size = other.Size;
    Term = other.Term;
    Sj = other.Sj;
    Analysis = std::move(other.Analysis);

    Parents._p.Store(other.Parents._p.Load(std::memory_order_relaxed),
                     std::memory_order_relaxed);
    other.Parents._p.Store(nullptr, std::memory_order_relaxed);

    DynTargets._sm = other.DynTargets._sm;
    other.DynTargets._sm = nullptr;

    DynTargets._p.Store(other.DynTargets._p.Load(std::memory_order_relaxed),
                        std::memory_order_relaxed);
    other.DynTargets._p.Store(nullptr, std::memory_order_relaxed);

    DynTargets.Complete = other.DynTargets.Complete;
  }
};

typedef basic_block_properties_t bbprop_t;

template <bool MT>
using ip_icfg_base_t =
ip_adjacency_list<MT,
                  true /* Spin */,
                  true /* PointUnique */,
                  boost::setS_ip,           /* OutEdgeList */
                  boost::dequeS_ip,         /* VertexList */
                  boost::directedS,         /* Directed */
                  basic_block_properties_t, /* VertexProperties */
                  boost::no_property,       /* EdgeProperties */
                  boost::no_property,       /* GraphProperties */
                  boost::listS_ip>;         /* EdgeList */

typedef ip_icfg_base_t<true> ip_icfg_t;

typedef ip_icfg_t::type interprocedural_control_flow_graph_t;

typedef interprocedural_control_flow_graph_t icfg_t;

typedef interprocedural_control_flow_graph_t::vertex_descriptor basic_block_t;
typedef interprocedural_control_flow_graph_t::edge_descriptor control_flow_t;

typedef std::vector<basic_block_t> basic_block_vec_t;

static inline basic_block_t NullBasicBlock(void) {
  return boost::graph_traits<
      interprocedural_control_flow_graph_t>::null_vertex();
}

template <bool MT>
constexpr bool IsDefinitelyTailCall(const ip_icfg_base_t<MT> &ICFG, basic_block_t bb) {
  auto &bbprop = ICFG[bb];

  assert(bbprop.Term.Type == TERMINATOR::INDIRECT_JUMP); /* catch bugs */
  //WARN_ON(ICFG.out_degree<L>(bb) > 0); /* catch bugs */
  return bbprop.hasDynTarget();
}

template <bool MT>
constexpr bool IsAmbiguousIndirectJump(const ip_icfg_base_t<MT> &ICFG, basic_block_t bb) {
  auto &bbprop = ICFG[bb];

  assert(bbprop.Term.Type == TERMINATOR::INDIRECT_JUMP); /* catch bugs */
  return bbprop.hasDynTarget() && ICFG.out_degree(bb) > 0;
}

template <bool MT>
constexpr bool IsExitBlock(const ip_icfg_base_t<MT> &ICFG, basic_block_t bb) {
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

template <bool MT>
constexpr block_t block_for_caller_in_binary(const caller_t &caller,
                                             const binary_base_t<MT> &caller_b,
                                             const jv_base_t<MT> &jv) {
  const binary_index_t BIdx = caller.first;

  assert(is_binary_index_valid(BIdx));

  const binary_base_t<MT> &b = jv.Binaries.at(BIdx);
  const basic_block_index_t BBIdx = ({
    auto s_lck_bbmap = b.BBMap.shared_access();

    index_of_basic_block_at_address(caller.second, b);
  });

  return block_t(BIdx, BBIdx);
}

typedef boost::interprocess::set<
    caller_t, std::less<caller_t>,
    boost::interprocess::node_allocator<caller_t, segment_manager_t>>
    ip_callers_t;

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

struct function_t {
  bool Speculative = false;

  binary_index_t BIdx = invalid_binary_index;
  function_index_t Idx = invalid_function_index;
  basic_block_index_t Entry = invalid_basic_block_index;

  class Callers_t : private ip_mt_base_rw_accessible_spin {
    ip_callers_t set;

  public:
    explicit Callers_t(segment_manager_t *sm) noexcept : set(sm) {}

    template <bool MT>
    void insert(binary_index_t BIdx, taddr_t TermAddr) {
      assert(TermAddr);

      auto e_lck = this->exclusive_access<MT>();

      set.emplace(BIdx, TermAddr);
    }

    template <bool MT>
    shared_lock_guard<MT> get(const ip_callers_t *&out) const {
      out = &set;
      return this->shared_access<MT>();
    }

    template <bool MT>
    bool empty(void) const {
      auto s_lck = this->shared_access<MT>();

      return set.empty();
    }
  } Callers;

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

  template <bool MT>
  ip_call_graph_base_t<MT>::vertex_descriptor ReverseCGVert(jv_base_t<MT> &);

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

  template <bool MT>
  explicit function_t(binary_base_t<MT> &, function_index_t) noexcept;
  explicit function_t(segment_manager_t *) noexcept; /* XXX used by serialize */
  explicit function_t() = delete;

  explicit function_t(function_t &&) noexcept = default;
  function_t &operator=(function_t &&) noexcept = default;

  explicit function_t(const function_t &) = delete;
  function_t &operator=(const function_t &) = delete;
};

#include "jove/objdump.h.inc"

template <bool MT = true>
struct binary_base_t {
  binary_index_t Idx = invalid_binary_index;

  bbbmap_t<MT> bbbmap;

  BBMap_t<MT> BBMap;
  fnmap_t<MT> fnmap;

  ip_string Name;
  ip_string Data;
  hash_t Hash;

  bool IsDynamicLinker = false;
  bool IsExecutable = false;
  bool IsVDSO = false;
  bool IsPIC = false;
  bool IsDynamicallyLoaded = false;

  ip_unique_ptr<ip_func_index_vec> EmptyFIdxVec;
  ip_func_index_vecs<MT> FIdxVecs;

  struct Analysis_t {
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
    // references to basic_block_properties_t will never be invalidated
    // (although their fields are subject to change: see explorer_t::split() in
    //  core/explore.cpp)
    ip_icfg_base_t<MT> ICFG;

    Analysis_t() = delete;
    Analysis_t(const Analysis_t &) = delete;
    Analysis_t &operator=(const Analysis_t &) = delete;

    explicit Analysis_t(jv_file_t &jv_file) noexcept
        : Functions(jv_file),
          ICFG(jv_file),
          objdump(jv_file.get_segment_manager()) {}

    explicit Analysis_t(Analysis_t &&other) noexcept
        : EntryFunction(std::move(other.EntryFunction)),
          Functions(std::move(other.Functions)),
          ICFG(std::move(other.ICFG)),
          objdump(std::move(other.objdump)) {}

    explicit Analysis_t(typename binary_base_t<!MT>::Analysis_t &&other) noexcept
        : EntryFunction(std::move(other.EntryFunction)),
          Functions(std::move(other.Functions)),
          ICFG(std::move(other.ICFG)),
          objdump(std::move(other.objdump)) {}

    template <bool MT2>
    Analysis_t &
    operator=(typename binary_base_t<MT2>::Analysis_t &&other) noexcept {
      if constexpr (MT == MT2) {
        if (this == &other)
          return *this;
      }

      EntryFunction = other.EntryFunction;
      Functions = std::move(other.Functions);
      ICFG = std::move(other.ICFG);
      objdump = std::move(other.objdump);
      return *this;
    }

    /*** may have use in future ***/
    void addSymDynTarget(const std::string &sym, dynamic_target_t X) {}
    void addRelocDynTarget(taddr_t A, dynamic_target_t X) {}
    void addIFuncDynTarget(taddr_t A, dynamic_target_t X) {}

    typedef objdump_output_t<
        boost::interprocess::allocator<unsigned long /* FIXME */, segment_manager_t>, MT>
        objdump_output_type;

    objdump_output_type objdump;
  } Analysis;

  void InvalidateBasicBlockAnalyses(void);

  //
  // we thought this was a goto, but now we know it's definitely a tail
  // call. translate all sucessors as functions, then store them into the
  // dynamic targets set for this bb. afterwards, delete the edges in the
  // ICFG that would originate from this basic block.
  //
  bool FixAmbiguousIndirectJump(taddr_t TermAddr,
                                explorer_t<MT> &,
                                llvm::object::Binary &,
                                jv_file_t &,
                                jv_base_t<MT> &);

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
  explicit binary_base_t(binary_base_t<MT2> &&other) noexcept
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
  binary_base_t &operator=(binary_base_t<MT2> &&other) noexcept {
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

    Analysis.template operator=<MT2>(std::move(other.Analysis));

    return *this;
  }

  explicit binary_base_t() = delete;
  explicit binary_base_t(const binary_base_t &) = delete;
  binary_base_t &operator=(const binary_base_t &) = delete;
};

typedef binary_base_t<true> binary_t;

struct objdump_exception {
  taddr_t Addr;
  objdump_exception(taddr_t Addr) : Addr(Addr) {}
};

template <bool MT>
allocates_basic_block_t::allocates_basic_block_t(binary_base_t<MT> &b,
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

template <bool MT>
allocates_function_t::allocates_function_t(binary_base_t<MT> &b,
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

  explicit adds_binary_t() = default;
  explicit adds_binary_t(binary_index_t BIdx) noexcept : BIdx(BIdx) {
    assert(is_binary_index_valid(BIdx));
  }

  // adds new binary, stores index
  template <bool MT>
  explicit adds_binary_t(binary_index_t &out,
                         jv_file_t &,
                         jv_base_t<MT> &,
                         explorer_t<MT> &,
                         get_data_t get_data,
                         const hash_t &,
                         const char *name,
                         const AddOptions_t &) noexcept(false);

  // adds new binary, stores index
  template <bool MT>
  explicit adds_binary_t(binary_index_t &out,
                         jv_base_t<MT> &,
                         binary_base_t<MT> &&) noexcept;

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

template <bool MT>
using ip_cached_hashes_type = possibly_concurrent_flat_map<
    MT, std::false_type /* !Spin */, ip_string, cached_hash_t, ip_string_hash_t,
    ip_string_equal_t,
    boost::container::scoped_allocator_adaptor<boost::interprocess::allocator<
        std::pair<const ip_string, cached_hash_t>, segment_manager_t>>>;

template <bool MT>
using ip_hash_to_binary_map_type = possibly_concurrent_flat_map<
    MT, std::false_type /* !Spin */, hash_t, adds_binary_t, JoveBinaryHash,
    std::equal_to<hash_t>,
    boost::interprocess::allocator<std::pair<const hash_t, adds_binary_t>,
                                   segment_manager_t>>;

template <bool MT>
using ip_name_to_binaries_map_type = possibly_concurrent_flat_map<
    MT, std::false_type /* !Spin */, ip_string, ip_binary_index_set,
    ip_string_hash_t, ip_string_equal_t,
    boost::container::scoped_allocator_adaptor<boost::interprocess::allocator<
        std::pair<const ip_string, ip_binary_index_set>, segment_manager_t>>>;

template <bool MT>
using on_newbin_proc_t = std::function<void(binary_base_t<MT> &)>;

struct AddOptions_t {
  bool Objdump = false;
  unsigned VerbosityLevel = 0;

  bool IsVerbose(void) const { return VerbosityLevel >= 1; };
  bool IsVeryVerbose(void) const { return VerbosityLevel >= 2; };
};

template <bool MT>
using ip_binary_deque_t =
    ip_deque<binary_base_t<MT>,
             boost::interprocess::private_node_allocator<binary_base_t<MT>,
                                                         segment_manager_t>,
             MT>;

template <bool MT>
using ip_binary_table_t = table_t<binary_base_t<MT>, MaxBinaries>;

template <bool MT = true>
struct jv_base_t {
  //
  // references to binary_t will never be invalidated.
  //
  ip_binary_table_t<MT> Binaries;

  struct Analysis_t {
    ip_call_graph_base_t<MT> ReverseCallGraph;

    explicit Analysis_t(jv_file_t &jv_file) noexcept
        : ReverseCallGraph(jv_file) {}

    explicit Analysis_t(Analysis_t &&other) noexcept
        : ReverseCallGraph(std::move(other.ReverseCallGraph)) {}

    explicit Analysis_t(typename jv_base_t<!MT>::Analysis_t &&other) noexcept
        : ReverseCallGraph(std::move(other.ReverseCallGraph)) {}
  } Analysis;

  ip_hash_to_binary_map_type<MT> hash_to_binary;
  ip_cached_hashes_type<MT> cached_hashes; /* NOT serialized */

  ip_name_to_binaries_map_type<MT> name_to_binaries;

  void InvalidateFunctionAnalyses(void);

  void clear(bool everything = false);

  segment_manager_t *get_segment_manager(void) const {
    return hash_to_binary.get_allocator().get_segment_manager();
  }

  explicit jv_base_t(jv_file_t &jv_file) noexcept
      : Binaries(jv_file),
        Analysis(jv_file),
        hash_to_binary(jv_file.get_segment_manager()),
        cached_hashes(jv_file.get_segment_manager()),
        name_to_binaries(jv_file.get_segment_manager()) {
    init_binary_indices();
  }

  explicit jv_base_t(jv_base_t<MT> &&other, jv_file_t &jv_file) noexcept
      : Binaries(jv_file),
        Analysis(std::move(other.Analysis)),
        hash_to_binary(std::move(other.hash_to_binary)),
        cached_hashes(std::move(other.cached_hashes)),
        name_to_binaries(std::move(other.name_to_binaries)) {
    init_binary_indices();

    const unsigned N = other.Binaries.len_.load(std::memory_order_relaxed);
    Binaries.len_.store(N, std::memory_order_relaxed);

    for (unsigned i = 0; i < N; ++i)
      Binaries[i] = std::move(other.Binaries[i]);
  }

  explicit jv_base_t(jv_base_t<!MT> &&other, jv_file_t &jv_file) noexcept
      : Binaries(jv_file),
        Analysis(std::move(other.Analysis)),
        hash_to_binary(std::move(other.hash_to_binary)),
        cached_hashes(std::move(other.cached_hashes)),
        name_to_binaries(std::move(other.name_to_binaries)) {
    init_binary_indices();

    const unsigned N = other.Binaries.len_.load(std::memory_order_relaxed);
    Binaries.len_.store(N, std::memory_order_relaxed);

    for (unsigned i = 0; i < N; ++i) {
      binary_base_t<!MT> &b = other.Binaries[i];
      Binaries[i] = std::move(b);
    }
  }

  explicit jv_base_t() = delete;
  explicit jv_base_t(const jv_base_t &) = delete;
  jv_base_t &operator=(const jv_base_t &) = delete;
  jv_base_t &operator=(jv_base_t &&) = delete;

  std::optional<binary_index_t> LookupByHash(const hash_t &h);
  bool LookupByName(const char *name, binary_index_set &out);

  template <bool ValidatePath = true>
  std::pair<binary_index_t, bool>
  AddFromPath(explorer_t<MT> &,
              jv_file_t &,
              const char *path,
              on_newbin_proc_t<MT> on_newbin = [](binary_base_t<MT> &) {},
              const AddOptions_t &Options = AddOptions_t());

  std::pair<binary_index_t, bool> Add(
      binary_base_t<MT> &&,
      on_newbin_proc_t<MT> on_newbin = [](binary_base_t<MT> &) {});

  std::pair<binary_index_t, bool>
  AddFromData(explorer_t<MT> &,
              jv_file_t &,
              std::string_view data,
              const char *name = nullptr,
              on_newbin_proc_t<MT> on_newbin = [](binary_base_t<MT> &) {},
              const AddOptions_t &Options = AddOptions_t());

  unsigned NumBinaries(void) {
    return Binaries.size();
  }

private:
  void LookupAndCacheHash(hash_t &out, const char *path,
                          std::string &file_contents);

  std::pair<binary_index_t, bool> AddFromDataWithHash(explorer_t<MT> &,
                                                      jv_file_t &,
                                                      get_data_t,
                                                      const hash_t &,
                                                      const char *name,
                                                      on_newbin_proc_t<MT>,
                                                      const AddOptions_t &);

  void init_binary_indices(void) {
    std::for_each(std::execution::par_unseq,
                  Binaries.begin(),
                  Binaries.begin() + MaxBinaries, [&](auto &b) {
                    const binary_index_t Idx = &b - Binaries.begin();
                    __atomic_store_n(&b.Idx, Idx, __ATOMIC_RELAXED);
                  });
  }
public:
  template <bool MT2>
  void DoAdd(binary_base_t<MT2> &,
             explorer_t<MT2> &,
             llvm::object::Binary &,
             const AddOptions_t &);

  friend adds_binary_t;

  void fixup(void);
  void fixup_binary(const binary_index_t);
};

typedef jv_base_t<true> jv_t;

static inline std::string
description_of_block(const basic_block_properties_t &bbprop,
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
constexpr basic_block_t basic_block_of_index(basic_block_index_t BBIdx,
                                             const ip_icfg_base_t<MT> &ICFG) {
  assert(is_basic_block_index_valid(BBIdx));
  assert(BBIdx < ICFG.num_vertices());
  return ICFG.vertex(BBIdx);
}

template <bool MT>
constexpr basic_block_t basic_block_of_index(basic_block_index_t BBIdx,
                                             const binary_base_t<MT> &b) {
  const auto &ICFG = b.Analysis.ICFG;
  return basic_block_of_index(BBIdx, ICFG);
}

template <typename BBMap>
constexpr auto bbmap_find(BBMap &bbmap, addr_intvl intvl) {
  return intvl_map_find(bbmap, intvl);
}

template <typename BBMap>
constexpr auto bbmap_find(BBMap &bbmap, taddr_t Addr) {
  return intvl_map_find(bbmap, Addr);
}

template <typename BBMap>
constexpr bool bbmap_contains(BBMap &bbmap, addr_intvl intvl) {
  return intvl_map_contains(bbmap, intvl);
}

template <typename BBMap>
constexpr bool bbmap_contains(BBMap &bbmap, taddr_t Addr) {
  return intvl_map_contains(bbmap, Addr);
}

template <typename BBMap, typename Value>
constexpr auto bbmap_add(BBMap &bbmap,
                         addr_intvl intvl,
                         Value &&val) {
  return intvl_map_add(bbmap, intvl, std::move(val));
}

template <class _ExecutionPolicy, class T, class Proc>
constexpr
void for_each_binary(_ExecutionPolicy &&__exec,
                     T &&jv,
                     Proc proc) {
  std::for_each(std::forward<_ExecutionPolicy>(__exec),
                jv.Binaries.begin(),
                jv.Binaries.end(),
                proc);
}

template <class T, class Proc>
constexpr
void for_each_binary(T &&jv, Proc proc) {
  std::for_each(jv.Binaries.begin(),
                jv.Binaries.end(),
                proc);
}

template <class _ExecutionPolicy, class T, class Pred, class Proc>
constexpr
void for_each_binary_if(_ExecutionPolicy &&__exec,
                        T &&jv,
                        Pred pred,
                        Proc proc) {
  for_each_if(std::forward<_ExecutionPolicy>(__exec),
              jv.Binaries.begin(),
              jv.Binaries.end(),
              pred, proc);
}

template <class T, class Pred, class Proc>
constexpr
void for_each_binary_if(T &&jv, Pred pred, Proc proc) {
  for_each_if(jv.Binaries.begin(),
              jv.Binaries.end(),
              pred, proc);
}

template <class _ExecutionPolicy, class T, class Proc>
constexpr
void for_each_function(_ExecutionPolicy &&__exec,
                       T &&jv,
                       Proc proc) {
  for_each_binary(std::forward<_ExecutionPolicy>(__exec),
                  std::forward<T>(jv),
                  [&__exec, proc](auto &b) {
    std::for_each(std::forward<_ExecutionPolicy>(__exec),
                  b.Analysis.Functions.begin(),
                  b.Analysis.Functions.end(),
                  [&b, proc](auto &f) { proc(f, b); });
  });
}

template <class T, class Proc>
constexpr
void for_each_function(T &&jv, Proc proc) {
  for_each_binary(std::forward<T>(jv),
                  [proc](auto &b) {
    std::for_each(b.Analysis.Functions.begin(),
                  b.Analysis.Functions.end(),
                  [&b, proc](auto &f) { proc(f, b); });
  });
}

template <class _ExecutionPolicy, class Pred, class Proc, bool MT = true>
constexpr
void for_each_function_if_in_binary(_ExecutionPolicy &&__exec,
                                    binary_base_t<MT> &b,
                                    Pred pred,
                                    Proc proc) {
  for_each_if(std::forward<_ExecutionPolicy>(__exec),
              b.Analysis.Functions.begin(),
              b.Analysis.Functions.end(), pred, proc);
}

template <class Pred, class Proc, bool MT = true>
constexpr
void for_each_function_if_in_binary(binary_base_t<MT> &b,
                                    Pred pred,
                                    Proc proc) {
  for_each_if(b.Analysis.Functions.begin(),
              b.Analysis.Functions.end(), pred, proc);
}


template <class _ExecutionPolicy, class Proc, bool MT = true>
constexpr
void for_each_function_in_binary(_ExecutionPolicy &&__exec,
                                 binary_base_t<MT> &b,
                                 Proc proc) {
  std::for_each(std::forward<_ExecutionPolicy>(__exec),
                b.Analysis.Functions.begin(),
                b.Analysis.Functions.end(), proc);
}

template <class _ExecutionPolicy, class Proc, bool MT = true>
constexpr
void for_each_function_in_binary(_ExecutionPolicy &&__exec,
                                 const binary_base_t<MT> &b,
                                 Proc proc) {
  std::for_each(std::forward<_ExecutionPolicy>(__exec),
                b.Analysis.Functions.begin(),
                b.Analysis.Functions.end(), proc);
}

template <class Proc, bool MT = true>
constexpr
void for_each_function_in_binary(binary_base_t<MT> &b,
                                 Proc proc) {
  std::for_each(b.Analysis.Functions.begin(),
                b.Analysis.Functions.end(), proc);
}

template <class Proc, bool MT>
constexpr
void for_each_function_in_binary(const binary_base_t<MT> &b,
                                 Proc proc) {
  std::for_each(b.Analysis.Functions.begin(),
                b.Analysis.Functions.end(), proc);
}

template <class _ExecutionPolicy, class T, class Pred, class Proc>
constexpr
void for_each_function_if(_ExecutionPolicy &&__exec,
                          T &&jv,
                          Pred pred,
                          Proc proc) {
  for_each_binary(std::forward<_ExecutionPolicy>(__exec),
                  std::forward<T>(jv),
                  [&__exec, pred, proc](auto &b) {
    for_each_if(std::forward<_ExecutionPolicy>(__exec),
                b.Analysis.Functions.begin(),
                b.Analysis.Functions.end(),
                pred, [&b, proc](auto &f) { proc(f, b); });
  });
}

template <class T, class Pred, class Proc>
constexpr
void for_each_function_if(T &&jv,
                          Pred pred,
                          Proc proc) {
  for_each_binary(std::forward<T>(jv),
                  [pred, proc](auto &b) {
    for_each_if(b.Analysis.Functions.begin(),
                b.Analysis.Functions.end(),
                pred, [&b, proc](auto &f) { proc(f, b); });
  });
}

template <class _ExecutionPolicy, class T, class Proc>
constexpr
void for_each_basic_block(_ExecutionPolicy &&__exec,
                          T &&jv,
                          Proc proc) {
  for_each_binary(std::forward<_ExecutionPolicy>(__exec),
                  std::forward<T>(jv),
                  [&__exec, proc](auto &b) {
    icfg_t::vertex_iterator it, it_end;
    std::tie(it, it_end) = b.Analysis.ICFG.vertices();

    std::for_each(std::forward<_ExecutionPolicy>(__exec),
                  it, it_end,
                  [&b, proc](basic_block_t bb) { proc(b, bb); });
  });
}

template <class T, class Proc>
constexpr
void for_each_basic_block(T &&jv, Proc proc) {
  for_each_binary(std::forward<T>(jv),
                  [proc](auto &b) {
    icfg_t::vertex_iterator it, it_end;
    std::tie(it, it_end) = b.Analysis.ICFG.vertices();

    std::for_each(it, it_end,
                  [&b, proc](basic_block_t bb) { proc(b, bb); });
  });
}

template <class _ExecutionPolicy, class Proc, bool MT = true>
static inline
void for_each_basic_block_in_binary(_ExecutionPolicy &&__exec,
                                    binary_base_t<MT> &b,
                                    Proc proc) {
  icfg_t::vertex_iterator it, it_end;
  std::tie(it, it_end) = b.Analysis.ICFG.vertices();

  std::for_each(std::forward<_ExecutionPolicy>(__exec),
               it, it_end, [proc](basic_block_t bb) { proc(bb); });
}

template <class _ExecutionPolicy, class Proc, bool MT = true>
static inline
void for_each_basic_block_in_binary(_ExecutionPolicy &&__exec,
                                    const binary_base_t<MT> &b,
                                    Proc proc) {
  icfg_t::vertex_iterator it, it_end;
  std::tie(it, it_end) = b.Analysis.ICFG.vertices();

  std::for_each(std::forward<_ExecutionPolicy>(__exec),
               it, it_end, [proc](basic_block_t bb) { proc(bb); });
}

template <class Proc, bool MT = true>
static inline
void for_each_basic_block_in_binary(binary_base_t<MT> &b, Proc proc) {
  icfg_t::vertex_iterator it, it_end;
  std::tie(it, it_end) = b.Analysis.ICFG.vertices();

  std::for_each(it, it_end, [proc](basic_block_t bb) { proc(bb); });
}

template <class Proc, bool MT = true>
static inline
void for_each_basic_block_in_binary(const binary_base_t<MT> &b, Proc proc) {
  icfg_t::vertex_iterator it, it_end;
  std::tie(it, it_end) = b.Analysis.ICFG.vertices();

  std::for_each(it, it_end, [proc](basic_block_t bb) { proc(bb); });
}

template <bool MT>
constexpr basic_block_index_t index_of_basic_block(const ip_icfg_base_t<MT> &ICFG,
                                                   basic_block_t bb) {
  return ICFG.index(bb);
}

template <bool MT>
constexpr basic_block_index_t index_of_basic_block(const binary_base_t<MT> &b,
                                                   basic_block_t bb) {
  return index_of_basic_block(b.Analysis.ICFG, bb);
}

constexpr binary_index_t binary_index_of_function(const function_t &f) {
  binary_index_t res = f.BIdx;
  assert(is_binary_index_valid(res));
  return res;
}

template <bool MT>
[[deprecated]] /* use binary_index_of_function(f) */
constexpr binary_index_t binary_index_of_function(const function_t &f,
                                                  const jv_base_t<MT> &jv) {
  return binary_index_of_function(f);
}

template <bool MT>
constexpr binary_index_t index_of_binary(const binary_base_t<MT> &b) {
  binary_index_t res = b.Idx;
  assert(is_binary_index_valid(res));
  return res;
}

template <bool MT>
[[deprecated]] /* use index_of_binary(b) */
constexpr binary_index_t
index_of_binary(const binary_base_t<MT> &b, const jv_base_t<MT> &jv) {
  return index_of_binary(b);
}

constexpr function_index_t index_of_function(const function_t &f) {
  function_index_t res = f.Idx;
  assert(is_function_index_valid(res));
  return res;
}

template <bool MT>
[[deprecated]] /* use index_of_function(f) */
constexpr function_index_t index_of_function_in_binary(const function_t &f,
                                                       const binary_base_t<MT> &b) {
  return index_of_function(f);
}

template <bool MT = true>
constexpr const binary_base_t<MT> &binary_of_function(const function_t &f,
                                                      const jv_base_t<MT> &jv) {
  binary_index_t BIdx = f.BIdx;
  assert(is_binary_index_valid(BIdx));
  return jv.Binaries.at(BIdx);
}

template <bool MT = true>
constexpr binary_base_t<MT> &binary_of_function(function_t &f,
                                                jv_base_t<MT> &jv) {
  binary_index_t BIdx = f.BIdx;
  assert(is_binary_index_valid(BIdx));
  return jv.Binaries.at(BIdx);
}

template <bool MT>
constexpr const function_t &function_of_target(dynamic_target_t X,
                                               const jv_base_t<MT> &jv) {
  return jv.Binaries.at(X.first).Analysis.Functions.at(X.second);
}

template <bool MT>
constexpr function_t &function_of_target(dynamic_target_t X, jv_base_t<MT> &jv) {
  return jv.Binaries.at(X.first).Analysis.Functions.at(X.second);
}

constexpr dynamic_target_t target_of_function(const function_t &f) {
  return {binary_index_of_function(f), index_of_function(f)};
}

template <bool MT>
static inline void basic_blocks_of_function_at_block(basic_block_t entry,
                                                     const binary_base_t<MT> &b,
                                                     basic_block_vec_t &out) {
  const auto &ICFG = b.Analysis.ICFG;

  struct bb_visitor : public boost::default_dfs_visitor {
    basic_block_vec_t &out;

    bb_visitor(basic_block_vec_t &out) : out(out) {}

    void discover_vertex(basic_block_t bb, const icfg_t &) const {
      out.push_back(bb);
    }
  };

  bb_visitor vis(out);
  ICFG.depth_first_visit(entry, vis);
}

template <bool MT>
static inline void basic_blocks_of_function(const function_t &f,
                                            const binary_base_t<MT> &b,
                                            basic_block_vec_t &out) {

  const auto &ICFG = b.Analysis.ICFG;

  basic_blocks_of_function_at_block(basic_block_of_index(f.Entry, ICFG), b, out);
}

template <bool MT>
static inline void exit_basic_blocks_of_function(const function_t &f,
                                                 const binary_base_t<MT> &b,
                                                 const basic_block_vec_t &bbvec,
                                                 basic_block_vec_t &out) {
  const auto &ICFG = b.Analysis.ICFG;

  out.reserve(bbvec.size());

  std::copy_if(bbvec.begin(),
               bbvec.end(),
               std::back_inserter(out),
               [&](basic_block_t bb) -> bool { return IsExitBlock(ICFG, bb); });
}

static inline bool does_function_return_fast(const ip_icfg_t &ICFG,
                                             const basic_block_vec_t &bbvec) {
  return std::any_of(bbvec.begin(),
                     bbvec.end(),
                     [&](basic_block_t bb) -> bool {
                       return IsExitBlock(ICFG, bb);
                     });
}

template <bool MT>
static inline bool does_function_at_block_return(basic_block_t entry,
                                                 const binary_base_t<MT> &b) {
  basic_block_vec_t bbvec;
  basic_blocks_of_function_at_block(entry, b, bbvec);

  const auto &ICFG = b.Analysis.ICFG;

  return std::any_of(bbvec.begin(),
                     bbvec.end(),
                     [&](basic_block_t bb) -> bool {
                       return IsExitBlock(ICFG, bb);
                     });
}

template <bool MT>
static inline bool does_function_return(const function_t &f,
                                        const binary_base_t<MT> &b) {
  return does_function_at_block_return(basic_block_of_index(f.Entry, b), b);
}

template <bool MT>
static inline bool IsLeafFunction(const function_t &f,
                                  const binary_base_t<MT> &b,
                                  const basic_block_vec_t &bbvec,
                                  const basic_block_vec_t &exit_bbvec) {
  const auto &ICFG = b.Analysis.ICFG;

  if (!std::none_of(bbvec.begin(),
                    bbvec.end(),
                    [&](basic_block_t bb) -> bool {
                      auto T = ICFG[bb].Term.Type;
                      return (T == TERMINATOR::INDIRECT_JUMP &&
                              ICFG.out_degree(bb) == 0)
                           || T == TERMINATOR::INDIRECT_CALL
                           || T == TERMINATOR::CALL;
                    }))
    return false;

  return std::all_of(exit_bbvec.begin(),
                     exit_bbvec.end(),
                     [&](basic_block_t bb) -> bool {
                       auto T = ICFG[bb].Term.Type;
                       return T == TERMINATOR::RETURN
                           || T == TERMINATOR::UNREACHABLE;
                     });
}

template <bool MT>
static inline bool IsFunctionSetjmp(const function_t &f,
                                    const binary_base_t<MT> &b,
                                    const basic_block_vec_t &bbvec) {
  const auto &ICFG = b.Analysis.ICFG;

  return std::any_of(bbvec.begin(),
                     bbvec.end(),
                     [&](basic_block_t bb) -> bool {
                       return ICFG[bb].Sj;
                     });
}

template <bool MT>
static inline bool IsFunctionLongjmp(const function_t &f,
                                     const binary_base_t<MT> &b,
                                     const basic_block_vec_t &bbvec) {
  const auto &ICFG = b.Analysis.ICFG;

  return std::any_of(bbvec.begin(),
                     bbvec.end(),
                     [&](basic_block_t bb) -> bool {
                       auto &Term = ICFG[bb].Term;
                       return Term.Type == TERMINATOR::INDIRECT_JUMP &&
                              Term._indirect_jump.IsLj;
                     });
}

template <bool MT>
static inline basic_block_index_t
index_of_basic_block_at_address(taddr_t Addr, const binary_base_t<MT> &b) {
  auto it = bbmap_find(b.BBMap.map, Addr);
  assert(it != b.BBMap.map.end());
  return (*it).second;
}

template <bool MT>
static inline basic_block_index_t
index_of_basic_block_starting_at_address(taddr_t Addr, const binary_base_t<MT> &b) {
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

  assert(found);
  return res;
}

template <bool MT = true>
static inline basic_block_t
basic_block_starting_at_address(taddr_t Addr, const binary_base_t<MT> &b) {
  return basic_block_of_index(index_of_basic_block_starting_at_address(Addr, b), b);
}

template <bool MT = true>
static inline basic_block_t basic_block_at_address(taddr_t Addr,
                                                   const binary_base_t<MT> &b) {
  return basic_block_of_index(index_of_basic_block_at_address(Addr, b), b);
}

template <bool MT>
static inline bool exists_basic_block_at_address(taddr_t Addr,
                                                 const binary_base_t<MT> &b) {
  return bbmap_contains(b.BBMap.map, Addr);
}

template <bool MT>
static inline bool exists_basic_block_starting_at_address(taddr_t Addr,
                                                          const binary_base_t<MT> &b) {
  return b.bbbmap.contains(Addr);
}

template <bool MT>
static inline function_index_t index_of_function_at_address(const binary_base_t<MT> &b,
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

template <bool MT>
static inline const function_t &function_at_address(const binary_base_t<MT> &b,
                                                    taddr_t Addr) {
  return b.Analysis.Functions.at(index_of_function_at_address(b, Addr));
}

template <bool MT>
static inline function_t &function_at_address(binary_base_t<MT> &b, taddr_t Addr) {
  return b.Analysis.Functions.at(index_of_function_at_address(b, Addr));
}

template <bool MT>
static inline bool exists_function_at_address(const binary_base_t<MT> &b, taddr_t Addr) {
  return b.fnmap.contains(Addr);
}

// NOTE: this function excludes tail calls.
template <bool MT>
static inline bool exists_indirect_jump_at_address(taddr_t Addr,
                                                   const binary_base_t<MT> &binary) {
  if (exists_basic_block_at_address(Addr, binary)) {
    const auto &ICFG = binary.Analysis.ICFG;
    basic_block_t bb = basic_block_at_address(Addr, binary);
    if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP &&
        !ICFG[bb].hasDynTarget())
      return true;
  }

  return false;
}

static inline taddr_t address_of_basic_block(basic_block_t bb,
                                             const ip_icfg_t &ICFG) {
  return ICFG[bb].Addr;
}

template <bool MT>
static inline taddr_t address_of_basic_block(basic_block_t bb,
                                             const binary_base_t<MT> &b) {
  return address_of_basic_block(bb, b.Analysis.ICFG);
}

static inline taddr_t address_of_basic_block_terminator(basic_block_t bb,
                                                        const ip_icfg_t &ICFG) {
  return ICFG[bb].Term.Addr;
}

template <bool MT>
static inline taddr_t address_of_basic_block_terminator(basic_block_t bb,
                                                        const binary_base_t<MT> &b) {
  return address_of_basic_block_terminator(bb, b.Analysis.ICFG);
}

template <bool MT>
static inline taddr_t entry_address_of_function(const function_t &f,
                                                const binary_base_t<MT> &binary) {
  const auto &ICFG = binary.Analysis.ICFG;
  return ICFG[basic_block_of_index(f.Entry, binary)].Addr;
}

template <bool MT>
static inline taddr_t address_of_block_in_binary(basic_block_index_t BBIdx,
                                                 const binary_base_t<MT> &b) {
  return b.Analysis.ICFG[basic_block_of_index(BBIdx, b)].Addr;
}

template <bool MT>
static inline taddr_t address_of_block(const block_t &block,
                                       const jv_base_t<MT> &jv) {
  const binary_base_t<MT> &b = jv.Binaries.at(block.first);
  return address_of_block_in_binary(block.second, b);
}

template <bool MT>
static inline taddr_t address_of_block_terminator(const block_t &Block,
                                                  const jv_base_t<MT> &jv) {
  const binary_base_t<MT> &b = jv.Binaries.at(Block.first);
  return b.Analysis.ICFG[basic_block_of_index(Block.second, b)].Term.Addr;
}

template <bool MT>
static inline void construct_bbmap(const jv_base_t<MT> &jv,
                                   const binary_base_t<MT> &binary,
                                   bbmap_t &out) {
  auto &ICFG = binary.Analysis.ICFG;

  for_each_basic_block_in_binary(binary, [&](basic_block_t bb) {
    const auto &bbprop = ICFG[bb];

    bbmap_add(out, addr_intvl(bbprop.Addr, bbprop.Size), ICFG.index(bb));
  });
}

template <bool MT>
static inline binary_base_t<MT> &get_dynl(jv_base_t<MT> &jv) {
  for (auto &b : jv.Binaries) {
    if (b.IsDynamicLinker)
      return b;
  }

  throw std::runtime_error(std::string(__func__) + ": not found!");
}

template <bool MT>
static inline binary_base_t<MT> &get_vdso(jv_base_t<MT> &jv) {
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
template <bool MT>
static inline void hack_interprocess_graphs(jv_base_t<MT> &jv) {
  for_each_binary(std::execution::par_unseq, jv, [&](auto &b) {
    __builtin_memset_inline(&b.Analysis.ICFG.container().m_property, 0,
                            sizeof(b.Analysis.ICFG.container().m_property));
  });
}

#include "jove/state.h.inc"

} /* namespace jove */

#endif /* __cplusplus */

#undef IN_JOVE_H
#endif /* JOVE_H */
