#ifndef JOVE_H
#define JOVE_H
#define IN_JOVE_H

#if defined(TARGET_AARCH64)
#include <jove/tcgconstants-aarch64.h>
#elif defined(TARGET_X86_64)
#include <jove/tcgconstants-x86_64.h>
#elif defined(TARGET_I386)
#include <jove/tcgconstants-i386.h>
#elif defined(TARGET_MIPS64)
#include <jove/tcgconstants-mips64el.h>
#elif defined(TARGET_MIPSEL)
#include <jove/tcgconstants-mipsel.h>
#elif defined(TARGET_MIPS)
#include <jove/tcgconstants-mips.h>
#define TARGET_WORDS_BIGENDIAN
#else
#error "unknown target"
#endif

#ifdef __cplusplus
#include "jove/macros.h"
#include "jove/types.h"

#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/breadth_first_search.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <boost/unordered/unordered_map.hpp>
#include <boost/unordered/unordered_node_set.hpp>
#include <boost/unordered/unordered_flat_set.hpp>
#include <boost/unordered/concurrent_flat_map.hpp>
#include <boost/unordered/concurrent_flat_set.hpp>
#include <boost/interprocess/containers/map.hpp>
#include <boost/interprocess/containers/flat_map.hpp>
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
#include <boost/range/iterator_range.hpp>
#include <boost/optional.hpp>
#include <boost/dynamic_bitset.hpp>
//#include <boost/container/scoped_allocator.hpp>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <deque>
#include <execution>
#include <functional>
#include <iomanip>
#include <limits>
#include <map>
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
#include <bit>

namespace llvm {
namespace object {
class Binary;
}
}

namespace jove {

class explorer_t;

static inline std::string taddr2str(taddr_t x, bool zero_padded = true) {
  std::stringstream stream;
  stream << "0x";
  if (zero_padded)
    stream << std::setfill('0') << std::setw(sizeof(taddr_t) * 2);
  stream << std::hex << x;
  return stream.str();
}

enum class TERMINATOR : uint8_t {
  UNKNOWN,
  UNCONDITIONAL_JUMP,
  NONE,
  CALL,
  CONDITIONAL_JUMP,
  INDIRECT_CALL,
  INDIRECT_JUMP,
  RETURN,
  UNREACHABLE
};

typedef uint32_t binary_index_t;
typedef uint32_t function_index_t;
typedef uint32_t basic_block_index_t;

typedef std::pair<binary_index_t, function_index_t> dynamic_target_t;
typedef std::pair<binary_index_t, basic_block_index_t> block_t;

constexpr binary_index_t
    invalid_binary_index = std::numeric_limits<binary_index_t>::max();
constexpr function_index_t
    invalid_function_index = std::numeric_limits<function_index_t>::max();
constexpr basic_block_index_t
    invalid_basic_block_index = std::numeric_limits<basic_block_index_t>::max();
constexpr dynamic_target_t
    invalid_dynamic_target(invalid_binary_index,
                           invalid_function_index);
constexpr block_t
    invalid_block(invalid_binary_index,
                  invalid_basic_block_index);
constexpr taddr_t invalid_taddr = std::numeric_limits<taddr_t>::max();

constexpr bool is_binary_index_valid(binary_index_t idx) {
  return idx != invalid_binary_index;
}
constexpr bool is_function_index_valid(function_index_t idx) {
  return idx != invalid_function_index;
}
constexpr bool is_basic_block_index_valid(basic_block_index_t idx) {
  return idx != invalid_basic_block_index;
}
constexpr bool is_dynamic_target_valid(dynamic_target_t X) {
  return is_binary_index_valid(X.first) &&
         is_function_index_valid(X.second);
}
constexpr bool is_block_valid(block_t X) {
  return is_binary_index_valid(X.first) &&
         is_basic_block_index_valid(X.second);
}
constexpr bool is_taddr_valid(taddr_t Addr) {
  // the following is equivalent to Addr != 0UL && Addr != ~0UL
  return !!((Addr + taddr_t(1)) & taddr_t(~1ull));
}

constexpr unsigned IsMIPSTarget =
#if defined(TARGET_MIPS32) || defined(TARGET_MIPS64)
    1
#else
    0
#endif
    ;

constexpr unsigned IsMips64elTarget =
#if defined(TARGET_MIPS64)
    1
#else
    0
#endif
    ;

constexpr unsigned IsX86Target =
#if defined(TARGET_I386) || defined(TARGET_X86_64)
    1
#else
    0
#endif
    ;

constexpr bool IsTarget32 = sizeof(taddr_t) == 4;

constexpr bool IsTargetLittleEndian =
#if defined(TARGET_MIPS32) && defined(TARGET_MIPS)
    false
#else
    true
#endif
    ;

constexpr const char *TargetStaticLinkerEmulation(bool IsCOFF) {
  if (IsCOFF) {
    return
#if defined(TARGET_X86_64)
        "i386pep"
#elif defined(TARGET_I386)
        "i386pe"
#else
        ""
#endif
        ;
  } else {
    return
#if defined(TARGET_X86_64)
        "elf_x86_64"
#elif defined(TARGET_I386)
        "elf_i386"
#elif defined(TARGET_AARCH64)
        "aarch64linux"
#elif defined(TARGET_MIPS64)
        "elf64ltsmip"
#elif defined(TARGET_MIPS32) && defined(TARGET_MIPSEL)
        "elf32ltsmip"
#elif defined(TARGET_MIPS32) && defined(TARGET_MIPS)
        "elf32btsmip"
#else
#error
#endif
        ;
  }
}

typedef boost::interprocess::managed_mapped_file jv_file_t;
typedef jv_file_t::segment_manager segment_manager_t;

typedef boost::interprocess::allocator<void, segment_manager_t>
    ip_void_allocator_t;

typedef boost::interprocess::interprocess_mutex ip_mutex;
typedef boost::interprocess::interprocess_sharable_mutex ip_sharable_mutex;
typedef boost::interprocess::interprocess_upgradable_mutex ip_upgradable_mutex;

template <typename Mutex>
using ip_scoped_lock = boost::interprocess::scoped_lock<Mutex>;
template <typename Mutex>
using ip_sharable_lock = boost::interprocess::sharable_lock<Mutex>;
template <typename Mutex>
using ip_upgradable_lock = boost::interprocess::upgradable_lock<Mutex>;

struct __do_nothing_t {
  template <typename... Args>
  __do_nothing_t (Args&&...) noexcept {}

  void unlock(void) const {}
  void lock(void) const {}
};

template <typename T>
struct ip_safe_deque {
  using alloc_t = boost::interprocess::allocator<T, segment_manager_t>;
  using deque_t = boost::interprocess::deque<T, alloc_t>;

  deque_t _deque;
  mutable ip_sharable_mutex _mtx;

  ip_safe_deque() = delete;
  ip_safe_deque(const ip_void_allocator_t &A) : _deque(A) {}
  ip_safe_deque(ip_safe_deque<T> &&other)
      : _deque(std::move(other._deque)) {}

  ip_safe_deque<T> &operator=(const ip_safe_deque<T> &other) {
    if (this == &other) {
      return *this;
    }

    _deque = other._deque;
    return *this;
  }

  unsigned size(void) const {
    ip_sharable_lock<ip_sharable_mutex> s_lck(_mtx);
    return _deque.size();
  }

  bool empty(void) const { return size() == 0; }

  T &at(unsigned idx) {
    ip_sharable_lock<ip_sharable_mutex> s_lck(_mtx);
    return _deque.at(idx);
  }

  const T &at(unsigned idx) const {
    ip_sharable_lock<ip_sharable_mutex> s_lck(_mtx);
    return _deque.at(idx);
  }

  /* FIXME */
  typename deque_t::const_iterator cbegin(void) const { return _deque.cbegin(); }
  typename deque_t::const_iterator cend(void) const { return _deque.cend(); }

  typename deque_t::const_iterator begin(void) const { return cbegin(); }
  typename deque_t::const_iterator end(void) const { return cend(); }

  typename deque_t::iterator begin(void) { return _deque.begin(); }
  typename deque_t::iterator end(void) { return _deque.end(); }
};

template <typename Ty>
struct ip_safe_adjacency_list {
  using vertex_descriptor = Ty::vertex_descriptor;
  using edge_descriptor = Ty::edge_descriptor;
  using vertices_size_type = Ty::vertices_size_type;
  using vertex_iterator = Ty::vertex_iterator;
  using degree_size_type = Ty::degree_size_type;
  using adjacency_iterator = Ty::adjacency_iterator;
  using out_edge_iterator = Ty::out_edge_iterator;
  using in_edge_iterator = Ty::in_edge_iterator;
  using inv_adjacency_iterator = Ty::inv_adjacency_iterator;
  using vertex_property_type = Ty::vertex_property_type;

  Ty _adjacency_list;
  mutable ip_sharable_mutex _mtx;

  std::atomic<vertices_size_type> _size = 0;

  template <typename... Args>
  ip_safe_adjacency_list(Args &&...args)
      : _adjacency_list(std::forward<Args>(args)...) {}
  ip_safe_adjacency_list(ip_safe_adjacency_list<Ty> &&other)
      : _adjacency_list(std::move(other._adjacency_list)),
        _size(other._size.load()) {}

  ip_safe_adjacency_list<Ty> &
  operator=(const ip_safe_adjacency_list<Ty> &other) {
    if (this == &other)
      return *this;

    _adjacency_list = other._adjacency_list;
    _size.store(other._size.load());
    return *this;
  }

#define _S_LCK(ShouldLock, Mutex)                                              \
  typename std::conditional<ShouldLock, ip_sharable_lock<ip_sharable_mutex>,   \
                            __do_nothing_t>::type __s_lck##__COUNTER__(Mutex)

#define _E_LCK(ShouldLock, Mutex)                                              \
  typename std::conditional<ShouldLock, ip_scoped_lock<ip_sharable_mutex>,     \
                            __do_nothing_t>::type __e_lck##__COUNTER__(Mutex)

#define S_LCK(ShouldLock) _S_LCK(ShouldLock, this->_mtx)
#define E_LCK(ShouldLock) _E_LCK(ShouldLock, this->_mtx)

  template <typename... Args>
  vertices_size_type index_of_add_vertex(Args &&...args) {
    const vertices_size_type Idx =
        _size.fetch_add(1u, std::memory_order_relaxed);

    if (unlikely(Idx >= actual_num_vertices<true>())) {
      E_LCK(true);

      vertices_size_type actual_size = actual_num_vertices<false>();
      if (Idx >= actual_size) {
        vertices_size_type desired = std::bit_ceil(Idx + 1);
        assert(desired > actual_size);
        for (unsigned i = 0; i < desired - actual_size; ++i)
          boost::add_vertex(_adjacency_list, std::forward<Args>(args)...);
      }
    }

    return Idx;
  }

  template <typename... Args>
  vertex_descriptor add_vertex(Args &&...args) {
    return vertex<false>(index_of_add_vertex(std::forward<Args>(args)...));
  }

  template <bool L = true>
  vertices_size_type actual_num_vertices(void) const {
    S_LCK(L);
    return boost::num_vertices(_adjacency_list);
  }

  vertices_size_type num_vertices(void) const {
    return _size.load(std::memory_order_relaxed);
  }

  bool empty(void) const { return num_vertices() == 0; }

  template <bool L = true>
  vertex_property_type &at(vertex_descriptor V) {
    S_LCK(L);

    if (unlikely(index(V) >= num_vertices()))
      throw std::out_of_range(__PRETTY_FUNCTION__);

    return _adjacency_list[V];
  }

  template <bool L = true>
  const vertex_property_type &at(vertex_descriptor V) const {
    S_LCK(L);

    if (unlikely(index(V) >= num_vertices()))
      throw std::out_of_range(__PRETTY_FUNCTION__);

    return _adjacency_list[V];
  }

  vertex_property_type &operator[](vertex_descriptor V) {
    S_LCK(true);
    return _adjacency_list[V];
  }

  const vertex_property_type &operator[](vertex_descriptor V) const {
    S_LCK(true);
    return _adjacency_list[V];
  }

  template <bool Check = true>
  vertex_descriptor vertex(vertices_size_type Idx) const {
    if (Check)
      assert(Idx < num_vertices()); /* catch bugs */

    // for VertexList=vecS this is just identity map
    return boost::vertex(Idx, _adjacency_list);
  }

  vertices_size_type index(vertex_descriptor V) const {
    // for VertexList=vecS this is just identity map
    return boost::get(boost::vertex_index, _adjacency_list)[V];
  }

  template <bool L = true, class DFSVisitor>
  void depth_first_visit(vertex_descriptor V, DFSVisitor &vis) const {
    std::map<vertex_descriptor, boost::default_color_type> color;

    S_LCK(L);

    boost::depth_first_visit(
        _adjacency_list, V, vis,
        boost::associative_property_map<
            std::map<vertex_descriptor, boost::default_color_type>>(color));
  }

  template <bool L = true, class BFSVisitor>
  void breadth_first_search(vertex_descriptor V, BFSVisitor &vis) const {
    S_LCK(L);

    boost::breadth_first_search(_adjacency_list, V, boost::visitor(vis));
  }

  template <bool L = true>
  degree_size_type out_degree(vertex_descriptor V) const {
    _S_LCK(L, _adjacency_list[V].mtx);

    return boost::out_degree(V, _adjacency_list);
  }

  template <bool L = true>
  void clear_out_edges(vertex_descriptor V) {
    _E_LCK(L, _adjacency_list[V].mtx);

    boost::clear_out_edges(V, _adjacency_list);
  }

  template <bool L = true>
  std::pair<edge_descriptor, bool> add_edge(vertex_descriptor V1,
                                            vertex_descriptor V2) {
    _E_LCK(L, _adjacency_list[V1].mtx);

    return boost::add_edge(V1, V2, _adjacency_list);
  }

  template <bool L = true>
  vertex_descriptor adjacent_front(vertex_descriptor V) const {
    _S_LCK(L, _adjacency_list[V].mtx);

    return *adjacent_vertices(V).first;
  }

  // precondition: out_degree(V) >= N
  template <unsigned N, bool L = true>
  __attribute__((always_inline))
  std::array<vertex_descriptor, N> adjacent_n(vertex_descriptor V) const {
    std::array<vertex_descriptor, N> res;

    {
      _S_LCK(L, _adjacency_list[V].mtx);

      adjacency_iterator it, it_end;
      std::tie(it, it_end) = adjacent_vertices(V);

#pragma clang loop unroll(full)
      for (unsigned i = 0; i < N; ++i)
        res[i] = *it++;
    }

    return res;
  }

#undef _S_LCK
#undef _E_LCK
#undef S_LCK
#undef E_LCK

  /* ********** unsafe methods ********** */

  template <bool L = true>
  std::pair<vertex_iterator, vertex_iterator> vertices(void) const {
    auto res = boost::vertices(_adjacency_list);
    std::advance(res.second, -(actual_num_vertices() - num_vertices()));
    return res;
  }
  std::pair<adjacency_iterator, adjacency_iterator>
  adjacent_vertices(vertex_descriptor V) const {
    return boost::adjacent_vertices(V, _adjacency_list);
  }
  std::pair<inv_adjacency_iterator, inv_adjacency_iterator>
  inv_adjacent_vertices(vertex_descriptor V) const {
    return boost::inv_adjacent_vertices(V, _adjacency_list);
  }
  std::pair<out_edge_iterator, out_edge_iterator>
  out_edges(vertex_descriptor V) const {
    return boost::out_edges(V, _adjacency_list);
  }
  std::pair<in_edge_iterator, in_edge_iterator>
  in_edges(vertex_descriptor V) const {
    return boost::in_edges(V, _adjacency_list);
  }
};

typedef boost::interprocess::allocator<char, segment_manager_t>
    ip_char_allocator;
typedef boost::interprocess::basic_string<char, std::char_traits<char>, ip_char_allocator>
    ip_string;

static inline std::string un_ips(const ip_string &x) {
  std::string res;
  res.reserve(x.size());
  std::copy(x.begin(), x.end(), std::back_inserter(res));
  return res;
}

static inline ip_string &to_ips(ip_string &res, const std::string &x) {
  res.clear();
  res.reserve(x.size());
  std::copy(x.begin(), x.end(), std::back_inserter(res));
  return res;
}

typedef boost::concurrent_flat_set<
    dynamic_target_t, boost::hash<dynamic_target_t>,
    std::equal_to<dynamic_target_t>,
    boost::interprocess::allocator<dynamic_target_t, segment_manager_t>>
    ip_dynamic_target_set;

typedef boost::interprocess::set<
    binary_index_t, std::less<binary_index_t>,
    boost::interprocess::allocator<binary_index_t, segment_manager_t>>
    ip_binary_index_set;

typedef boost::unordered_flat_set<dynamic_target_t> dynamic_target_set;

typedef std::pair<taddr_t, taddr_t> addr_intvl; /* right open interval */

struct addr_intvl_cmp {
  typedef void is_transparent;

  bool operator()(const addr_intvl &lhs, const addr_intvl &rhs) const {
    return lhs.first < rhs.first;
  }

  bool operator()(const addr_intvl &lhs, taddr_t rhs) const {
    return lhs.first < rhs;
  }

  bool operator()(taddr_t lhs, const addr_intvl &rhs) const {
    return lhs < rhs.first;
  }
};

typedef boost::container::flat_map<addr_intvl, binary_index_t, addr_intvl_cmp>
    address_space_t;

struct binary_t;

struct allocates_basic_block_t {
  basic_block_index_t BBIdx = invalid_basic_block_index;

  allocates_basic_block_t () = default;

  // allocates (creates) new basic block in binary, stores index
  inline allocates_basic_block_t(binary_t &b, basic_block_index_t &store,
                                 taddr_t Addr);

  operator basic_block_index_t() const { return BBIdx; }
};

typedef boost::concurrent_flat_map<
    taddr_t, allocates_basic_block_t, boost::hash<taddr_t>, std::equal_to<taddr_t>,
    boost::interprocess::allocator<std::pair<const taddr_t, basic_block_index_t>,
                                   segment_manager_t>>
    bbbmap_t;

typedef boost::interprocess::flat_map<
    addr_intvl, basic_block_index_t, addr_intvl_cmp,
    boost::interprocess::allocator<std::pair<addr_intvl, basic_block_index_t>,
                                   segment_manager_t>>
    bbmap_t;

struct allocates_function_t {
  function_index_t FIdx = invalid_function_index;

  allocates_function_t() = default;

  // allocates (creates) new function in binary, stores index
  inline allocates_function_t(binary_t &b, function_index_t &store);

  operator function_index_t() const { return FIdx; }
};

typedef boost::concurrent_flat_map<
    taddr_t, allocates_function_t, boost::hash<taddr_t>, std::equal_to<taddr_t>,
    boost::interprocess::allocator<std::pair<const taddr_t, function_index_t>,
                                   segment_manager_t>>
    fnmap_t;

typedef boost::unordered::unordered_flat_set<
    function_index_t, boost::hash<function_index_t>,
    std::equal_to<function_index_t>>
    func_index_set;

typedef boost::unordered::unordered_flat_set<
    function_index_t, boost::hash<function_index_t>,
    std::equal_to<function_index_t>,
    boost::interprocess::allocator<function_index_t, segment_manager_t>>
    ip_func_index_set;

typedef boost::unordered_node_set<
    ip_func_index_set, boost::hash<ip_func_index_set>,
    std::equal_to<ip_func_index_set>,
    boost::interprocess::allocator<function_index_t, segment_manager_t>>
    ip_func_index_sets;

struct jv_t;
size_t jvDefaultInitialSize(void);

struct basic_block_properties_t {
  mutable ip_sharable_mutex mtx;
  struct {
    int is = 0;
    mutable ip_sharable_mutex mtx;
  } pub;

  bool Speculative = false;

  taddr_t Addr = ~0UL;
  uint32_t Size = ~0UL;

  struct {
    taddr_t Addr = ~0UL;
    TERMINATOR Type = TERMINATOR::UNKNOWN;

    struct {
      function_index_t Target = invalid_function_index;
    } _call;

    struct {
      bool IsLj;
    } _indirect_jump;

    struct {
    } _indirect_call;

    struct {
      bool Returns;
    } _return;
  } Term;

  ip_dynamic_target_set DynTargets;
  bool DynTargetsComplete = false;

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

    bool Stale = true;
  } Analysis;

  struct {
    mutable ip_sharable_mutex _mtx;
    boost::interprocess::offset_ptr<const ip_func_index_set> _p;
  } Parents;

  bool hasDynTarget(void) const {
    return !DynTargets.empty();
  }
  unsigned getNumDynTargets(void) const {
    return DynTargets.size();
  }
  bool insertDynTarget(binary_index_t ThisBIdx, const dynamic_target_t &, jv_t &);
  bool DynTargetsAnyOf(std::function<bool(const dynamic_target_t &)> proc) const {
    bool res = false;
    DynTargets.cvisit_while([&](const dynamic_target_t &X) -> bool {
      if (proc(X)) {
        res = true;
        return false;
      }
      return true;
    });
    return res;
  }
  bool DynTargetsAllOf(std::function<bool(const dynamic_target_t &)> proc) const {
    bool res = true;
    DynTargets.cvisit_while([&](const dynamic_target_t &X) -> bool {
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

    DynTargets.cvisit_while([&](const dynamic_target_t &X) -> bool {
      res = X;
      return false;
    });

    assert(is_dynamic_target_valid(res));
    return res;
  }

  bool HasParent(void) const;
  bool IsParent(function_index_t) const;
  void AddParent(function_index_t, jv_t &);
  void GetParents(func_index_set &) const;

  bool IsSingleInstruction(void) const { return Addr == Term.Addr; }

  void InvalidateAnalysis(void) {
    this->Analysis.Stale = true;
  }

  basic_block_properties_t(const ip_void_allocator_t &A) : DynTargets(A) {}

  basic_block_properties_t &operator=(const basic_block_properties_t &other) {
    pub.is = other.pub.is;
    Speculative = other.Speculative;
    Addr = other.Addr;
    Size = other.Size;
    Term = other.Term;
    DynTargets = other.DynTargets;
    DynTargetsComplete = other.DynTargetsComplete;
    Sj = other.Sj;
    Analysis = other.Analysis;
    Parents._p = other.Parents._p;

    return *this;
  }
};

typedef boost::adjacency_list<boost::setS_ip,           /* OutEdgeList */
                              boost::dequeS_ip,         /* VertexList */
                              boost::directedS,         /* Directed */
                              basic_block_properties_t, /* VertexProperties */
                              boost::no_property,       /* EdgeProperties */
                              boost::no_property,       /* GraphProperties */
                              boost::listS_ip>          /* EdgeList */
    interprocedural_control_flow_graph_t;

typedef interprocedural_control_flow_graph_t icfg_t;

typedef interprocedural_control_flow_graph_t::vertex_descriptor basic_block_t;
typedef interprocedural_control_flow_graph_t::edge_descriptor control_flow_t;

typedef std::vector<basic_block_t> basic_block_vec_t;

static inline basic_block_t NullBasicBlock(void) {
  return boost::graph_traits<
      interprocedural_control_flow_graph_t>::null_vertex();
}

typedef ip_safe_adjacency_list<icfg_t> ip_icfg_t;

template <bool L = true>
constexpr bool IsDefinitelyTailCall(const ip_icfg_t &ICFG, basic_block_t bb) {
  assert(ICFG.at<L>(bb).Term.Type == TERMINATOR::INDIRECT_JUMP); /* catch bugs */
  //WARN_ON(ICFG.out_degree<L>(bb) > 0); /* catch bugs */
  return ICFG.at<L>(bb).hasDynTarget();
}

template <bool L = true>
constexpr bool IsAmbiguousIndirectJump(const ip_icfg_t &ICFG, basic_block_t bb) {
  assert(ICFG.at<L>(bb).Term.Type == TERMINATOR::INDIRECT_JUMP); /* catch bugs */
  return ICFG.at<L>(bb).hasDynTarget() && ICFG.out_degree<L>(bb) > 0;
}

template <bool L = true>
constexpr bool IsExitBlock(const ip_icfg_t &ICFG, basic_block_t bb) {
  auto T = ICFG.at<L>(bb).Term.Type;

  return T == TERMINATOR::RETURN ||
        (T == TERMINATOR::INDIRECT_JUMP &&
         IsDefinitelyTailCall<L>(ICFG, bb));
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
typedef boost::concurrent_flat_set<
    caller_t, boost::hash<caller_t>, std::equal_to<caller_t>,
    boost::interprocess::allocator<caller_t, segment_manager_t>>
    ip_callers;

struct binary_t;

struct function_t {
  bool Speculative = false;

  boost::interprocess::offset_ptr<binary_t> b;

  function_index_t Idx = invalid_function_index;

  basic_block_index_t Entry = invalid_basic_block_index;

  ip_callers Callers;

  struct Analysis_t {
    tcg_global_set_t args;
    tcg_global_set_t rets;

    bool Stale = true;
  } Analysis;

  bool IsABI, IsSignalHandler, Returns;

  void InvalidateAnalysis(void) {
    this->Analysis.Stale = true;
  }

  function_t(binary_t &, function_index_t);
  function_t(const ip_void_allocator_t &); /* XXX */
  function_t() = delete;
};

#include "jove/objdump.h"

struct binary_t {
  binary_index_t Idx = invalid_binary_index;

  bbbmap_t bbbmap;

  bbmap_t bbmap;
  fnmap_t fnmap;

  ip_string Name;
  ip_string Data;
  hash_t Hash;

  bool IsDynamicLinker, IsExecutable, IsVDSO;

  bool IsPIC;

  bool IsDynamicallyLoaded;

  ip_sharable_mutex bbmap_mtx;

  struct Analysis_t {
    function_index_t EntryFunction = invalid_function_index;

    //
    // references to function_t will never be invalidated.
    //
    ip_safe_deque<function_t> Functions;

    //
    // references to basic_block_properties_t will never be invalidated
    // (although their fields are subject to change: see explorer_t::split() in
    //  core/explore.cpp)
    ip_safe_adjacency_list<interprocedural_control_flow_graph_t> ICFG;

    Analysis_t() = delete;
    Analysis_t(const ip_void_allocator_t &A)
        : Functions(A), ICFG(icfg_t::graph_property_type(), A), objdump(A) {}

    Analysis_t(Analysis_t &&other)
        : EntryFunction(std::move(other.EntryFunction)),
          Functions(std::move(other.Functions)),
          ICFG(std::move(other.ICFG)),
          objdump(std::move(other.objdump)) {}

    Analysis_t &operator=(const Analysis_t &other) {
      if (this == &other)
        return *this;

      EntryFunction = other.EntryFunction;
      Functions = other.Functions;
      ICFG = other.ICFG;
      objdump = other.objdump;
      return *this;
    }

    /*** may have use in future ***/
    void addSymDynTarget(const std::string &sym, dynamic_target_t X) {}
    void addRelocDynTarget(taddr_t A, dynamic_target_t X) {}
    void addIFuncDynTarget(taddr_t A, dynamic_target_t X) {}

    typedef objdump_output_t<
        true, boost::interprocess::allocator<unsigned long, segment_manager_t>>
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
  bool FixAmbiguousIndirectJump(taddr_t TermAddr, explorer_t &,
                                llvm::object::Binary &, jv_t &);

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

  ip_void_allocator_t get_allocator(void) {
    return Analysis.Functions._deque.get_allocator();
  }

  binary_t(const ip_void_allocator_t &A, binary_index_t Idx = invalid_binary_index)
      : Idx(Idx), bbbmap(A), bbmap(A), fnmap(A), Name(A), Data(A), Analysis(A) {}

  binary_t(binary_t &&other)
      : Idx(other.Idx),

        bbbmap(std::move(other.bbbmap)),
        bbmap(std::move(other.bbmap)),
        fnmap(std::move(other.fnmap)),

        Name(std::move(other.Name)),
        Data(std::move(other.Data)),
        Hash(std::move(other.Hash)),

        IsDynamicLinker(other.IsDynamicLinker),
        IsExecutable(other.IsExecutable),
        IsVDSO(other.IsVDSO),
        IsPIC(other.IsPIC),
        IsDynamicallyLoaded(other.IsDynamicallyLoaded),

        Analysis(std::move(other.Analysis)) {}

  binary_t &operator=(const binary_t &other) {
    if (this == &other) {
      return *this;
    }

    Idx = other.Idx;

    bbbmap = other.bbbmap;
    bbmap = other.bbmap;
    fnmap = other.fnmap;

    Name = other.Name;
    Data = other.Data;
    Hash = other.Hash;

    IsDynamicLinker = other.IsDynamicLinker;
    IsExecutable = other.IsExecutable;
    IsVDSO = other.IsVDSO;
    IsPIC = other.IsPIC;
    IsDynamicallyLoaded = other.IsDynamicallyLoaded;

    Analysis = other.Analysis;

    return *this;
  }

  binary_t() = delete;
};

struct objdump_exception {
  taddr_t Addr;
  objdump_exception(taddr_t Addr) : Addr(Addr) {}
};

allocates_basic_block_t::allocates_basic_block_t(binary_t &b,
                                                 basic_block_index_t &store,
                                                 taddr_t Addr) {
#if 0
  if (unlikely(b.Analysis.objdump.is_addr_bad(Addr)))
    throw objdump_exception(Addr);
#endif

  auto &ICFG = b.Analysis.ICFG;

  basic_block_index_t Idx = ICFG.index_of_add_vertex(b.get_allocator());
  auto &bbprop = ICFG[ICFG.vertex<false>(Idx)];
  bbprop.Addr = Addr;

  bool success;

  success = bbprop.pub.mtx.try_lock();
  assert(success);
  success = bbprop.mtx.try_lock();
  assert(success);

  store = Idx;
  BBIdx = Idx;
}

allocates_function_t::allocates_function_t(binary_t &b,
                                           function_index_t &store) {
  ip_safe_deque<function_t> &Functions = b.Analysis.Functions;

  {
    ip_scoped_lock<ip_sharable_mutex> e_lck(Functions._mtx);

    FIdx = Functions._deque.size();
    Functions._deque.emplace_back(b, FIdx);
  }

  store = FIdx;
}

typedef boost::interprocess::allocator<binary_t, segment_manager_t>
    ip_binary_allocator;
typedef boost::interprocess::deque<binary_t, ip_binary_allocator>
    ip_binary_deque;

struct cached_hash_t {
  hash_t h;

  struct {
    int64_t sec = 0, nsec = 0;
  } mtime;
};

typedef boost::unordered_map<
    ip_string, cached_hash_t, boost::hash<ip_string>, std::equal_to<ip_string>,
    boost::interprocess::allocator<std::pair<const ip_string, cached_hash_t>,
                                   segment_manager_t>>
    ip_cached_hashes_type;

typedef boost::unordered_map<
    hash_t, binary_index_t, boost::hash<hash_t>, std::equal_to<hash_t>,
    boost::interprocess::allocator<std::pair<const hash_t, binary_index_t>,
                                   segment_manager_t>>
    ip_hash_to_binary_map_type;

typedef boost::unordered_map<
    ip_string, ip_binary_index_set, boost::hash<ip_string>,
    std::equal_to<ip_string>,
    boost::interprocess::allocator<
        std::pair<const ip_string, ip_binary_index_set>, segment_manager_t>>
    ip_name_to_binaries_map_type;

typedef std::function<void(binary_t &)> on_newbin_proc_t;

struct jv_t {
  //
  // references to binary_t will never be invalidated.
  //
  ip_safe_deque<binary_t> Binaries;

  ip_func_index_sets FIdxSets;
  ip_sharable_mutex FIdxSetsMtx;

  ip_hash_to_binary_map_type hash_to_binary;
  ip_cached_hashes_type cached_hashes; /* NOT serialized */

  ip_name_to_binaries_map_type name_to_binaries;

  ip_sharable_mutex hash_to_binary_mtx;
  ip_mutex cached_hashes_mtx;
  ip_sharable_mutex name_to_binaries_mtx;

  void InvalidateFunctionAnalyses(void);

  void clear(bool everything = false);

  ip_void_allocator_t get_allocator(void) {
    return Binaries._deque.get_allocator();
  }

  jv_t(const ip_void_allocator_t &A)
      : Binaries(A), FIdxSets(A), hash_to_binary(A), cached_hashes(A),
        name_to_binaries(A) {}

  jv_t() = delete;

  boost::optional<binary_index_t> LookupByHash(const hash_t &h);
  boost::optional<const ip_binary_index_set &> Lookup(const char *name);

  std::pair<binary_index_t, bool>
  AddFromPath(explorer_t &,
              const char *path,
              const binary_index_t TargetIdx = invalid_binary_index,
              on_newbin_proc_t on_newbin = [](binary_t &) {});
  std::pair<binary_index_t, bool>
  AddFromData(explorer_t &,
              std::string_view data,
              const char *name = nullptr,
              const binary_index_t TargetIdx = invalid_binary_index,
              on_newbin_proc_t on_newbin = [](binary_t &) {});

  unsigned NumBinaries(void) {
    return Binaries.size();
  }

private:
  hash_t LookupAndCacheHash(const char *path,
                            std::string &file_contents);
  void UpdateCachedHash(cached_hash_t &,
                        const char *path,
                        std::string &file_contents);

  typedef std::function<void(ip_string &)> get_data_t;

  std::pair<binary_index_t, bool> AddFromDataWithHash(explorer_t &E, get_data_t,
                                                      const hash_t &h,
                                                      const char *name,
                                                      const binary_index_t TargetIdx,
                                                      on_newbin_proc_t on_newbin);
  void DoAdd(binary_t &, explorer_t &);
};

static inline const char *string_of_terminator(TERMINATOR TermTy) {
  switch (TermTy) {
  case TERMINATOR::UNKNOWN:
    return "UNKNOWN";
  case TERMINATOR::UNCONDITIONAL_JUMP:
    return "UNCONDITIONAL_JUMP";
  case TERMINATOR::CONDITIONAL_JUMP:
    return "CONDITIONAL_JUMP";
  case TERMINATOR::INDIRECT_CALL:
    return "INDIRECT_CALL";
  case TERMINATOR::INDIRECT_JUMP:
    return "INDIRECT_JUMP";
  case TERMINATOR::CALL:
    return "CALL";
  case TERMINATOR::RETURN:
    return "RETURN";
  case TERMINATOR::UNREACHABLE:
    return "UNREACHABLE";
  case TERMINATOR::NONE:
    return "NONE";
  }

  return "";
}

static inline const char *description_of_terminator(TERMINATOR TermTy) {
  switch (TermTy) {
  case TERMINATOR::UNKNOWN:
    return "<?>";
  case TERMINATOR::UNCONDITIONAL_JUMP:
    return "<unconditional jump>";
  case TERMINATOR::CONDITIONAL_JUMP:
    return "<conditional jump>";
  case TERMINATOR::INDIRECT_CALL:
    return "<indirect call>";
  case TERMINATOR::INDIRECT_JUMP:
    return "<indirect jump>";
  case TERMINATOR::CALL:
    return "<call>";
  case TERMINATOR::RETURN:
    return "<return>";
  case TERMINATOR::UNREACHABLE:
    return "<unreachable>";
  case TERMINATOR::NONE:
    return "<none>";
  }

  return "";
}

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

struct terminator_info_t {
  TERMINATOR Type;
  taddr_t Addr;

  struct {
    struct {
      taddr_t Target;
    } _unconditional_jump;

    struct {
      taddr_t Target;
      taddr_t NextPC;
    } _conditional_jump;

    struct {
      taddr_t Target;
      taddr_t NextPC;
    } _call;

    struct {
      taddr_t NextPC;
    } _indirect_call;

    struct {
      /* deliberately left empty */
    } _indirect_jump;

    struct {
      /* deliberately left empty */
    } _return;

    struct {
      /* deliberately left empty */
    } _unreachable;

    struct {
      taddr_t NextPC;
    } _none;
  };
};

static inline std::string
description_of_terminator_info(const terminator_info_t &T,
                               bool zero_padded = true) {
  std::string res;
  res += description_of_terminator(T.Type);
  res += " @ ";
  res += taddr2str(T.Addr, zero_padded);
  res += " {";

  switch (T.Type) {
  case TERMINATOR::UNKNOWN:
    break;
  case TERMINATOR::UNCONDITIONAL_JUMP:
    res += " -> ";
    res += taddr2str(T._unconditional_jump.Target, zero_padded);
    break;
  case TERMINATOR::CONDITIONAL_JUMP:
    res += " -> ";
    res += taddr2str(T._conditional_jump.Target, zero_padded);
    res += ", ";
    res += taddr2str(T._conditional_jump.NextPC, zero_padded);
    break;
  case TERMINATOR::INDIRECT_CALL:
    res += " ->_ ";
    res += taddr2str(T._indirect_call.NextPC, zero_padded);
    break;
  case TERMINATOR::INDIRECT_JUMP:
    break;
  case TERMINATOR::CALL:
    res += " -> ";
    res += taddr2str(T._call.Target, zero_padded);
    res += ", ";
    res += " ->_ ";
    res += taddr2str(T._call.NextPC, zero_padded);
    break;
  case TERMINATOR::RETURN:
    break;
  case TERMINATOR::UNREACHABLE:
    break;
  case TERMINATOR::NONE:
    res += " _->_ ";
    res += taddr2str(T._none.NextPC, zero_padded);
    break;
  }

  res += "}";

  return res;
}

constexpr basic_block_t basic_block_of_index(basic_block_index_t BBIdx,
                                             const ip_icfg_t &ICFG) {
  assert(is_basic_block_index_valid(BBIdx));
  return ICFG.vertex(BBIdx);
}

constexpr basic_block_t basic_block_of_index(basic_block_index_t BBIdx,
                                             const binary_t &b) {
  const auto &ICFG = b.Analysis.ICFG;
  return basic_block_of_index(BBIdx, ICFG);
}

template <typename _ExecutionPolicy, typename Iter, typename Pred, typename Proc>
constexpr
void for_each_if(_ExecutionPolicy &&__exec, Iter first, Iter last, Pred pred, Proc proc) {
  std::for_each(std::forward<_ExecutionPolicy>(__exec), first, last,
                [pred, proc](auto &elem) {
                  if (pred(elem)) {
                    proc(elem);
                  }
                });
}

template <typename Iter, typename Pred, typename Proc>
constexpr
void for_each_if(Iter first, Iter last, Pred pred, Proc proc) {
  std::for_each(first, last,
                [pred, proc](auto &elem) {
                  if (pred(elem)) {
                    proc(elem);
                  }
                });
}

static inline std::string addr_intvl2str(addr_intvl intvl) {
  return "[" +
         taddr2str(intvl.first, false) + ", " +
         taddr2str(intvl.first + intvl.second, false) + ")";
}

constexpr addr_intvl right_open_addr_intvl(taddr_t lower, taddr_t upper) {
  assert(upper > lower);
  return addr_intvl(lower, upper - lower);
}

constexpr taddr_t addr_intvl_lower(addr_intvl intvl) {
  return intvl.first;
}

constexpr taddr_t addr_intvl_upper(addr_intvl intvl) {
  return intvl.first + intvl.second;
}

constexpr bool addr_intvl_contains(addr_intvl intvl, taddr_t Addr) {
  return Addr >= intvl.first && Addr < intvl.first + intvl.second;
}

constexpr bool addr_intvl_intersects(addr_intvl x, addr_intvl y) {
  taddr_t a = addr_intvl_lower(x), b = addr_intvl_upper(x);
  taddr_t c = addr_intvl_lower(y), d = addr_intvl_upper(y);

  if (b <= c || d <= a)
    return false;

  return true;
}

constexpr bool addr_intvl_intersects(addr_intvl intvl, taddr_t Addr) {
  return addr_intvl_contains(intvl, Addr);
}

constexpr bool addr_intvl_disjoint(addr_intvl x, addr_intvl y) {
  return !addr_intvl_intersects(x, y);
}

constexpr addr_intvl addr_intvl_hull(addr_intvl x, addr_intvl y) {
  taddr_t L_1 = addr_intvl_lower(x);
  taddr_t L_2 = addr_intvl_lower(y);

  taddr_t U_1 = addr_intvl_upper(x);
  taddr_t U_2 = addr_intvl_upper(y);

  return right_open_addr_intvl(std::min(L_1, L_2), std::max(U_1, U_2));
}

template <typename OrderedIntvlMap, typename T>
constexpr auto intvl_map_find(OrderedIntvlMap &map, T x) {
  if (unlikely(map.empty()))
    return map.end();

  auto it = map.upper_bound(x);

  if (it != map.end() && addr_intvl_intersects((*it).first, x))
    return it;

  if (it == map.begin())
    return map.end();

  --it;

  if (addr_intvl_intersects((*it).first, x))
    return it;

  return map.end();
}

template <typename OrderedIntvlMap, typename T>
constexpr bool intvl_map_contains(OrderedIntvlMap &map, T x) {
  return intvl_map_find(map, x) != map.end();
}

template <typename OrderedIntvlMap, typename Value>
constexpr auto intvl_map_add(OrderedIntvlMap &map,
                             addr_intvl intvl,
                             Value &&val) {
  auto x = map.insert(typename OrderedIntvlMap::value_type(intvl, std::move(val)));

  assert(x.second);
  return x.first;
}

template <typename OrderedIntvlMap>
constexpr void intvl_map_clear(OrderedIntvlMap &map, addr_intvl intvl) {
  const taddr_t L2 = addr_intvl_lower(intvl);
  const taddr_t U2 = addr_intvl_upper(intvl);

  for (;;) {
    auto it = intvl_map_find(map, intvl);
    if (it == map.end())
      break;

    auto val = (*it).second;

    const taddr_t L1 = addr_intvl_lower((*it).first);
    const taddr_t U1 = addr_intvl_upper((*it).first);

    map.erase(it);

    if (L1 >= L2 && U1 <= U2) {
      //
      //   {   [    ]   }
      //   L2  L1  U1   U2
      //
      ;
    } else if (L1 <= L2 && U1 >= U2) {
      //
      //   [   {    }   ]
      //   L1  L2   U2  U1
      //
      if (L2 > L1) {
        addr_intvl left_intvl = right_open_addr_intvl(L1, L2);
        intvl_map_add(map, left_intvl, val);
      }
      if (U1 > U2) {
        addr_intvl right_intvl = right_open_addr_intvl(U2, U1);
        intvl_map_add(map, right_intvl, val);
      }
    } else if (L1 < L2 && U1 > L2 && U1 <= U2) {
      //
      //   [   {    ]   }
      //   L1  L2   U1  U2
      //
      addr_intvl new_intvl = right_open_addr_intvl(L1, L2);
      intvl_map_add(map, new_intvl, val);
    } else if (L1 >= L2 && L1 < U2 && U1 > U2) {
      //
      //   {   [    }   ]
      //   L2  L1   U2  U1
      //
      addr_intvl new_intvl = right_open_addr_intvl(U2, U1);
      intvl_map_add(map, new_intvl, val);
    } else {
      abort();
    }
  }
}

template <typename OrderedIntvlMap>
constexpr void intvl_map_clear_all(OrderedIntvlMap &map, addr_intvl intvl) {
  for (;;) {
    auto it = intvl_map_find(map, intvl);
    if (it == map.end())
      break;
    else
      map.erase(it);
  }
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

template <class _ExecutionPolicy, class Pred, class Proc>
constexpr
void for_each_function_if_in_binary(_ExecutionPolicy &&__exec,
                                    binary_t &b,
                                    Pred pred,
                                    Proc proc) {
  for_each_if(std::forward<_ExecutionPolicy>(__exec),
              b.Analysis.Functions.begin(),
              b.Analysis.Functions.end(), pred, proc);
}


template <class _ExecutionPolicy, class Proc>
constexpr
void for_each_function_in_binary(_ExecutionPolicy &&__exec,
                                 binary_t &b,
                                 Proc proc) {
  std::for_each(std::forward<_ExecutionPolicy>(__exec),
                b.Analysis.Functions.begin(),
                b.Analysis.Functions.end(), proc);
}

template <class _ExecutionPolicy, class Proc>
constexpr
void for_each_function_in_binary(_ExecutionPolicy &&__exec,
                                 const binary_t &b,
                                 Proc proc) {
  std::for_each(std::forward<_ExecutionPolicy>(__exec),
                b.Analysis.Functions.begin(),
                b.Analysis.Functions.end(), proc);
}

template <class Proc>
constexpr
void for_each_function_in_binary(binary_t &b,
                                 Proc proc) {
  std::for_each(b.Analysis.Functions.begin(),
                b.Analysis.Functions.end(), proc);
}

template <class Proc>
constexpr
void for_each_function_in_binary(const binary_t &b,
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

template <class _ExecutionPolicy, class Proc>
static inline
void for_each_basic_block_in_binary(_ExecutionPolicy &&__exec,
                                    binary_t &b,
                                    Proc proc) {
  icfg_t::vertex_iterator it, it_end;
  std::tie(it, it_end) = b.Analysis.ICFG.vertices();

  std::for_each(std::forward<_ExecutionPolicy>(__exec),
               it, it_end, [proc](basic_block_t bb) { proc(bb); });
}

template <class _ExecutionPolicy, class Proc>
static inline
void for_each_basic_block_in_binary(_ExecutionPolicy &&__exec,
                                    const binary_t &b,
                                    Proc proc) {
  icfg_t::vertex_iterator it, it_end;
  std::tie(it, it_end) = b.Analysis.ICFG.vertices();

  std::for_each(std::forward<_ExecutionPolicy>(__exec),
               it, it_end, [proc](basic_block_t bb) { proc(bb); });
}

template <class Proc>
static inline
void for_each_basic_block_in_binary(binary_t &b, Proc proc) {
  icfg_t::vertex_iterator it, it_end;
  std::tie(it, it_end) = b.Analysis.ICFG.vertices();

  std::for_each(it, it_end, [proc](basic_block_t bb) { proc(bb); });
}

template <class Proc>
static inline
void for_each_basic_block_in_binary(const binary_t &b, Proc proc) {
  icfg_t::vertex_iterator it, it_end;
  std::tie(it, it_end) = b.Analysis.ICFG.vertices();

  std::for_each(it, it_end, [proc](basic_block_t bb) { proc(bb); });
}

constexpr basic_block_index_t index_of_basic_block(const ip_icfg_t &ICFG,
                                                   basic_block_t bb) {
  return ICFG.index(bb);
}

constexpr basic_block_index_t index_of_basic_block(const binary_t &b,
                                                   basic_block_t bb) {
  return index_of_basic_block(b.Analysis.ICFG, bb);
}

constexpr binary_index_t binary_index_of_function(const function_t &f) {
  assert(f.b);
  binary_index_t res = f.b->Idx;
  assert(is_binary_index_valid(res));
  return res;
}

[[deprecated]] /* use binary_index_of_function(f) */
constexpr binary_index_t binary_index_of_function(const function_t &f,
                                                  const jv_t &jv) {
  return binary_index_of_function(f);
}

constexpr binary_index_t index_of_binary(const binary_t &b) {
  binary_index_t res = b.Idx;
  assert(is_binary_index_valid(res));
  return res;
}

[[deprecated]] /* use index_of_binary(b) */
constexpr binary_index_t index_of_binary(const binary_t &b, const jv_t &jv) {
  return index_of_binary(b);
}

constexpr function_index_t index_of_function(const function_t &f) {
  function_index_t res = f.Idx;
  assert(is_function_index_valid(res));
  return res;
}

[[deprecated]] /* use index_of_function(f) */
constexpr function_index_t index_of_function_in_binary(const function_t &f,
                                                       const binary_t &b) {
  return index_of_function(f);
}

constexpr const binary_t &binary_of_function(const function_t &f) {
  assert(f.b);
  return *f.b.get();
}

constexpr binary_t &binary_of_function(function_t &f) {
  assert(f.b);
  return *f.b.get();
}

[[deprecated]] /* use binary_of_function(f) */
constexpr const binary_t &binary_of_function(const function_t &f,
                                             const jv_t &jv) {
  return binary_of_function(f);
}

constexpr function_t &function_of_target(dynamic_target_t X, jv_t &jv) {
  return jv.Binaries.at(X.first).Analysis.Functions.at(X.second);
}

static inline void basic_blocks_of_function_at_block(basic_block_t entry,
                                                     const binary_t &b,
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

static inline void basic_blocks_of_function(const function_t &f,
                                            const binary_t &b,
                                            basic_block_vec_t &out) {

  const auto &ICFG = b.Analysis.ICFG;

  basic_blocks_of_function_at_block(basic_block_of_index(f.Entry, ICFG), b, out);
}

static inline void exit_basic_blocks_of_function(const function_t &f,
                                                 const binary_t &b,
                                                 const basic_block_vec_t &bbvec,
                                                 basic_block_vec_t &out) {
  const auto &ICFG = b.Analysis.ICFG;

  out.reserve(bbvec.size());

  std::copy_if(bbvec.begin(),
               bbvec.end(),
               std::back_inserter(out),
               [&](basic_block_t bb) -> bool { return IsExitBlock(ICFG, bb); });
}

static inline bool does_function_return_fast(const icfg_t &ICFG,
                                             const basic_block_vec_t &bbvec) {
  return std::any_of(bbvec.begin(),
                     bbvec.end(),
                     [&](basic_block_t bb) -> bool {
                       return IsExitBlock(ICFG, bb);
                     });
}

static inline bool does_function_at_block_return(basic_block_t entry,
                                                 const binary_t &b) {
  basic_block_vec_t bbvec;
  basic_blocks_of_function_at_block(entry, b, bbvec);

  const auto &ICFG = b.Analysis.ICFG;

  return std::any_of(bbvec.begin(),
                     bbvec.end(),
                     [&](basic_block_t bb) -> bool {
                       return IsExitBlock(ICFG, bb);
                     });
}

static inline bool does_function_return(const function_t &f,
                                        const binary_t &b) {
  return does_function_at_block_return(basic_block_of_index(f.Entry, b), b);
}

static inline bool IsLeafFunction(const function_t &f,
                                  const binary_t &b,
                                  const basic_block_vec_t &bbvec) {
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

  {
    basic_block_vec_t exit_bbvec;
    exit_basic_blocks_of_function(f, b, bbvec, exit_bbvec);

    return std::all_of(exit_bbvec.begin(),
                       exit_bbvec.end(),
                       [&](basic_block_t bb) -> bool {
                         auto T = ICFG[bb].Term.Type;
                         return T == TERMINATOR::RETURN
                             || T == TERMINATOR::UNREACHABLE;
                       });
  }
}

static inline bool IsFunctionSetjmp(const function_t &f,
                                    const binary_t &b,
                                    const basic_block_vec_t &bbvec) {
  const auto &ICFG = b.Analysis.ICFG;

  return std::any_of(bbvec.begin(),
                     bbvec.end(),
                     [&](basic_block_t bb) -> bool {
                       return ICFG[bb].Sj;
                     });
}

static inline bool IsFunctionLongjmp(const function_t &f,
                                     const binary_t &b,
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

static inline basic_block_index_t
index_of_basic_block_at_address(taddr_t Addr, const binary_t &b) {
  auto it = bbmap_find(b.bbmap, Addr);
  assert(it != b.bbmap.end());
  return (*it).second;
}

static inline basic_block_index_t
index_of_basic_block_starting_at_address(taddr_t Addr, const binary_t &b) {
  basic_block_index_t res = invalid_basic_block_index;
  bool found = b.bbbmap.cvisit(Addr, [&](const auto &x) { res = x.second; });

  assert(found);
  return res;
}

template <bool L = true>
static inline basic_block_t
basic_block_starting_at_address(taddr_t Addr, const binary_t &b) {
  return basic_block_of_index(index_of_basic_block_starting_at_address(Addr, b), b);
}

template <bool L = true>
static inline basic_block_t basic_block_at_address(taddr_t Addr,
                                                   const binary_t &b) {
  return basic_block_of_index(index_of_basic_block_at_address(Addr, b), b);
}

static inline bool exists_basic_block_at_address(taddr_t Addr,
                                                 const binary_t &b) {
  return bbmap_contains(b.bbmap, Addr);
}

static inline bool exists_basic_block_starting_at_address(taddr_t Addr,
                                                          const binary_t &b) {
  return b.bbbmap.contains(Addr);
}

static inline function_index_t index_of_function_at_address(const binary_t &b,
                                                            taddr_t Addr) {
  function_index_t FIdx = invalid_function_index;
  bool found = b.fnmap.cvisit(Addr, [&](const auto &x) { FIdx = x.second; });
  assert(found);

  return FIdx;
}

static inline const function_t &function_at_address(const binary_t &b,
                                                    taddr_t Addr) {
  return b.Analysis.Functions.at(index_of_function_at_address(b, Addr));
}

static inline function_t &function_at_address(binary_t &b, taddr_t Addr) {
  return b.Analysis.Functions.at(index_of_function_at_address(b, Addr));
}

static inline bool exists_function_at_address(const binary_t &b, taddr_t Addr) {
  return b.fnmap.contains(Addr);
}

// NOTE: this function excludes tail calls.
static inline bool exists_indirect_jump_at_address(taddr_t Addr,
                                                   const binary_t &binary) {
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

static inline taddr_t address_of_basic_block(basic_block_t bb,
                                             const binary_t &b) {
  return address_of_basic_block(bb, b.Analysis.ICFG);
}

static inline taddr_t address_of_basic_block_terminator(basic_block_t bb,
                                                        const ip_icfg_t &ICFG) {
  return ICFG[bb].Term.Addr;
}

static inline taddr_t address_of_basic_block_terminator(basic_block_t bb,
                                                        const binary_t &b) {
  return address_of_basic_block_terminator(bb, b.Analysis.ICFG);
}

static inline taddr_t entry_address_of_function(const function_t &f,
                                                const binary_t &binary) {
  const auto &ICFG = binary.Analysis.ICFG;
  return ICFG[basic_block_of_index(f.Entry, binary)].Addr;
}

static inline taddr_t address_of_block_in_binary(basic_block_index_t BBIdx,
                                                 const binary_t &b) {
  return b.Analysis.ICFG[basic_block_of_index(BBIdx, b)].Addr;
}

static inline taddr_t address_of_block(const block_t &block,
                                       const jv_t &jv) {
  const binary_t &b = jv.Binaries.at(block.first);
  return address_of_block_in_binary(block.second, b);
}

static inline taddr_t address_of_block_terminator(const block_t &Block,
                                                  const jv_t &jv) {
  const binary_t &b = jv.Binaries.at(Block.first);
  return b.Analysis.ICFG[basic_block_of_index(Block.second, b)].Term.Addr;
}

static inline void construct_bbmap(const jv_t &jv,
                                   const binary_t &binary,
                                   bbmap_t &out) {
  auto &ICFG = binary.Analysis.ICFG;

  for_each_basic_block_in_binary(binary, [&](basic_block_t bb) {
    const auto &bbprop = ICFG[bb];

    bbmap_add(out, addr_intvl(bbprop.Addr, bbprop.Size), ICFG.index(bb));
  });
}

static inline void identify_ABIs(jv_t &jv) {
  //
  // If a function is called from a different binary, it is an ABI.
  //
  for_each_basic_block(std::execution::par_unseq,
                       jv, [&](binary_t &b, basic_block_t bb) {
    auto &bbprop = b.Analysis.ICFG[bb];
    if (!bbprop.hasDynTarget())
      return;

    const binary_index_t BIdx = index_of_binary(b, jv);

    if (bbprop.DynTargetsAnyOf(
            [&](const dynamic_target_t &X) { return X.first != BIdx; }))
      bbprop.DynTargets.cvisit_all(std::execution::par_unseq,
                                   [&](const dynamic_target_t &X) {
                                     function_of_target(X, jv).IsABI = true;
                                   });
  });
}

static inline binary_t &get_dynl(jv_t &jv) {
  for (binary_t &binary : jv.Binaries) {
    if (binary.IsDynamicLinker)
      return binary;
  }

  throw std::runtime_error(std::string(__func__) + ": not found!");
}

static inline binary_t &get_vdso(jv_t &jv) {
  for (binary_t &binary : jv.Binaries) {
    if (binary.IsVDSO)
      return binary;
  }

  throw std::runtime_error(std::string(__func__) + ": not found!");
}

#include "jove/state.h"

} /* namespace jove */

#endif /* __cplusplus */

#undef IN_JOVE_H
#endif /* JOVE_H */
