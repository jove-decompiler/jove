#ifndef JOVE_H
#define JOVE_H
#define IN_JOVE_H

#include "jove/tcg.h"
#ifdef __cplusplus
#include "jove/macros.h"
#include "jove/types.h"
#include "jove/racy.h"

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
template <bool MT>
struct jv_base_t;

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

#ifdef NDEBUG
constexpr taddr_t uninit_taddr = invalid_taddr;
constexpr bool is_taddr_init(taddr_t) { return true; }
#else
constexpr taddr_t uninit_taddr = invalid_taddr - 1;
constexpr bool is_taddr_init(taddr_t Addr) { return Addr != uninit_taddr; }
#endif

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
#ifdef NDEBUG
  // the following is equivalent to Addr != 0UL && Addr != ~0UL
  return !!((Addr + taddr_t(1)) & taddr_t(~1ull));
#else
  // same as the top except also covers uninit_taddr (and one **)
  return !!((Addr + taddr_t(2)) & taddr_t(~3ull));
#endif
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
constexpr bool IsTarget64 = sizeof(taddr_t) == 8;

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

template <typename T>
using ip_unique_ptr = boost::interprocess::managed_unique_ptr<T, jv_file_t>::type;

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

#include "jove/mt.h"

template <bool MT, typename Spin, typename... Params>
using possibly_concurrent_flat_map =
    std::conditional_t<MT, boost::concurrent_flat_map<Params..., Spin>,
                       boost::unordered_flat_map<Params...>>;

template <bool MT, typename... Params>
using possibly_concurrent_flat_set =
    std::conditional_t<MT, boost::concurrent_flat_set<Params...>,
                       boost::unordered_flat_set<Params...>>;

template <bool MT, typename... Params>
using possibly_concurrent_node_set =
    std::conditional_t<MT, boost::concurrent_node_set<Params...>,
                       boost::unordered_node_set<Params...>>;

template <typename T, typename Alloc,
          bool MT = true,
          bool Spin = true,
          bool PointUnique = false>
struct deque : public ip_base_rw_accessible<MT, Spin> {
  typedef boost::container::deque_options<
      boost::container::stored_size<uint32_t>>::type DequeOptions;

  using type = boost::interprocess::deque<T, Alloc, DequeOptions>;

  std::conditional_t<PointUnique, ip_unique_ptr<type>, type> _deque;

  const type &container(void) const {
    if constexpr (PointUnique)
      return *_deque;
    else
      return _deque;
  }
  type &container(void) {
    if constexpr (PointUnique)
      return *_deque;
    else
      return _deque;
  }

  deque() = delete;

  deque(jv_file_t &jv_file)
    requires(PointUnique)
      : _deque(boost::interprocess::make_managed_unique_ptr(
            jv_file.construct<type>(boost::interprocess::anonymous_instance)(
                jv_file.get_segment_manager()),
            jv_file)) {}

  deque(jv_file_t &jv_file)
    requires(!PointUnique)
      : _deque(jv_file.get_segment_manager()) {}

  template <bool MT2, bool Spin2>
  deque(deque<T, Alloc, MT2, Spin2, PointUnique> &&other) noexcept
      : _deque(std::move(other._deque)) {}

  template <bool MT2, bool Spin2>
  deque &operator=(deque<T, Alloc, MT2, Spin2, PointUnique> &&other) noexcept {
    if constexpr (MT == MT2) {
      if (this == &other)
        return *this;
    }

    _deque = std::move(other._deque);
    return *this;
  }

  unsigned size(void) const {
    auto s_lck = this->shared_access();
    return container().size();
  }

  bool empty(void) const { return size() == 0; }

  T &at(unsigned idx) {
    auto s_lck = this->shared_access();
    return container().at(idx);
  }

  const T &at(unsigned idx) const {
    auto s_lck = this->shared_access();
    return container().at(idx);
  }

  void clear(void) {
    auto e_lck = this->exclusive_access();

    container().clear();
  }

  /* FIXME */
  typename type::const_iterator cbegin(void) const { return container().cbegin(); }
  typename type::const_iterator cend(void) const { return container().cend(); }

  typename type::const_iterator begin(void) const { return cbegin(); }
  typename type::const_iterator end(void) const { return cend(); }

  typename type::iterator begin(void) { return container().begin(); }
  typename type::iterator end(void) { return container().end(); }
};

template <class OutEdgeListS,
          class VertexListS,
          class DirectedS,
          class VertexProperty,
          class EdgeProperty,
          class GraphProperty,
          class EdgeListS,
          bool MT = true, bool Spin = true, bool PointUnique = true>
struct adjacency_list : public ip_base_rw_accessible<MT, Spin> {
  using type = boost::adjacency_list<OutEdgeListS, VertexListS, DirectedS,
                                     VertexProperty, EdgeProperty,
                                     GraphProperty, EdgeListS>;

  std::conditional_t<PointUnique, ip_unique_ptr<type>, type> _adjacency_list;

  const type &container(void) const {
    if constexpr (PointUnique)
      return *_adjacency_list;
    else
      return _adjacency_list;
  }
  type &container(void) {
    if constexpr (PointUnique)
      return *_adjacency_list;
    else
      return _adjacency_list;
  }

  using vertex_descriptor = type::vertex_descriptor;
  using edge_descriptor = type::edge_descriptor;
  using vertices_size_type = type::vertices_size_type;
  using vertex_iterator = type::vertex_iterator;
  using degree_size_type = type::degree_size_type;
  using adjacency_iterator = type::adjacency_iterator;
  using out_edge_iterator = type::out_edge_iterator;
  using in_edge_iterator = type::in_edge_iterator;
  using inv_adjacency_iterator = type::inv_adjacency_iterator;
  using vertex_property_type = type::vertex_property_type;

  std::atomic<uint32_t> _size = 0;

  adjacency_list(jv_file_t &jv_file)
    requires(PointUnique)
      : _adjacency_list(boost::interprocess::make_managed_unique_ptr(
            jv_file.construct<type>(boost::interprocess::anonymous_instance)(
                typename type::graph_property_type(),
                jv_file.get_segment_manager()),
            jv_file)) {}

  adjacency_list(jv_file_t &jv_file)
    requires(!PointUnique)
      : _adjacency_list(typename type::graph_property_type(),
                        jv_file.get_segment_manager()) {}

  template <bool MT2, bool Spin2>
  adjacency_list(
      adjacency_list<OutEdgeListS, VertexListS, DirectedS, VertexProperty,
                     EdgeProperty, GraphProperty, EdgeListS, MT2, Spin2,
                     PointUnique> &&other) noexcept
      : _adjacency_list(std::move(other._adjacency_list)),
        _size(other._size.load(std::memory_order_relaxed)) {
    other._size.store(0, std::memory_order_relaxed);
  }

  template <bool MT2, bool Spin2>
  adjacency_list &
  operator=(adjacency_list<OutEdgeListS, VertexListS, DirectedS, VertexProperty,
                           EdgeProperty, GraphProperty, EdgeListS, MT2, Spin2,
                           PointUnique> &&other) noexcept {
    if constexpr (MT == MT2) {
      if (this == &other)
        return *this;
    }

    _adjacency_list = std::move(other._adjacency_list);
    _size.store(other._size.load(std::memory_order_relaxed));
    other._size.store(0, std::memory_order_relaxed);
    return *this;
  }

  template <bool MT2, bool Spin2>
  adjacency_list(
      const adjacency_list<OutEdgeListS, VertexListS, DirectedS, VertexProperty,
                           EdgeProperty, GraphProperty, EdgeListS, MT2, Spin2,
                           PointUnique> &) = delete;

  template <bool MT2, bool Spin2>
  adjacency_list &operator=(
      const adjacency_list<OutEdgeListS, VertexListS, DirectedS, VertexProperty,
                           EdgeProperty, GraphProperty, EdgeListS, MT2, Spin2,
                           PointUnique> &) = delete;

#define _S_LCK(ShouldLock, Mutex)                                              \
  typename std::conditional<ShouldLock && MT,                                  \
                            ip_sharable_lock<ip_sharable_mutex>,               \
                            __do_nothing_t>::type                              \
  UNIQUE_VAR_NAME(__s_lck)(Mutex)

#define _E_LCK(ShouldLock, Mutex)                                              \
  typename std::conditional<ShouldLock && MT,                                  \
                            ip_scoped_lock<ip_sharable_mutex>,                 \
                            __do_nothing_t>::type                              \
  UNIQUE_VAR_NAME(__e_lck)(Mutex)

  template <typename... Args>
  vertices_size_type index_of_add_vertex(Args &&...args) {
    const vertices_size_type Idx =
        _size.fetch_add(1u, std::memory_order_relaxed);

    if (unlikely(Idx >= actual_num_vertices())) {
      auto e_lck = this->exclusive_access();

      vertices_size_type actual_size = boost::num_vertices(container());
      if (Idx >= actual_size) {
        vertices_size_type desired = std::bit_ceil(Idx + 1);
        assert(desired > actual_size);
        for (unsigned i = 0; i < desired - actual_size; ++i)
          boost::add_vertex(container(), std::forward<Args>(args)...);
        assert(Idx < boost::num_vertices(container()));
      }
    }

    return Idx;
  }

  template <typename... Args>
  vertex_descriptor add_vertex(Args &&...args) {
    return vertex<false>(index_of_add_vertex(std::forward<Args>(args)...));
  }

  vertices_size_type actual_num_vertices(void) const {
    auto s_lck = this->shared_access();
    return boost::num_vertices(container());
  }

  vertices_size_type num_vertices(void) const {
    return _size.load(std::memory_order_relaxed);
  }

  bool empty(void) const { return num_vertices() == 0; }

  vertex_property_type &at(vertex_descriptor V) {
    auto s_lck = this->shared_access();

    if (unlikely(index(V) >= num_vertices()))
      throw std::out_of_range(__PRETTY_FUNCTION__);

    return container()[V];
  }

  const vertex_property_type &at(vertex_descriptor V) const {
    auto s_lck = this->shared_access();

    if (unlikely(index(V) >= num_vertices()))
      throw std::out_of_range(__PRETTY_FUNCTION__);

    return container()[V];
  }

  vertex_property_type &operator[](vertex_descriptor V) {
    auto s_lck = this->shared_access();
    return container()[V];
  }

  const vertex_property_type &operator[](vertex_descriptor V) const {
    auto s_lck = this->shared_access();
    return container()[V];
  }

  template <bool Check = true>
  vertex_descriptor vertex(vertices_size_type Idx) const {
    if (Check)
      assert(Idx < num_vertices()); /* catch bugs */

    // for VertexList=vecS this is just identity map
    return boost::vertex(Idx, container());
  }

  vertices_size_type index(vertex_descriptor V) const {
    // for VertexList=vecS this is just identity map
    return boost::get(boost::vertex_index, container())[V];
  }

  template <bool L = true, class DFSVisitor>
  void depth_first_visit(vertex_descriptor V, DFSVisitor &vis) const {
    std::map<vertex_descriptor, boost::default_color_type> color;

    auto s_lck = this->shared_access();

    boost::depth_first_visit(
        container(), V, vis,
        boost::associative_property_map<
            std::map<vertex_descriptor, boost::default_color_type>>(color));
  }

  template <bool L = true, class BFSVisitor>
  void breadth_first_search(vertex_descriptor V, BFSVisitor &vis) const {
    auto s_lck = this->shared_access();

    boost::breadth_first_search(container(), V, boost::visitor(vis));
  }

  template <bool L = true>
  degree_size_type out_degree(vertex_descriptor V) const {
    auto s_lck = this->shared_access();
    _S_LCK(L, container()[V].mtx);

    return boost::out_degree(V, container());
  }

  template <bool L = true>
  void clear_out_edges(vertex_descriptor V) {
    auto s_lck = this->shared_access();
    _E_LCK(L, container()[V].mtx);

    boost::clear_out_edges(V, container());
  }

  template <bool L = true>
  std::pair<edge_descriptor, bool> add_edge(vertex_descriptor V1,
                                            vertex_descriptor V2) {
    auto s_lck = this->shared_access();
    _E_LCK(L, container()[V1].mtx);

    return boost::add_edge(V1, V2, container());
  }

  template <bool L = true>
  vertex_descriptor adjacent_front(vertex_descriptor V) const {
    _S_LCK(L, container()[V].mtx);

    return *adjacent_vertices(V).first;
  }

  // precondition: out_degree(V) >= N
  template <unsigned N, bool L = true>
  __attribute__((always_inline))
  std::array<vertex_descriptor, N> adjacent_n(vertex_descriptor V) const {
    std::array<vertex_descriptor, N> res;

    {
      _S_LCK(L, container()[V].mtx);

      adjacency_iterator it, it_end;
      std::tie(it, it_end) = adjacent_vertices(V);

#pragma clang loop unroll(full)
      for (unsigned i = 0; i < N; ++i)
        res[i] = *it++;
    }

    return res;
  }

  template <bool L = true>
  std::pair<vertex_iterator, vertex_iterator> vertices(void) const {
    auto res = boost::vertices(container());
    std::advance(res.second, -(actual_num_vertices() - num_vertices()));
    return res;
  }
  std::pair<adjacency_iterator, adjacency_iterator>
  adjacent_vertices(vertex_descriptor V) const {
    auto s_lck = this->shared_access();
    return boost::adjacent_vertices(V, container());
  }
  std::pair<inv_adjacency_iterator, inv_adjacency_iterator>
  inv_adjacent_vertices(vertex_descriptor V) const {
    auto s_lck = this->shared_access();
    return boost::inv_adjacent_vertices(V, container());
  }
  std::pair<out_edge_iterator, out_edge_iterator>
  out_edges(vertex_descriptor V) const {
    auto s_lck = this->shared_access();
    return boost::out_edges(V, container());
  }
  std::pair<in_edge_iterator, in_edge_iterator>
  in_edges(vertex_descriptor V) const {
    auto s_lck = this->shared_access();
    return boost::in_edges(V, container());
  }

  std::vector<vertex_descriptor>
  get_adjacent_vertices(vertex_descriptor V) const {
    std::vector<vertex_descriptor> res;

#if 0
    _S_LCK(L, container()[V].mtx);
#else
    auto s_lck = this->shared_access();
#endif

    res.reserve(boost::out_degree(V, container()));

    adjacency_iterator it, it_end;
    std::tie(it, it_end) = boost::adjacent_vertices(V, container());
    std::copy(it, it_end, std::back_inserter(res));

    return res;
  }

#undef _S_LCK
#undef _E_LCK
};

typedef boost::interprocess::allocator<char, segment_manager_t>
    ip_char_allocator;
typedef boost::interprocess::basic_string<char, std::char_traits<char>,
                                          ip_char_allocator>
    ip_string;

static inline std::string un_ips(const ip_string &x) {
  std::string res;
  res.reserve(x.size());
  std::copy(x.begin(), x.end(), std::back_inserter(res));
  return res;
}

static inline ip_string &to_ips(ip_string &res, std::string_view x) {
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

typedef boost::concurrent_flat_set<
    binary_index_t, boost::hash<binary_index_t>, std::equal_to<binary_index_t>,
    boost::interprocess::allocator<binary_index_t, segment_manager_t>>
    ip_binary_index_set;

typedef boost::container::flat_set<binary_index_t, std::less<binary_index_t>>
    binary_index_set;

typedef boost::unordered_flat_set<dynamic_target_t> dynamic_target_set;

typedef std::pair<taddr_t, taddr_t> addr_intvl; /* right open interval */

struct addr_intvl_cmp {
  using is_transparent = void;

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

template <bool MT>
struct binary_base_t;

struct allocates_basic_block_t {
  basic_block_index_t BBIdx = invalid_basic_block_index;

  allocates_basic_block_t () noexcept = default;

  // allocates (creates) new basic block in binary, stores index
  template <bool MT>
  inline allocates_basic_block_t(binary_base_t<MT> &b, basic_block_index_t &store,
                                 taddr_t Addr) noexcept;

  operator basic_block_index_t() const { return BBIdx; }
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
struct BBMap_t : public ip_base_rw_accessible<MT, false> {
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

  allocates_function_t() noexcept = default;

  // allocates (creates) new function in binary, stores index
  template <bool MT>
  allocates_function_t(binary_base_t<MT> &b, function_index_t &store) noexcept;

  operator function_index_t() const { return FIdx; }
};

template <bool MT>
using fnmap_t = possibly_concurrent_flat_map<
    MT, std::true_type /* Spin */, taddr_t, allocates_function_t,
    boost::hash<taddr_t>, std::equal_to<taddr_t>,
    boost::interprocess::allocator<
        std::pair<const taddr_t, allocates_function_t>, segment_manager_t>>;

typedef boost::unordered::unordered_flat_set<
    function_index_t, boost::hash<function_index_t>,
    std::equal_to<function_index_t>>
    func_index_set;

typedef boost::interprocess::set<
    function_index_t, std::less<function_index_t>,
    boost::interprocess::node_allocator<function_index_t, segment_manager_t>>
    ip_func_index_set;

template <bool MT>
using ip_func_index_sets = possibly_concurrent_node_set<
    MT, ip_func_index_set, boost::hash<ip_func_index_set>,
    std::equal_to<ip_func_index_set>,
    boost::interprocess::node_allocator<ip_func_index_set, segment_manager_t>>;

size_t jvDefaultInitialSize(void);

#include "jove/atomic.h"

struct basic_block_properties_t : public ip_mt_base_rw_accessible_nospin {
  struct pub_t : public ip_mt_base_rw_accessible_nospin {
    std::atomic<bool> is = false;
  } pub;

  bool Speculative = false;

  taddr_t Addr = uninit_taddr;
  uint32_t Size = ~0UL;

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
    AtomicOffsetPtr<ip_dynamic_target_set> _p; /* TODO atomic ip_unique_ptr.. */
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

    bool Stale = true;

    struct straight_line_t {
      std::atomic<bool> Stale = true;

      basic_block_index_t BBIdx = invalid_basic_block_index;
      taddr_t Addr = uninit_taddr;
      taddr_t TermAddr = uninit_taddr;
      TERMINATOR TermType = TERMINATOR::UNKNOWN;
      boost::container::static_vector<basic_block_index_t, 2> adj;
      boost::container::flat_set<addr_intvl, addr_intvl_cmp> addrng;
    };
  } Analysis;

  class Parents_t : public ip_mt_base_accessible_spin {
    boost::interprocess::offset_ptr<const ip_func_index_set> _p = nullptr;

    friend basic_block_properties_t;
    friend allocates_basic_block_t;

    Parents_t() noexcept = default;

    template <bool MT>
    void set(const ip_func_index_set &x) {
      auto e_lck = this->exclusive_access<MT>();

      _p = &x;
    }

  public:
    template <bool MT>
    const ip_func_index_set &get(void) const {
      auto s_lck = this->exclusive_access<MT>();

      assert(_p);
      return *_p;
    }

    template <bool MT>
    bool empty(void) const {
      return get<MT>().empty();
    }

    template <bool MT>
    bool contains(function_index_t FIdx) const {
      return get<MT>().contains(FIdx);
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
    ip_dynamic_target_set *const p =
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
    ip_dynamic_target_set *const p =
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
    ip_dynamic_target_set *const p =
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

    ip_dynamic_target_set *const p =
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

  void InvalidateAnalysis(void) {
    this->Analysis.Stale = true;
  }

  basic_block_properties_t() noexcept = default;

  basic_block_properties_t(basic_block_properties_t &&other) noexcept {
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

  basic_block_properties_t(const basic_block_properties_t &) = delete;
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
    Analysis = other.Analysis;

    Parents._p = other.Parents._p;
    other.Parents._p = nullptr;

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
adjacency_list<boost::setS_ip,           /* OutEdgeList */
               boost::dequeS_ip,         /* VertexList */
               boost::directedS,         /* Directed */
               basic_block_properties_t, /* VertexProperties */
               boost::no_property,       /* EdgeProperties */
               boost::no_property,       /* GraphProperties */
               boost::listS_ip,          /* EdgeList */
               MT>;

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
  const binary_index_t BIdx =
      is_binary_index_valid(caller.first)
          ? caller.first
          : index_of_binary(caller_b); /* invalid => binary of caller */

  const binary_base_t<MT> &b = jv.Binaries.at(BIdx);
  const basic_block_index_t BBIdx =
      index_of_basic_block_at_address(caller.second, b);

  return {BIdx, BBIdx};
}

typedef boost::interprocess::set<
    caller_t, std::less<caller_t>,
    boost::interprocess::node_allocator<caller_t, segment_manager_t>>
    callers_t;

struct function_t {
  bool Speculative = false;

  binary_index_t BIdx = invalid_binary_index;
  function_index_t Idx = invalid_function_index;
  basic_block_index_t Entry = invalid_basic_block_index;

  class Callers_t : private ip_mt_base_rw_accessible_spin {
    callers_t set;

  public:
    explicit Callers_t(segment_manager_t *sm) noexcept : set(sm) {}

    template <bool MT>
    void insert(binary_index_t BIdx, taddr_t TermAddr) {
      auto e_lck = this->exclusive_access<MT>();

      set.emplace(BIdx, TermAddr);
    }

    template <bool MT>
    shared_lock_guard<MT> get(const callers_t *&out) const {
      out = &set;
      return this->shared_access<MT>();
    }

    template <bool MT>
    bool empty(void) const {
      auto s_lck = this->shared_access<MT>();

      return set.empty();
    }
  } Callers;

  struct Analysis_t {
    tcg_global_set_t args;
    tcg_global_set_t rets;

    bool Stale = true;
  } Analysis;

  bool IsABI = false;
  bool IsSignalHandler = false;
  bool Returns = false;

  void InvalidateAnalysis(void) {
    this->Analysis.Stale = true;
  }

  template <bool MT>
  function_t(binary_base_t<MT> &, function_index_t) noexcept;
  function_t(segment_manager_t *) noexcept; /* XXX used by serialize */
  function_t() = delete;

  function_t(function_t &&) noexcept = default;
  function_t &operator=(function_t &&) noexcept = default;

  function_t(const function_t &) = delete;
  function_t &operator=(const function_t &) = delete;
};

#include "jove/objdump.h"

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

  ip_unique_ptr<ip_func_index_set> EmptyFIdxSet;
  ip_func_index_sets<MT> FIdxSets;

  struct Analysis_t {
    function_index_t EntryFunction = invalid_function_index;

    //
    // references to function_t will never be invalidated.
    //
    deque<function_t,
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

    Analysis_t(Analysis_t &&other) noexcept
        : EntryFunction(std::move(other.EntryFunction)),
          Functions(std::move(other.Functions)),
          ICFG(std::move(other.ICFG)),
          objdump(std::move(other.objdump)) {}

    Analysis_t(typename binary_base_t<!MT>::Analysis_t &&other) noexcept
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

    template <class Archive>
    void serialize(Archive &ar, const unsigned int version);

    /*** may have use in future ***/
    void addSymDynTarget(const std::string &sym, dynamic_target_t X) {}
    void addRelocDynTarget(taddr_t A, dynamic_target_t X) {}
    void addIFuncDynTarget(taddr_t A, dynamic_target_t X) {}

    typedef objdump_output_t<
        boost::interprocess::allocator<unsigned long, segment_manager_t>, MT>
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
      : Idx(Idx), bbbmap(jv_file.get_segment_manager()),
        BBMap(jv_file),
        fnmap(jv_file.get_segment_manager()),
        Name(jv_file.get_segment_manager()),
        EmptyFIdxSet(boost::interprocess::make_managed_unique_ptr(
            jv_file.construct<ip_func_index_set>(
                boost::interprocess::anonymous_instance)(
                jv_file.get_segment_manager()),
            jv_file)),
        FIdxSets(jv_file.get_segment_manager()),
        Data(jv_file.get_segment_manager()), Analysis(jv_file) {}

  template <bool MT2>
  binary_base_t(binary_base_t<MT2> &&other) noexcept
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

        EmptyFIdxSet(std::move(other.EmptyFIdxSet)),
        FIdxSets(std::move(other.FIdxSets)),

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

    EmptyFIdxSet = std::move(other.EmptyFIdxSet);
    FIdxSets = std::move(other.FIdxSets);

    Analysis.template operator=<MT2>(std::move(other.Analysis));

    return *this;
  }

  binary_base_t() = delete;
  binary_base_t(const binary_base_t &) = delete;
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
  bbprop.Parents.template set<false>(*b.EmptyFIdxSet);

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

  adds_binary_t() = default;

  explicit adds_binary_t(binary_index_t BIdx) noexcept : BIdx(BIdx) {
    assert(is_binary_index_valid(BIdx));
  }

  // adds new binary, stores index
  template <bool MT>
  adds_binary_t(binary_index_t &out,
                jv_file_t &,
                jv_base_t<MT> &,
                explorer_t &,
                get_data_t get_data,
                const hash_t &,
                const char *name,
                const AddOptions_t &) noexcept(false);

  // adds new binary, stores index
  template <bool MT>
  adds_binary_t(binary_index_t &out,
                jv_base_t<MT> &,
                binary_base_t<MT> &&) noexcept;

  operator binary_index_t() const { return BIdx; }
};

struct ip_string_hash_t  {
  using is_transparent = void;

  template <typename A>
  std::size_t operator()(const boost::interprocess::basic_string<char, std::char_traits<char>, A> &str) const noexcept {
    return std::hash<std::string_view>{}(std::string_view(str.data(), str.size()));
  }

  std::size_t operator()(std::string_view sv) const noexcept {
    return std::hash<std::string_view>{}(sv);
  }

  std::size_t operator()(const char *s) const noexcept {
    return std::hash<std::string_view>{}(s);
  }
};

struct ip_string_equal_t {
  using is_transparent = void;

  template <typename A>
  bool operator()(
      const boost::interprocess::basic_string<char, std::char_traits<char>, A> &lhs,
      const boost::interprocess::basic_string<char, std::char_traits<char>, A> &rhs) const noexcept {
    return lhs == rhs;
  }

  template <typename A>
  bool operator()(const boost::interprocess::basic_string<char, std::char_traits<char>, A> &lhs,
      std::string_view rhs) const noexcept {
    return lhs == rhs;
  }

  template <typename A>
  bool operator()(std::string_view lhs,
                  const boost::interprocess::basic_string<char, std::char_traits<char>, A> &rhs) const noexcept {
    return lhs == rhs;
  }

  bool operator()(std::string_view lhs, std::string_view rhs) const noexcept {
    return lhs == rhs;
  }

  template <typename A>
  bool operator()(const boost::interprocess::basic_string<char, std::char_traits<char>, A> &lhs,
      const char *rhs) const noexcept {
    return lhs == rhs;
  }

  template <typename A>
  bool operator()(
      const char *lhs,
      const boost::interprocess::basic_string<char, std::char_traits<char>, A> &rhs) const noexcept {
    return lhs == rhs;
  }

  bool operator()(std::string_view lhs, const char* rhs) const noexcept {
    return lhs == rhs;
  }

  bool operator()(const char* lhs, std::string_view rhs) const noexcept {
    return lhs == rhs;
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
    MT, std::false_type /* !Spin */, hash_t, adds_binary_t, boost::hash<hash_t>,
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
};

template <bool MT = true>
struct jv_base_t {
  //
  // references to binary_t will never be invalidated.
  //
  deque<binary_base_t<MT>,
        boost::interprocess::private_node_allocator<binary_base_t<MT>,
                                                    segment_manager_t>,
        MT>
      Binaries;

  ip_hash_to_binary_map_type<MT> hash_to_binary;
  ip_cached_hashes_type<MT> cached_hashes; /* NOT serialized */

  ip_name_to_binaries_map_type<MT> name_to_binaries; /* this is questionable */
                                                     /* used by LookupByName */

  void InvalidateFunctionAnalyses(void);

  void clear(bool everything = false);

  segment_manager_t *get_segment_manager(void) const {
    return Binaries.container().get_allocator().get_segment_manager();
  }

  explicit jv_base_t(jv_file_t &jv_file) noexcept
      : Binaries(jv_file),
        hash_to_binary(jv_file.get_segment_manager()),
        cached_hashes(jv_file.get_segment_manager()),
        name_to_binaries(jv_file.get_segment_manager()) {}

  template <bool MT2>
  jv_base_t(jv_base_t<MT2> &&other, jv_file_t &jv_file) noexcept
      : Binaries(jv_file),
        hash_to_binary(std::move(other.hash_to_binary)),
        cached_hashes(std::move(other.cached_hashes)),
        name_to_binaries(std::move(other.name_to_binaries)) {
    for (binary_base_t<MT2> &b : other.Binaries)
      Binaries.container().push_back(std::move(b));
  }

  jv_base_t() = delete;
  jv_base_t(const jv_base_t &) = delete;
  jv_base_t &operator=(const jv_base_t &) = delete;
  jv_base_t &operator=(jv_base_t &&) = delete;

  std::optional<binary_index_t> LookupByHash(const hash_t &h);
  bool LookupByName(const char *name, binary_index_set &out);

  template <bool ValidatePath = true>
  std::pair<binary_index_t, bool>
  AddFromPath(explorer_t &,
              jv_file_t &,
              const char *path,
              on_newbin_proc_t<MT> on_newbin = [](binary_base_t<MT> &) {},
              const AddOptions_t &Options = AddOptions_t());

  std::pair<binary_index_t, bool> Add(
      binary_base_t<MT> &&,
      on_newbin_proc_t<MT> on_newbin = [](binary_base_t<MT> &) {});

  std::pair<binary_index_t, bool>
  AddFromData(explorer_t &,
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

  std::pair<binary_index_t, bool> AddFromDataWithHash(explorer_t &E,
                                                      jv_file_t &,
                                                      get_data_t,
                                                      const hash_t &h,
                                                      const char *name,
                                                      on_newbin_proc_t<MT> on_newbin,
                                                      const AddOptions_t &Options);
public:
  template <bool MT2>
  void DoAdd(binary_base_t<MT2> &,
             explorer_t &,
             llvm::object::Binary &,
             const AddOptions_t &);

  friend adds_binary_t;

  void fixup_binary(binary_index_t); /* XXX */
};

typedef jv_base_t<true> jv_t;

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

static constexpr addr_intvl
    empty_addr_intvl(std::numeric_limits<taddr_t>::max(), 1);

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

template <typename OrderedIntvlSet, typename T>
constexpr auto intvl_set_find(OrderedIntvlSet &set, T x) {
  if (unlikely(set.empty()))
    return set.end();

  auto it = set.upper_bound(x);

  if (it != set.end() && addr_intvl_intersects(*it, x))
    return it;

  if (it == set.begin())
    return set.end();

  --it;

  if (addr_intvl_intersects(*it, x))
    return it;

  return set.end();
}

template <typename OrderedIntvlSet, typename T>
constexpr bool intvl_set_contains(OrderedIntvlSet &set, T x) {
  return intvl_set_find(set, x) != set.end();
}

template <typename OrderedIntvlSet, typename T>
constexpr void intvl_set_add(OrderedIntvlSet &set, T intvl) {
  auto h = intvl;
  for (;;) {
    auto it = intvl_set_find(set, intvl);
    if (it == set.end()) {
      break;
    } else {
      h = addr_intvl_hull(h, *it);
      set.erase(it);
    }
  }

  bool success = set.insert(h).second;
  (void)success;
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
    found = b.bbbmap.cvisit(Addr, [&](const auto &x) { res = x.second; });
  } else {
    auto it = b.bbbmap.find(Addr);
    found = it != b.bbbmap.end();
    if (found)
      res = (*it).second;
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
  bool found;
  if constexpr (MT) {
    b.fnmap.cvisit(Addr, [&](const auto &x) { FIdx = x.second; });
  } else {
    auto it = b.fnmap.find(Addr);
    if (it == b.fnmap.end()) {
      found = false;
    } else {
      found = true;
      FIdx = (*it).second;
    }
  }
  assert(found);

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
  for (binary_base_t<MT> &binary : jv.Binaries) {
    if (binary.IsDynamicLinker)
      return binary;
  }

  throw std::runtime_error(std::string(__func__) + ": not found!");
}

template <bool MT>
static inline binary_base_t<MT> &get_vdso(jv_base_t<MT> &jv) {
  for (binary_base_t<MT> &binary : jv.Binaries) {
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
