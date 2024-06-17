#pragma once
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

#include <atomic>
#include <algorithm>
#include <cstdint>
#include <functional>
#include <execution>
#include <iomanip>
#include <limits>
#include <map>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <tuple>
#include <vector>
#include <shared_mutex>
#include <deque>

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
  CONDITIONAL_JUMP,
  INDIRECT_CALL,
  INDIRECT_JUMP,
  CALL,
  RETURN,
  UNREACHABLE,
  NONE
};

typedef uint32_t binary_index_t;
typedef uint32_t function_index_t;
typedef uint32_t basic_block_index_t;

typedef std::pair<binary_index_t, function_index_t> dynamic_target_t;

constexpr binary_index_t
    invalid_binary_index = std::numeric_limits<binary_index_t>::max();
constexpr function_index_t
    invalid_function_index = std::numeric_limits<function_index_t>::max();
constexpr basic_block_index_t
    invalid_basic_block_index = std::numeric_limits<basic_block_index_t>::max();
constexpr dynamic_target_t
    invalid_dynamic_target(invalid_binary_index,
                           invalid_function_index);

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

constexpr unsigned IsMIPSTarget =
#if defined(TARGET_MIPS32) || defined(TARGET_MIPS64)
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

static const char *TargetStaticLinkerEmulation =
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

//typedef boost::interprocess::managed_shared_memory::segment_manager
//    segment_manager_t;

typedef boost::interprocess::managed_mapped_file jv_file_t;
typedef jv_file_t::segment_manager segment_manager_t;

typedef boost::interprocess::allocator<void, segment_manager_t>
    ip_void_allocator_t;

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

typedef boost::interprocess::set<
    dynamic_target_t, std::less<dynamic_target_t>,
    boost::interprocess::allocator<dynamic_target_t, segment_manager_t>>
    ip_dynamic_target_set;

typedef boost::interprocess::set<
    binary_index_t, std::less<binary_index_t>,
    boost::interprocess::allocator<binary_index_t, segment_manager_t>>
    ip_binary_index_set;

typedef std::set<dynamic_target_t> dynamic_target_set;

typedef std::pair<taddr_t, unsigned> addr_intvl; /* right open interval */

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

constexpr addr_intvl make_addr_intvl(taddr_t lower, taddr_t upper) {
  assert(upper > lower);
  return addr_intvl(lower, upper - lower);
}

typedef boost::concurrent_flat_map<
    taddr_t, basic_block_index_t, boost::hash<taddr_t>, std::equal_to<taddr_t>,
    boost::interprocess::allocator<std::pair<const taddr_t, basic_block_index_t>,
                                   segment_manager_t>>
    bbbmap_t;

typedef boost::interprocess::flat_map<
    addr_intvl, basic_block_index_t, addr_intvl_cmp,
    boost::interprocess::allocator<std::pair<addr_intvl, basic_block_index_t>,
                                   segment_manager_t>>
    bbmap_t;

typedef boost::concurrent_flat_map<
    taddr_t, function_index_t, boost::hash<taddr_t>, std::equal_to<taddr_t>,
    boost::interprocess::allocator<std::pair<const taddr_t, function_index_t>,
                                   segment_manager_t>>
    fnmap_t;

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

struct basic_block_properties_t {
  uint64_t Addr;
  uint32_t Size;

  struct {
    uint64_t Addr;
    TERMINATOR Type;

    struct {
      function_index_t Target;

      bool Returns;
      uint8_t ReturnsOff;
    } _call;

    struct {
      bool IsLj;
    } _indirect_jump;

    struct {
      bool Returns;
      uint8_t ReturnsOff;
    } _indirect_call;

    struct {
      bool Returns;
    } _return;
  } Term;

  boost::interprocess::offset_ptr<ip_dynamic_target_set> pDynTargets;
  bool DynTargetsComplete; // XXX

  bool Sj;

  struct {
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

    bool Stale;
  } Analysis;

  boost::interprocess::offset_ptr<const ip_func_index_set> Parents;

  bool HasParent(function_index_t FIdx) const {
    if (!Parents)
      return false;

    return Parents->contains(FIdx);
  }

  void AddParent(function_index_t, jv_t &);

  bool IsSingleInstruction(void) const { return Addr == Term.Addr; }

  void InvalidateAnalysis(void) {
    this->Analysis.Stale = true;
  }

  bool hasDynTarget(void) const {
    if (!pDynTargets)
      return false;

    return !pDynTargets->empty();
  }

  bool insertDynTarget(dynamic_target_t, jv_t &);

  unsigned getNumDynTargets(void) const {
    return hasDynTarget() ? pDynTargets->size() : 0;
  }

  ip_dynamic_target_set::const_iterator dyn_targets_begin(void) const {
    assert(hasDynTarget());
    return pDynTargets->cbegin();
  }

  ip_dynamic_target_set::const_iterator dyn_targets_end(void) const {
    assert(hasDynTarget());
    return pDynTargets->cend();
  }

  boost::iterator_range<ip_dynamic_target_set::const_iterator> dyn_targets(void) const {
    return boost::make_iterator_range(dyn_targets_begin(), dyn_targets_end());
  }
};

typedef boost::adjacency_list<boost::setS_ip,           /* OutEdgeList */
                              boost::dequeS_ip,         /* VertexList */
                              boost::bidirectionalS,    /* Directed */
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

static inline bool IsDefinitelyTailCall(const icfg_t &ICFG, basic_block_t bb) {
  assert(ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP);

#ifdef WARN_ON
  WARN_ON(boost::out_degree(bb, ICFG) > 0);
#endif

  return ICFG[bb].hasDynTarget();
}

static inline bool IsAmbiguousIndirectJump(const icfg_t &ICFG, basic_block_t bb) {
  assert(ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP);

  return ICFG[bb].hasDynTarget() && boost::out_degree(bb, ICFG) > 0;
}

static inline bool IsExitBlock(const icfg_t &ICFG, basic_block_t bb) {
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
typedef boost::concurrent_flat_set<
    caller_t, boost::hash<caller_t>, std::equal_to<caller_t>,
    boost::interprocess::allocator<caller_t, segment_manager_t>>
    ip_callers;

struct binary_t;

struct function_t {
  boost::interprocess::offset_ptr<binary_t> b;

  function_index_t Idx = invalid_function_index;

  basic_block_index_t Entry = invalid_basic_block_index;

  ip_callers Callers;

  struct Analysis_t {
    tcg_global_set_t args;
    tcg_global_set_t rets;

    bool Stale;
  } Analysis;

  bool IsABI, IsSignalHandler, Returns;

  void InvalidateAnalysis(void) {
    this->Analysis.Stale = true;
  }

  function_t(binary_t &, function_index_t);
  function_t(const ip_void_allocator_t &); /* XXX */
  function_t() = delete;
};

typedef boost::interprocess::interprocess_mutex ip_mutex;
typedef boost::interprocess::interprocess_sharable_mutex ip_sharable_mutex;
typedef boost::interprocess::interprocess_upgradable_mutex ip_upgradable_mutex;

template <typename Mutex>
using ip_scoped_lock = boost::interprocess::scoped_lock<Mutex>;
template <typename Mutex>
using ip_sharable_lock = boost::interprocess::sharable_lock<Mutex>;
template <typename Mutex>
using ip_upgradable_lock = boost::interprocess::upgradable_lock<Mutex>;

typedef boost::interprocess::interprocess_condition ip_condition;

typedef boost::interprocess::allocator<function_t, segment_manager_t>
    ip_function_allocator;
typedef boost::interprocess::deque<function_t, ip_function_allocator>
    ip_function_deque;

#define DEFINE_INTERPROCESS_MAP(name, key, value)                              \
  boost::interprocess::map<                                                    \
      key, value, std::less<key>,                                              \
      boost::interprocess::allocator<std::pair<const key, value>,              \
                                     segment_manager_t>>                       \
      name

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

  ip_upgradable_mutex bbmap_mtx;
  ip_mutex na_bbmap_mtx;

  struct Analysis_t {
    function_index_t EntryFunction;

    struct _Functions {
      ip_function_deque _deque;
      mutable ip_sharable_mutex _mtx;

      //
      // references to function_t will never be invalidated.
      //
      function_t &at(unsigned idx) {
        ip_sharable_lock<ip_sharable_mutex> s_lck(_mtx);
        return _deque.at(idx);
      }

      const function_t &at(unsigned idx) const {
        ip_sharable_lock<ip_sharable_mutex> s_lck(_mtx);
        return _deque.at(idx);
      }

      unsigned size(void) const {
        ip_sharable_lock<ip_sharable_mutex> s_lck(_mtx);
        return _deque.size();
      }

      bool empty(void) const { return size() == 0; }

      //
      // with iterators we don't even bother taking the shared lock; they would be
      // invalidated anyways if a modification to _deque took place in between the
      // locking.
      //
      ip_function_deque::const_iterator cbegin(void) const { return _deque.cbegin(); }
      ip_function_deque::const_iterator cend(void) const { return _deque.cend(); }

      ip_function_deque::const_iterator begin(void) const { return cbegin(); }
      ip_function_deque::const_iterator end(void) const { return cend(); }

      ip_function_deque::iterator begin(void) { return _deque.begin(); }
      ip_function_deque::iterator end(void) { return _deque.end(); }

      _Functions(const ip_void_allocator_t &A) : _deque(A) {}
      _Functions(_Functions &&other) : _deque(std::move(other._deque)) {}

      _Functions &operator=(const _Functions &other) {
        if (this == &other) {
          return *this;
        }

        _deque = other._deque;
        return *this;
      }
    } Functions;

    interprocedural_control_flow_graph_t ICFG;

    DEFINE_INTERPROCESS_MAP(IFuncDynTargets, uint64_t, ip_dynamic_target_set);
    DEFINE_INTERPROCESS_MAP(RelocDynTargets, uint64_t, ip_dynamic_target_set);
    DEFINE_INTERPROCESS_MAP(SymDynTargets, ip_string, ip_dynamic_target_set);

    Analysis_t(const ip_void_allocator_t &A)
        : Functions(A), ICFG(icfg_t::graph_property_type(), A),
          IFuncDynTargets(A), RelocDynTargets(A), SymDynTargets(A) {}

    Analysis_t() = delete;

    void addSymDynTarget(const std::string &sym, dynamic_target_t X);
    void addRelocDynTarget(uint64_t A, dynamic_target_t X);
    void addIFuncDynTarget(uint64_t A, dynamic_target_t X);
  } Analysis;

  void InvalidateBasicBlockAnalyses(void);

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

#undef DEFINE_INTERPROCESS_MAP

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
  struct _Binaries {
    ip_binary_deque _deque;
    mutable ip_sharable_mutex _mtx;

    _Binaries(const ip_void_allocator_t &A) : _deque(A) {}

    //
    // references to binary_t will never be invalidated.
    //
    binary_t &at(unsigned idx) {
      ip_sharable_lock<ip_sharable_mutex> s_lck(_mtx);
      return _deque.at(idx);
    }

    const binary_t &at(unsigned idx) const {
      ip_sharable_lock<ip_sharable_mutex> s_lck(_mtx);
      return _deque.at(idx);
    }

    unsigned size(void) const {
      ip_sharable_lock<ip_sharable_mutex> s_lck(_mtx);
      return _deque.size();
    }

    bool empty(void) const { return size() == 0; }

    //
    // with iterators we don't even bother taking the shared lock; they would be
    // invalidated anyways if a modification to _deque took place in between the
    // locking.
    //
    ip_binary_deque::const_iterator cbegin(void) const { return _deque.cbegin(); }
    ip_binary_deque::const_iterator cend(void) const { return _deque.cend(); }

    ip_binary_deque::const_iterator begin(void) const { return cbegin(); }
    ip_binary_deque::const_iterator end(void) const { return cend(); }

    ip_binary_deque::iterator begin(void) { return _deque.begin(); }
    ip_binary_deque::iterator end(void) { return _deque.end(); }
  } Binaries;

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
  uint64_t Addr;

  struct {
    struct {
      uint64_t Target;
    } _unconditional_jump;

    struct {
      uint64_t Target;
      uint64_t NextPC;
    } _conditional_jump;

    struct {
      uint64_t Target;
      uint64_t NextPC;
    } _call;

    struct {
      uint64_t NextPC;
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
      uint64_t NextPC;
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
                                             const icfg_t &ICFG) {
  assert(is_basic_block_index_valid(BBIdx));

  return boost::vertex(BBIdx, ICFG);
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
  for_each_if(std::execution::seq, first, last, pred, proc);
}

static inline std::string addr_intvl2str(addr_intvl intvl) {
  return "[" +
         taddr2str(intvl.first, false) + ", " +
         taddr2str(intvl.first + intvl.second, false) + ")";
}

constexpr addr_intvl right_open_addr_intvl(taddr_t Addr, taddr_t End) {
  assert(End > Addr);
  return addr_intvl(Addr, End - Addr);
}

constexpr taddr_t addr_intvl_lower(addr_intvl intvl) {
  return intvl.first;
}

constexpr taddr_t addr_intvl_upper(addr_intvl intvl) {
  return intvl.first + intvl.second;
}

constexpr bool addr_intvl_contains(addr_intvl &intvl, taddr_t Addr) {
  return Addr >= intvl.first && Addr < intvl.first + intvl.second;
}

constexpr bool addr_intvl_intersects(addr_intvl x, addr_intvl y) {
  taddr_t a = addr_intvl_lower(x), b = addr_intvl_upper(x);
  taddr_t c = addr_intvl_lower(y), d = addr_intvl_upper(y);

  if (b <= c || d <= a)
    return false;

  return true;
}

constexpr bool addr_intvl_disjoint(addr_intvl x, addr_intvl y) {
  return !addr_intvl_intersects(x, y);
}

template <typename OrderedIntvlMap>
constexpr auto intvl_map_find(OrderedIntvlMap &map, addr_intvl intvl) {
  if (unlikely(map.empty()))
    return map.end();

  auto it = map.upper_bound(intvl.first);

  if (it != map.end() && addr_intvl_intersects((*it).first, intvl))
    return it;

  if (it == map.begin())
    return map.end();

  --it;

  if (addr_intvl_intersects((*it).first, intvl))
    return it;

  return map.end();
}

template <typename OrderedIntvlMap>
constexpr auto intvl_map_find(OrderedIntvlMap &map, taddr_t Addr) {
  return intvl_map_find(map, addr_intvl(Addr, 1u));
}

template <typename OrderedIntvlMap>
constexpr bool intvl_map_contains(OrderedIntvlMap &map, addr_intvl intvl) {
  return intvl_map_find(map, intvl) != map.end();
}

template <typename OrderedIntvlMap>
constexpr bool intvl_map_contains(OrderedIntvlMap &map, taddr_t Addr) {
  return intvl_map_contains(map, addr_intvl(Addr, 1u));
}

template <typename OrderedIntvlMap, typename Value>
constexpr auto intvl_map_add(OrderedIntvlMap &map,
                             addr_intvl intvl,
                             Value &&val) {
  auto x = map.insert(typename OrderedIntvlMap::value_type(intvl, std::move(val)));

  assert(x.second);
  return x.first;
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
  for_each_binary(std::execution::seq, std::forward<T>(jv), proc);
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
  return for_each_binary_if(std::execution::seq, std::forward<T>(jv), pred, proc);
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
  for_each_function(std::execution::seq, std::forward<T>(jv), proc);
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
  for_each_function_in_binary(std::execution::seq, b, proc);
}

template <class Proc>
constexpr
void for_each_function_in_binary(const binary_t &b,
                                 Proc proc) {
  for_each_function_in_binary(std::execution::seq, b, proc);
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
  for_each_function_if(std::execution::seq, std::forward<T>(jv), pred, proc);
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
    std::tie(it, it_end) = boost::vertices(b.Analysis.ICFG);

    std::for_each(std::forward<_ExecutionPolicy>(__exec),
                  it, it_end,
                  [&b, proc](basic_block_t bb) { proc(b, bb); });
  });
}

template <class T, class Proc>
constexpr
void for_each_basic_block(T &&jv, Proc proc) {
  for_each_basic_block(std::execution::seq, std::forward<T>(jv), proc);
}

template <class _ExecutionPolicy, class Proc>
static inline
void for_each_basic_block_in_binary(_ExecutionPolicy &&__exec,
                                    binary_t &b,
                                    Proc proc) {
  icfg_t::vertex_iterator it, it_end;
  std::tie(it, it_end) = boost::vertices(b.Analysis.ICFG);

  std::for_each(std::forward<_ExecutionPolicy>(__exec),
               it, it_end, [proc](basic_block_t bb) { proc(bb); });
}

template <class _ExecutionPolicy, class Proc>
static inline
void for_each_basic_block_in_binary(_ExecutionPolicy &&__exec,
                                    const binary_t &b,
                                    Proc proc) {
  icfg_t::vertex_iterator it, it_end;
  std::tie(it, it_end) = boost::vertices(b.Analysis.ICFG);

  std::for_each(std::forward<_ExecutionPolicy>(__exec),
               it, it_end, [proc](basic_block_t bb) { proc(bb); });
}

template <class Proc>
constexpr
void for_each_basic_block_in_binary(binary_t &b, Proc proc) {
  for_each_basic_block_in_binary(std::execution::seq, b, proc);
}

template <class Proc>
constexpr
void for_each_basic_block_in_binary(const binary_t &b, Proc proc) {
  for_each_basic_block_in_binary(std::execution::seq, b, proc);
}

static inline basic_block_index_t index_of_basic_block(const icfg_t &ICFG,
                                                       basic_block_t bb) {
  boost::property_map<icfg_t, boost::vertex_index_t>::type bb2idx =
      boost::get(boost::vertex_index, ICFG);
  return bb2idx[bb];
}

constexpr binary_index_t binary_index_of_function(const function_t &f,
                                                  const jv_t &jv) {
  assert(f.b);
  binary_index_t res = f.b->Idx;
  assert(is_binary_index_valid(res));
  return res;
}

constexpr binary_index_t index_of_binary(const binary_t &b, const jv_t &jv) {
  binary_index_t res = b.Idx;
  assert(is_binary_index_valid(res));
  return res;
}

constexpr function_index_t index_of_function_in_binary(const function_t &f,
                                                       const binary_t &b) {
  function_index_t res = f.Idx;
  assert(is_function_index_valid(res));
  return res;
}

constexpr binary_t &binary_of_function(const function_t &f, jv_t &jv) {
  return jv.Binaries.at(binary_index_of_function(f, jv));
}

constexpr const binary_t &binary_of_function(const function_t &f,
                                             const jv_t &jv) {
  return jv.Binaries.at(binary_index_of_function(f, jv));
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

  std::map<basic_block_t, boost::default_color_type> color;
  bb_visitor vis(out);
  depth_first_visit(
      ICFG, entry, vis,
      boost::associative_property_map<
          std::map<basic_block_t, boost::default_color_type>>(color));
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
                              boost::out_degree(bb, ICFG) == 0)
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
index_of_basic_block_at_address(uint64_t Addr, const binary_t &b) {
  auto &bbmap = b.bbmap;

  auto it = bbmap_find(bbmap, Addr);
  if (it == bbmap.end())
    throw std::runtime_error(std::string(__func__) + ": no block for address " +
                             taddr2str(Addr) + " in " + b.Name.c_str());

  return (*it).second;
}

static inline basic_block_index_t
index_of_basic_block_starting_at_address(uint64_t Addr, const binary_t &b) {
  basic_block_index_t res = invalid_basic_block_index;
  bool found = b.bbbmap.cvisit(Addr, [&](const auto &x) { res = x.second; });

  assert(found);
  return res;
}

static inline basic_block_t basic_block_at_address(uint64_t Addr,
                                                   const binary_t &b) {
  return basic_block_of_index(index_of_basic_block_at_address(Addr, b), b);
}

static inline bool exists_basic_block_at_address(uint64_t Addr,
                                                 const binary_t &b) {
  return bbmap_contains(b.bbmap, Addr);
}

static inline bool exists_basic_block_starting_at_address(uint64_t Addr,
                                                          const binary_t &b) {
  return b.bbbmap.contains(Addr);
}

static inline function_index_t index_of_function_at_address(const binary_t &b,
                                                            uint64_t Addr) {
  function_index_t FIdx = invalid_function_index;
  bool found = b.fnmap.cvisit(Addr, [&](const auto &x) { FIdx = x.second; });
  assert(found);

  return FIdx;
}

static inline const function_t &function_at_address(const binary_t &b,
                                                    uint64_t Addr) {
  return b.Analysis.Functions.at(index_of_function_at_address(b, Addr));
}

static inline function_t &function_at_address(binary_t &b, uint64_t Addr) {
  return b.Analysis.Functions.at(index_of_function_at_address(b, Addr));
}

static inline bool exists_function_at_address(const binary_t &b, uint64_t Addr) {
  return b.fnmap.contains(Addr);
}

// NOTE: this function excludes tail calls.
static inline bool exists_indirect_jump_at_address(uint64_t Addr,
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

static inline uint64_t entry_address_of_function(const function_t &f,
                                                 const binary_t &binary) {
  const auto &ICFG = binary.Analysis.ICFG;
  return ICFG[basic_block_of_index(f.Entry, binary)].Addr;
}

static inline void construct_bbbmap(const jv_t &jv,
                                    const binary_t &binary,
                                    bbbmap_t &out) {
  auto &ICFG = binary.Analysis.ICFG;

  for_each_basic_block_in_binary(binary, [&](basic_block_t bb) {
    const auto &bbprop = ICFG[bb];

    bool success = out.emplace(bbprop.Addr, index_of_basic_block(ICFG, bb));
    assert(success);
  });
}

static inline void construct_bbmap(const jv_t &jv,
                                   const binary_t &binary,
                                   bbmap_t &out) {
  auto &ICFG = binary.Analysis.ICFG;

  for_each_basic_block_in_binary(binary, [&](basic_block_t bb) {
    const auto &bbprop = ICFG[bb];

    bbmap_add(out, addr_intvl(bbprop.Addr, bbprop.Size),
              index_of_basic_block(ICFG, bb));
  });
}

static inline void construct_fnmap(const jv_t &jv,
                                   const binary_t &binary,
                                   fnmap_t &out) {
  for_each_function_in_binary(binary, [&](const function_t &f) {
    if (unlikely(!is_basic_block_index_valid(f.Entry)))
      return;

    auto &ICFG = binary.Analysis.ICFG;

    uint64_t Addr = ICFG[basic_block_of_index(f.Entry, ICFG)].Addr;
    function_index_t FIdx = index_of_function_in_binary(f, binary);

    bool success = out.emplace(Addr, FIdx);
    assert(success);
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

    auto dyn_targ_beg = bbprop.dyn_targets_begin();
    auto dyn_targ_end = bbprop.dyn_targets_end();

    if (std::any_of(
            dyn_targ_beg,
            dyn_targ_end,
            [&](dynamic_target_t X) -> bool { return X.first != BIdx; }))
      std::for_each(std::execution::par_unseq,
                    dyn_targ_beg,
                    dyn_targ_end,
                    [&](dynamic_target_t X) {
                      function_of_target(X, jv).IsABI = true;
                    });
  });

  // XXX unnecessary?
  for_each_binary(jv, [&](auto &b) {
    auto &IFuncDynTargets = b.Analysis.IFuncDynTargets;

    std::for_each(
        std::execution::par_unseq,
        IFuncDynTargets.begin(),
        IFuncDynTargets.end(),
        [&](const auto &pair) {
          std::for_each(pair.second.begin(),
                        pair.second.end(),
              [&](dynamic_target_t X) {
                function_of_target(X, jv).IsABI = true;
              });
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

template <typename BinaryStateTy>
struct jv_bin_state_t {
  const jv_t &jv;

  mutable std::shared_mutex _mtx;

  std::deque<BinaryStateTy> stuff;

  jv_bin_state_t(const jv_t &jv) : jv(jv) {
    update();
  }

  BinaryStateTy &for_binary(const binary_t &binary) {
    std::shared_lock<std::shared_mutex> s_lck(_mtx);

    return stuff.at(index_of_binary(binary, jv));
  }

  void update(void) {
    std::unique_lock<std::shared_mutex> e_lck(_mtx);

    stuff.resize(jv.Binaries.size());
  }
};

template <typename FunctionStateTy>
struct jv_fn_state_t {
  const jv_t &jv;

  std::vector<std::vector<FunctionStateTy>> stuff;

  jv_fn_state_t(const jv_t &jv) : jv(jv) {
    update();
  }

  FunctionStateTy &for_function(const function_t &function) {
    binary_index_t BIdx = binary_index_of_function(function, jv);
    std::vector<FunctionStateTy> &function_state_vec = stuff.at(BIdx);

    const binary_t &binary = jv.Binaries.at(BIdx);
    function_index_t FIdx = index_of_function_in_binary(function, binary);

    return function_state_vec.at(FIdx);
  }

  void update(void) {
    stuff.resize(jv.Binaries.size());

    for_each_binary(jv, [&](const binary_t &binary) {
      stuff.at(index_of_binary(binary, jv))
          .resize(binary.Analysis.Functions.size());
    });
  }
};

template <typename BinaryStateTy, typename FunctionStateTy>
struct jv_bin_fn_state_t {
  const jv_t &jv;

  std::vector<std::pair<BinaryStateTy, std::vector<FunctionStateTy>>> stuff;

  jv_bin_fn_state_t(const jv_t &jv) : jv(jv) {
    update();
  }

  BinaryStateTy &for_binary(const binary_t &binary) {
    return stuff.at(index_of_binary(binary, jv)).first;
  }

  FunctionStateTy &for_function(function_t &f) {
    binary_index_t BIdx = binary_index_of_function(f, jv);
    std::vector<FunctionStateTy> &function_state_vec = stuff.at(BIdx).second;

    const binary_t &b = jv.Binaries.at(BIdx);
    function_index_t FIdx = index_of_function_in_binary(f, b);

    return function_state_vec.at(FIdx);
  }

  FunctionStateTy &for_function(binary_index_t BIdx, function_index_t FIdx) {
    if (unlikely(BIdx >= stuff.size()))
      stuff.resize(BIdx + 1);

    std::vector<FunctionStateTy> &function_state_vec = stuff.at(BIdx).second;

    if (unlikely(FIdx >= function_state_vec.size()))
      function_state_vec.resize(FIdx + 1);

    return function_state_vec.at(FIdx);
  }

  void update(void) {
    stuff.resize(jv.Binaries.size());

    for_each_binary(jv, [&](const binary_t &binary) {
      stuff.at(index_of_binary(binary, jv))
          .second.resize(binary.Analysis.Functions.size());
    });
  }
};

template <typename BinaryStateTy, typename FunctionStateTy, typename BasicBlockStateTy>
struct jv_bin_fn_bb_state_t {
  const jv_t &jv;

  std::vector<std::tuple<BinaryStateTy,
                         std::vector<FunctionStateTy>,
                         std::vector<BasicBlockStateTy>>>
      stuff;

  jv_bin_fn_bb_state_t(const jv_t &jv) : jv(jv) {
    update();
  }

  BinaryStateTy &for_binary(const binary_t &binary) {
    return std::get<0>(stuff.at(index_of_binary(binary, jv)));
  }

  FunctionStateTy &for_function(const function_t &function) {
    binary_index_t BIdx = binary_index_of_function(function, jv);
    std::vector<FunctionStateTy> &function_state_vec = std::get<1>(stuff.at(BIdx));

    const binary_t &binary = jv.Binaries.at(BIdx);
    function_index_t FIdx = index_of_function_in_binary(function, binary);

    return function_state_vec.at(FIdx);
  }

  BasicBlockStateTy &for_basic_block(const binary_t &binary, basic_block_t bb) {
    binary_index_t BIdx = index_of_binary(binary, jv);
    std::vector<BasicBlockStateTy> &bb_state_vec = std::get<2>(stuff.at(BIdx));

    basic_block_index_t BBIdx = index_of_basic_block(binary.Analysis.ICFG, bb);

    return bb_state_vec.at(BBIdx);
  }

  void update(void) {
    stuff.resize(jv.Binaries.size());

    for_each_binary(jv, [&](const binary_t &binary) {
      auto &bin_stuff = stuff.at(index_of_binary(binary, jv));

      std::get<1>(bin_stuff).resize(binary.Analysis.Functions.size());
      std::get<2>(bin_stuff).resize(boost::num_vertices(binary.Analysis.ICFG));
    });
  }
};

}

#endif /* __cplusplus */
