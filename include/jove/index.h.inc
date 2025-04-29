#ifndef IN_JOVE_H
#error "only to be included inline in jove/jove.h"
#endif

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

template <bool MT = true>
using ip_dynamic_target_set = possibly_concurrent_flat_set<MT,
    dynamic_target_t, boost::hash<dynamic_target_t>,
    std::equal_to<dynamic_target_t>,
    boost::interprocess::allocator<dynamic_target_t, segment_manager_t>>;

typedef boost::concurrent_flat_set<
    binary_index_t, boost::hash<binary_index_t>, std::equal_to<binary_index_t>,
    boost::interprocess::allocator<binary_index_t, segment_manager_t>>
    ip_binary_index_set;

typedef std::set<binary_index_t> binary_index_set;

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
