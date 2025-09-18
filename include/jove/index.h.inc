#ifndef IN_JOVE_H
#error "only to be included inline in jove/jove.h"
#endif

typedef uint32_t binary_index_t;
typedef uint32_t function_index_t;
typedef uint32_t basic_block_index_t;
typedef uint32_t call_graph_index_t;

// FIXME make our own custom class so these things are trivially copyable
typedef std::pair<binary_index_t, function_index_t> dynamic_target_t;
typedef std::pair<binary_index_t, basic_block_index_t> block_t;

constexpr binary_index_t
    invalid_binary_index = std::numeric_limits<binary_index_t>::max();
constexpr function_index_t
    invalid_function_index = std::numeric_limits<function_index_t>::max();
constexpr basic_block_index_t
    invalid_basic_block_index = std::numeric_limits<basic_block_index_t>::max();
constexpr call_graph_index_t
    invalid_call_graph_index = std::numeric_limits<call_graph_index_t>::max();
constexpr dynamic_target_t
    invalid_dynamic_target(invalid_binary_index,
                           invalid_function_index);
constexpr block_t
    invalid_block(invalid_binary_index,
                  invalid_basic_block_index);

constexpr bool is_binary_index_valid(binary_index_t idx) {
  return idx != invalid_binary_index;
}
constexpr bool is_function_index_valid(function_index_t idx) {
  return idx != invalid_function_index;
}
constexpr bool is_basic_block_index_valid(basic_block_index_t idx) {
  return idx != invalid_basic_block_index;
}
constexpr bool is_call_graph_index_valid(call_graph_index_t idx) {
  return idx != invalid_call_graph_index;
}
constexpr bool is_dynamic_target_valid(dynamic_target_t X) {
  return is_binary_index_valid(X.first) &&
         is_function_index_valid(X.second);
}
constexpr bool is_block_valid(block_t X) {
  return is_binary_index_valid(X.first) &&
         is_basic_block_index_valid(X.second);
}

template <bool MT, bool Node>
using ip_dynamic_target_set =
    possibly_concurrent_node_or_flat_set<MT, Node, dynamic_target_t,
                                         boost::hash<dynamic_target_t>,
                                         std::equal_to<dynamic_target_t>>;

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
    MT, std::true_type /* Spin */, ip_func_index_set,
    boost::hash<ip_func_index_set>, std::equal_to<ip_func_index_set>,
    boost::interprocess::node_allocator<ip_func_index_set, segment_manager_t>>;

typedef boost::container::vector<
    function_index_t,
    boost::interprocess::allocator<function_index_t, segment_manager_t>,
    boost::container::vector_options<
        boost::container::stored_size<uint32_t>>::type>
    ip_func_index_vec;

template <bool MT>
using ip_func_index_vec_set = possibly_concurrent_node_set<
    MT, std::true_type /* Spin */, ip_func_index_vec,
    boost::hash<ip_func_index_vec>, std::equal_to<ip_func_index_vec>,
    boost::interprocess::node_allocator<ip_func_index_vec, segment_manager_t>>;

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
