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
