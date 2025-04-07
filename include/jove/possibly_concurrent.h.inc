#ifndef IN_JOVE_H
#error "only to be included inline in jove/jove.h"
#endif

//
// The concurrent and non-concurrent data structures can be move-constructed
// from one another.
//
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
