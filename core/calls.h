#pragma once
#include <jove/jove.h>

namespace jove {

typedef boost::adjacency_list<boost::vecS,           /* OutEdgeList */
                              boost::vecS,           /* VertexList */
                              boost::bidirectionalS, /* Directed */
                              dynamic_target_t,      /* VertexProperties */
                              boost::no_property,    /* EdgeProperties */
                              boost::no_property,    /* GraphProperties */
                              boost::vecS>           /* EdgeList */
    call_graph_t;

typedef call_graph_t::vertex_descriptor call_node_t;

template <bool MT, bool MinSize>
struct call_graph_builder_t {
  using jv_t = jv_base_t<MT, MinSize>;
  using binary_t = binary_base_t<MT, MinSize>;
  using icfg_t = ip_icfg_base_t<MT>;
  using bb_t = binary_t::bb_t;

  call_graph_t G;

  struct function_state_t {
    call_node_t V = boost::graph_traits<call_graph_t>::null_vertex();

    function_state_t(auto &, auto &) noexcept {}
  };

  jv_state_t<void, function_state_t, void, AreWeMT, false, true, true, true, MT,
             MinSize>
      state;

  call_graph_builder_t(const jv_t &) noexcept;
  call_graph_builder_t() = delete;

  void write_graphviz(std::ostream &) const;
};

}
