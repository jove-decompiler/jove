#pragma once
#include <jove/jove.h>

namespace jove {

typedef boost::adjacency_list<boost::vecS,        /* OutEdgeList */
                              boost::vecS,        /* VertexList */
                              boost::directedS,   /* Directed */
                              dynamic_target_t,   /* VertexProperties */
                              boost::no_property, /* EdgeProperties */
                              boost::no_property, /* GraphProperties */
                              boost::vecS>        /* EdgeList */
    call_graph_t;

typedef call_graph_t::vertex_descriptor call_node_t;

template <bool MT>
struct call_graph_builder_t {
  call_graph_t G;

  struct function_state_t {
    call_node_t V = boost::graph_traits<call_graph_t>::null_vertex();

    function_state_t(auto &, auto &) noexcept {}
  };

  jv_state_t<void, function_state_t, void, false, false, true, false, MT, false> state;

  call_graph_builder_t(const jv_base_t<MT> &jv) noexcept;
  call_graph_builder_t() = delete;

  /* returns whether topological sort is perfect (acyclic graph) */
  bool best_toposort(std::vector<call_graph_t::vertex_descriptor> &out) const;
  void write_graphviz(std::ostream &) const;
};

}
