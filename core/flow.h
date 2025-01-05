#pragma once
#include "jove/jove.h"

namespace jove {

struct flow_vertex_properties_t {
  const basic_block_properties_t::Analysis_t *Analysis = nullptr;

  tcg_global_set_t IN, OUT;
};

struct flow_edge_properties_t {
  struct {
    tcg_global_set_t mask = ~tcg_global_set_t();
  } reach;
};

struct flow_graph_dummy_analyses_t {
  std::deque<bbprop_t::Analysis_t> deq;
};

typedef boost::adjacency_list<boost::vecS, /*parallel*/ /* OutEdgeList */
                              boost::vecS,              /* VertexList */
                              boost::bidirectionalS,    /* Directed */
                              flow_vertex_properties_t, /* VertexProperties */
                              flow_edge_properties_t,   /* EdgeProperties */
                              flow_graph_dummy_analyses_t  /* GraphProperties */>
    flow_graph_t;

typedef flow_graph_t::vertex_descriptor flow_vertex_t;
typedef flow_graph_t::edge_descriptor flow_edge_t;

using flow_vertex_vec_t = std::vector<flow_vertex_t>;

}
