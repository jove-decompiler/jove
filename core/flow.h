#pragma once
#include "jove/jove.h"
#include <boost/container/slist.hpp>

//
// data-flow analysis (liveness, reaching definitions)
//

namespace jove {

struct flow_vertex_properties_t {
  const bb_analysis_t *Analysis = nullptr;

  tcg_global_set_t IN, OUT;
};

struct flow_edge_properties_t {
  struct {
    tcg_global_set_t mask = ~tcg_global_set_t();
  } reach;
};

struct flow_graph_dummy_analyses_t {
  boost::container::slist<bb_analysis_t
                          /* boost::container::node_allocator<bb_analysis_t> */>
      extra;
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


void verticesInDfsOrder(const flow_graph_t &, flow_vertex_vec_t &out);
void livenessComputeFixpoint(flow_graph_t &, const flow_vertex_vec_t &dfsOrder);
void reachingComputeFixpoint(flow_graph_t &, const flow_vertex_vec_t &dfsOrder);

}
