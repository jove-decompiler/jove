#include "flow.h"

#include <boost/range/adaptor/reversed.hpp>

namespace jove {

void verticesInDfsOrder(const flow_graph_t &G, flow_vertex_vec_t &out) {
  out.reserve(boost::num_vertices(G));

  struct in_dfs_order_visitor : public boost::default_dfs_visitor {
    flow_vertex_vec_t &out;

    in_dfs_order_visitor(flow_vertex_vec_t &out) : out(out) {}

    void discover_vertex(flow_vertex_t v, const flow_graph_t &) const {
      out.push_back(v);
    }
  };

  std::vector<boost::default_color_type> ColorVec(boost::num_vertices(G));
  auto ColorPropMap = boost::make_iterator_property_map(
      ColorVec.begin(), boost::get(boost::vertex_index, G));

  in_dfs_order_visitor vis(out);
  boost::depth_first_search(G, boost::visitor(vis).color_map(ColorPropMap));
}

void livenessComputeFixpoint(flow_graph_t &G,
                             const flow_vertex_vec_t &Vertices) {
  //
  // liveness analysis
  //
  for (flow_vertex_t V : Vertices) {
    G[V].IN.reset();
    G[V].OUT.reset();
  }

  bool change;
  do {
    change = false;

    for (flow_vertex_t V : boost::adaptors::reverse(Vertices)) {
      const tcg_global_set_t _IN = G[V].IN;

      auto eit_pair = boost::out_edges(V, G);
      const tcg_global_set_t G_V_OUT = std::accumulate(
          eit_pair.first,
          eit_pair.second,
          tcg_global_set_t(),
          [&](tcg_global_set_t res, flow_edge_t E) -> tcg_global_set_t {
            return res | G[boost::target(E, G)].IN;
          });

      const tcg_global_set_t use = G[V].Analysis->live.use;
      const tcg_global_set_t def = G[V].Analysis->live.def;

      const tcg_global_set_t G_V_IN = use | (G_V_OUT & ~def);

      G[V].OUT = G_V_OUT;
      G[V].IN = G_V_IN;

      change = change || _IN != G_V_IN;
    }
  } while (likely(change));
}

void reachingComputeFixpoint(flow_graph_t &G,
                             const flow_vertex_vec_t &Vertices) {
  //
  // reaching definitions
  //
  for (flow_vertex_t V : Vertices) {
    G[V].IN.reset();
    G[V].OUT.reset();
  }

  bool change;
  do {
    change = false;

    for (flow_vertex_t V : Vertices) {
      const tcg_global_set_t _OUT = G[V].OUT;

      auto eit_pair = boost::in_edges(V, G);
      const tcg_global_set_t G_V_IN = std::accumulate(
          eit_pair.first,
          eit_pair.second,
          tcg_global_set_t(),
          [&](tcg_global_set_t res, flow_edge_t E) -> tcg_global_set_t {
            return res | (G[boost::source(E, G)].OUT & G[E].reach.mask);
          });
      const tcg_global_set_t G_V_OUT = G[V].Analysis->reach.def | G_V_IN;

      G[V].OUT = G_V_OUT;
      G[V].IN = G_V_IN;

      change = change || _OUT != G_V_OUT;
    }
  } while (likely(change));
}

}
