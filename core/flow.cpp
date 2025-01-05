#include "flow.h"

#include <boost/range/adaptor/reversed.hpp>

namespace jove {

void verticesInDfsOrder(const flow_graph_t &G, flow_vertex_vec_t &out) {
  out.reserve(boost::num_vertices(G));

  struct flowvert_dfs_visitor : public boost::default_dfs_visitor {
    flow_vertex_vec_t &out;

    flowvert_dfs_visitor(flow_vertex_vec_t &out) : out(out) {}

    void discover_vertex(flow_vertex_t v, const flow_graph_t &) const {
      out.push_back(v);
    }
  };

  std::unique_ptr<boost::default_color_type[]> ColorMap(
      new boost::default_color_type[boost::num_vertices(G)]);

  auto ColorPropMap = boost::make_iterator_property_map(
      ColorMap.get(), boost::get(boost::vertex_index, G));

  flowvert_dfs_visitor vis(out);
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
      G[V].OUT = std::accumulate(
          eit_pair.first,
          eit_pair.second,
          tcg_global_set_t(),
          [&](tcg_global_set_t res, flow_edge_t E) -> tcg_global_set_t {
            return res | G[boost::target(E, G)].IN;
          });

      tcg_global_set_t use = G[V].Analysis->live.use;
      tcg_global_set_t def = G[V].Analysis->live.def;

      G[V].IN = use | (G[V].OUT & ~def);

      change = change || _IN != G[V].IN;
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
      G[V].IN = std::accumulate(
          eit_pair.first,
          eit_pair.second,
          tcg_global_set_t(),
          [&](tcg_global_set_t res, flow_edge_t E) -> tcg_global_set_t {
            return res | (G[boost::source(E, G)].OUT & G[E].reach.mask);
          });
      G[V].OUT = G[V].Analysis->reach.def | G[V].IN;

      change = change || _OUT != G[V].OUT;
    }
  } while (likely(change));
}

}
