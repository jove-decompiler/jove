#include "calls.h"

#include <boost/graph/graphviz.hpp>
#include <boost/filesystem.hpp>

#include <numeric>

namespace fs = boost::filesystem;

namespace jove {

template <bool MT, bool MinSize>
call_graph_builder_t<MT, MinSize>::call_graph_builder_t(const jv_t &jv) noexcept
    : state(jv) {
  //
  // create vertex for every function
  //
  for_each_function(jv, [&](const function_t &f, const binary_t &b) {
    auto V = boost::add_vertex(G);

    G[V] = target_of_function(f);

    state.for_function(f).V = V;
  });

  //
  // create the edges
  //
  for_each_function(jv, [&](const function_t &callee, const binary_t &b) {
    const ip_callers_t *pcallers;
    auto s_lck_callers = callee.Callers.get<AreWeMT>(pcallers);

    for (const auto &pair : *pcallers) {
      // determine block in caller
      // look at parents of block
      assert(is_binary_index_valid(pair.first));

      const binary_t &caller_b = jv.Binaries.at(pair.first);
      const icfg_t &ICFG = caller_b.Analysis.ICFG;

      auto s_lck_bbmap = caller_b.BBMap.template shared_access<AreWeMT>();

      bb_t bb = basic_block_at_address(pair.second, caller_b);
      const bbprop_t &bbprop = ICFG[bb];

      for (function_index_t FIdx : bbprop.Parents.get<>()) {
        const function_t &caller = caller_b.Analysis.Functions.at(FIdx);

        boost::add_edge(state.for_function(caller).V,
                        state.for_function(callee).V, G);
      }
    }
  });
}

template <bool MT, bool MinSize>
void call_graph_builder_t<MT, MinSize>::write_graphviz(std::ostream &os) const {
  struct graphviz_label_writer {
    const jv_base_t<MT, MinSize> &jv;
    const call_graph_t &G;

    graphviz_label_writer(const jv_base_t<MT, MinSize> &jv,
                          const call_graph_t &G)
        : jv(jv), G(G) {}

    void operator()(std::ostream &out,
		    const typename call_graph_t::vertex_descriptor &V) const {
      const function_t &f = function_of_target(G[V], jv);
      const auto &b = binary_of_function(f, jv);

      std::string str(b.is_file() ? fs::path(b.path()).filename().string()
				  : std::string(b.Name.c_str()));
      std::size_t dotPos = str.find('.');
      if (dotPos != std::string::npos)
	str = str.substr(0, dotPos);

      str += ".";
      str += std::to_string(index_of_function(f));

      out << "[";
      if (true /* ForGraphviz */) {
#if 1
	out << "shape=plain, ";
	out << "style=filled, ";
	out << "fillcolor=grey, ";
#else
	out << "shape=box, ";
	out << "width=0, ";
	out << "height=0, ";
	out << "margin=0, ";
#endif
      }

      out << "label=\"\\l";
      out << str;
      out << "\"]";
    }
  };

  struct graphviz_edge_prop_writer {
    void operator()(std::ostream &out,
		    const typename call_graph_t::edge_descriptor &E) const {
      static const char *edge_type_styles[] = {
	  "solid", "dashed", /*"invis"*/ "dotted"
      };

      out << "[style=\"" << edge_type_styles[0] << "\"]";
    }
  };

  struct graphviz_prop_writer {
    void operator()(std::ostream &out) const {
      out << "fontname = \"Courier\"\n"
	     "fontsize = 10\n"
	     "\n"
	     "node [\n"
	     "fontname = \"Courier\"\n"
	     "fontsize = 10\n"
	     "shape = \"box\"\n"
	     "]\n"
	     "\n"
	     "edge [\n"
	     "fontname = \"Courier\"\n"
	     "fontsize = 10\n"
	     "]\n"
	     "\n";
    }
  };

  std::vector<int> idx_map(boost::num_vertices(G));
  std::iota(idx_map.begin(), idx_map.end(), 0);

  boost::write_graphviz(
      os, G,
      graphviz_label_writer(state.jv, G),
      graphviz_edge_prop_writer(),
      graphviz_prop_writer(),
      boost::make_iterator_property_map(
	  idx_map.begin(),
	  boost::get(boost::vertex_index, G)
      ));
}

#define VALUES_TO_INSTANTIATE_WITH1                                            \
    ((true))                                                                   \
    ((false))
#define VALUES_TO_INSTANTIATE_WITH2                                            \
    ((true))                                                                   \
    ((false))
#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)

#define DO_INSTANTIATE(r, product)                                             \
  template struct call_graph_builder_t<                                        \
      GET_VALUE(BOOST_PP_SEQ_ELEM(1, product)),                                \
      GET_VALUE(BOOST_PP_SEQ_ELEM(0, product))>;

BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_INSTANTIATE, (VALUES_TO_INSTANTIATE_WITH1)(VALUES_TO_INSTANTIATE_WITH2))

}
