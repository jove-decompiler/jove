#pragma once
#include <boost/graph/adjacency_list.hpp>
#include <cstdint>
#include <string>

namespace jove {

struct ida_flowgraph_node_info_t {
  uint64_t start_ea;

  std::string label;
};

struct ida_flowgraph_edge_info_t {
  std::string label;
};

typedef boost::adjacency_list<
    boost::setS, /* no parallel edges */
    boost::listS,
    boost::bidirectionalS, /* directed graph (with in and out edges) */
    ida_flowgraph_node_info_t,
    ida_flowgraph_edge_info_t>
    ida_flowgraph_t;

typedef ida_flowgraph_t::vertex_descriptor ida_flowgraph_node_t;
typedef ida_flowgraph_t::edge_descriptor   ida_flowgraph_edge_t;

bool ReadIDAFlowgraphFromGDLFile(const char *filepath, ida_flowgraph_t &out);
bool ReadIDAFlowgraphFromDOTFile(const char *filepath, ida_flowgraph_t &out);

}
