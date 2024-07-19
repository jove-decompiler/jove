#include "tool.h"
#include "tcg.h"
#include "B.h"
#include "disas.h"

#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/DataExtractor.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/WithColor.h>

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/graph/breadth_first_search.hpp>
#include <boost/graph/filtered_graph.hpp>
#include <boost/graph/graphviz.hpp>
#include <boost/icl/split_interval_map.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/unordered_set.hpp>

#include <memory>

#include "jove_macros.h"

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

namespace {

struct binary_state_t {
  std::unique_ptr<llvm::object::Binary> Bin;
};

}

class CFGTool : public StatefulJVTool<ToolKind::CopyOnWrite, binary_state_t, void, void> {
  struct Cmdline {
    cl::opt<std::string> Addr;
    cl::opt<std::string> Binary;
    cl::alias BinaryAlias;
    cl::opt<bool> PrintTerminatorType;
    cl::opt<std::string> LocalGotoAddress;
    cl::alias LocalGotoAddressAlias;
    cl::opt<bool> PrintInsnBytes;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Addr(cl::Positional, cl::Required,
               cl::desc("address of basic block of interest"),
               cl::value_desc("hexadecimal address"), cl::cat(JoveCategory)),

          Binary("binary", cl::desc("Binary of function"), cl::Required,
                 cl::cat(JoveCategory)),

          BinaryAlias("b", cl::desc("Alias for --binary."),
                      cl::aliasopt(Binary), cl::cat(JoveCategory)),

          PrintTerminatorType("terminator-type",
                              cl::desc("Print terminator type at end of BB"),
                              cl::cat(JoveCategory)),

          LocalGotoAddress(
              "indjmp", cl::desc("Only print given local goto and its targets"),
              cl::cat(JoveCategory)),

          LocalGotoAddressAlias("j", cl::desc("Alias for --indjmp."),
                                cl::aliasopt(LocalGotoAddress),
                                cl::cat(JoveCategory)),

          PrintInsnBytes("insn-bytes", cl::desc("Print machine code bytes"),
                         cl::cat(JoveCategory)) {}
  } opts;

  binary_index_t BinaryIndex = invalid_binary_index;

  disas_t disas;
  tiny_code_generator_t TCG;

public:
  CFGTool() : opts(JoveCategory) {}

  int Run(void) override;

  template <typename GraphTy>
  std::string disassemble_basic_block(const GraphTy &,
                                      typename GraphTy::vertex_descriptor);
};

JOVE_REGISTER_TOOL("cfg", CFGTool);

typedef boost::format fmt;

struct reached_visitor : public boost::default_bfs_visitor {
  boost::unordered_set<basic_block_t> &out;

  reached_visitor(boost::unordered_set<basic_block_t> &out) : out(out) {}

  void discover_vertex(basic_block_t bb,
                       const interprocedural_control_flow_graph_t &) const {
    out.insert(bb);
  }
};

template <typename GraphTy>
struct graphviz_label_writer {
  CFGTool &tool;
  const GraphTy &G;

  graphviz_label_writer(CFGTool &tool, const GraphTy &G) : tool(tool), G(G) {}

  void operator()(std::ostream &out,
                  const typename GraphTy::vertex_descriptor &V) const {
    std::string src = tool.disassemble_basic_block(G, V);

    src.reserve(2 * src.size());

    boost::replace_all(src, "\\", "\\\\");
    boost::replace_all(src, "\r\n", "\\l");
    boost::replace_all(src, "\n", "\\l");
    boost::replace_all(src, "\"", "\\\"");
    boost::replace_all(src, "{", "\\{");
    boost::replace_all(src, "}", "\\}");
    boost::replace_all(src, "|", "\\|");
    boost::replace_all(src, "|", "\\|");
    //boost::replace_all(src, "<", "\\<");
    //boost::replace_all(src, ">", "\\>");
    boost::replace_all(src, "(", "\\(");
    boost::replace_all(src, ")", "\\)");
    //boost::replace_all(src, ",", "\\,");
    boost::replace_all(src, ";", "\\;");
    //boost::replace_all(src, ":", "\\:");
    //boost::replace_all(src, " ", "\\ ");

    out << "[";
    if (true /* ForGraphviz */) {
#if 0
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
    out << src;
    out << "\"]";
  }
};

template <typename GraphTy>
std::string CFGTool::disassemble_basic_block(const GraphTy &G,
                                             typename GraphTy::vertex_descriptor V) {
  assert(BinaryIndex != invalid_binary_index);

  binary_t &b = jv.Binaries.at(BinaryIndex);

  llvm::object::Binary &Bin = *state.for_binary(b).Bin;
  TCG.set_binary(Bin);

  uint64_t End = G[V].Addr + G[V].Size;

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
  if (G[V].Term.Type != TERMINATOR::NONE)
    End += 4; /* delay slot */
#endif

  std::string res;

  uint64_t InstLen = 0;
  for (uint64_t A = G[V].Addr; A < End; A += InstLen) {
    llvm::MCInst Inst;

    const void *ExpectedContents = B::toMappedAddr(Bin, A);
    if (!ExpectedContents)
      break;

    const uint8_t *Contents = (uint8_t *)ExpectedContents;

    std::string errmsg;
    bool Disassembled;
    {
      llvm::raw_string_ostream ErrorStrStream(errmsg);

      llvm::ArrayRef<uint8_t> ContentsRef(Contents, UINT32_MAX);

      Disassembled = disas.DisAsm->getInstruction(Inst, InstLen, ContentsRef, A,
                                                  ErrorStrStream);
    }

    if (!Disassembled) {
      res.append("failed to disassemble ");
      res.append(taddr2str(A));
      if (!errmsg.empty()) {
        res.append(": ");
        res.append(errmsg);
      }
      res.push_back('\n');
      break;
    }

    std::string line;
    {
      llvm::raw_string_ostream StrStream(line);
      disas.IP->printInst(&Inst, A, "", *disas.STI, StrStream);
    }
    boost::trim(line);

    res.append((fmt("%x   ") % A).str());

    if (opts.PrintInsnBytes) {
      std::string s;
      for (unsigned i = 0; i < InstLen; ++i)
        s.append((fmt("%02x ") % (unsigned)Contents[i]).str());
      res.append((fmt("%-18s ") % s).str());
    }

    res.append(line);
    res.push_back('\n');
  }

  if (opts.PrintTerminatorType && G[V].Term.Type != TERMINATOR::NONE) {
    res.push_back('\n');
    res.append(description_of_terminator(G[V].Term.Type));
    res.push_back('\n');
  }

  return res;
}

template <typename GraphTy>
struct graphviz_edge_prop_writer {
  const GraphTy &G;
  graphviz_edge_prop_writer(const GraphTy &G) : G(G) {}

  void operator()(std::ostream &out,
                  const typename GraphTy::edge_descriptor &E) const {
    static const char *edge_type_styles[] = {
        "solid", "dashed", /*"invis"*/ "dotted"
    };

    const typename GraphTy::vertex_descriptor V = boost::source(E, G);

    const char *edge_type_style = G[V].Term.Type == TERMINATOR::INDIRECT_JUMP
                                      ? edge_type_styles[1]
                                      : edge_type_styles[0];

    out << "[style=\"" << edge_type_style << "\"]";
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

typedef boost::filtered_graph<
    interprocedural_control_flow_graph_t,
    boost::keep_all,
    boost::is_in_subset<boost::unordered_set<basic_block_t>>>
    control_flow_graph_t;

typedef control_flow_graph_t cfg_t;

int CFGTool::Run(void) {
  std::string path_to_graph_easy = locator().graph_easy();

  //
  // find the binary of interest
  //
  BinaryIndex = invalid_binary_index;

  for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
    if (!strstr(jv.Binaries.at(BIdx).Name.c_str(), opts.Binary.c_str()))
      continue;

    BinaryIndex = BIdx;
    break;
  }

  if (BinaryIndex == invalid_binary_index) {
    WithColor::error() << llvm::formatv("failed to find binary \"{0}\"\n",
                                        opts.Binary);
    return 1;
  }

  binary_t &b = jv.Binaries.at(BinaryIndex);
  auto &ICFG = b.Analysis.ICFG;

  //
  // initialize state associated with binary
  //
  state.for_binary(b).Bin = B::Create(b.data());

  uint64_t Addr = strtoull(opts.Addr.c_str(), nullptr, 0x10);

  //
  // is there a function at the exact address provided?
  //
  function_index_t FunctionIndex = invalid_function_index;

  if (exists_function_at_address(b, Addr)) {
    FunctionIndex = index_of_function_at_address(b, Addr);
    goto Found;
  }

  //
  // is there a block we know about at the address?
  //
  if (exists_basic_block_at_address(Addr, b)) {
    basic_block_t bb = basic_block_at_address(Addr, b);
    if (ICFG[bb].hasParent()) {
      FunctionIndex = *ICFG[bb].Parents->begin();
      goto Found;
    }

    WithColor::warning() << llvm::formatv(
        "failed to find function for block {0:x} in {1}\n", ICFG[bb].Addr,
        b.path_str());
    return 1;
  }

  //
  // give up
  //
  WithColor::error() << "failed to find block at given address\n";
  return 1;

Found:
  const function_t &f = b.Analysis.Functions.at(FunctionIndex);
  assert(is_basic_block_index_valid(f.Entry));

  std::string dot_path = (fs::path(temporary_dir()) / "cfg.dot").string();

  auto output_cfg = [&](const cfg_t &cfg) -> void {
    std::ofstream ofs(dot_path);

    std::map<cfg_t::vertex_descriptor, int> idx_map;
    {
      int i = 0;
      cfg_t::vertex_iterator vi, vi_end;
      for (std::tie(vi, vi_end) = boost::vertices(cfg); vi != vi_end; ++vi)
        idx_map[*vi] = i++;
    }

    //
    // generate graphviz
    //
    boost::write_graphviz(
        ofs, cfg,
        graphviz_label_writer<cfg_t>(*this, cfg),
        graphviz_edge_prop_writer<cfg_t>(cfg),
        graphviz_prop_writer(),
        boost::associative_property_map<
            std::map<cfg_t::vertex_descriptor, int>>(idx_map));
  };

  boost::unordered_set<basic_block_t> blocks;

  reached_visitor vis(blocks);
  boost::breadth_first_search(ICFG, f.Entry, boost::visitor(vis));

  boost::keep_all e_filter;
  boost::is_in_subset<boost::unordered_set<basic_block_t>> v_filter(blocks);

  cfg_t cfg(ICFG, e_filter, v_filter);

  if (opts.LocalGotoAddress.empty()) {
    output_cfg(cfg);
  } else {
    uint64_t indjmp_addr =
        strtoull(opts.LocalGotoAddress.c_str(), nullptr, 0x10);
    boost::unordered_set<basic_block_t> indjmp_blocks;

    cfg_t::vertex_iterator vi, vi_end;
    for (std::tie(vi, vi_end) = boost::vertices(cfg); vi != vi_end; ++vi) {
      if (cfg[*vi].Term.Addr == indjmp_addr) {
        indjmp_blocks.insert(*vi);

        {
          auto it_pair = boost::adjacent_vertices(*vi, cfg);
          std::copy(it_pair.first, it_pair.second,
                    std::inserter(indjmp_blocks, indjmp_blocks.end()));
        }

        break;
      }
    }

    if (indjmp_blocks.empty()) {
      WithColor::error() << llvm::formatv("indirect jump @ {0:x} not found!",
                                          indjmp_addr);
      return 1;
    }

    boost::keep_all e_filter;
    boost::is_in_subset<boost::unordered_set<basic_block_t>> v_filter(indjmp_blocks);

    cfg_t _cfg(ICFG, e_filter, v_filter);

    output_cfg(_cfg);
  }

  return RunExecutableToExit(path_to_graph_easy, [&](auto Arg) {
    Arg(path_to_graph_easy);

    Arg("--input=" + dot_path);
    //Arg("--as=ascii");
    Arg("--as=boxart");
  });
}

}
