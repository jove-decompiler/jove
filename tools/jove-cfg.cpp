#include "tool.h"
#include "tcg.h"
#include "elf.h"
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

struct binary_state_t {
  std::unique_ptr<llvm::object::Binary> ObjectFile;
};

typedef boost::filtered_graph<
    interprocedural_control_flow_graph_t,
    boost::keep_all,
    boost::is_in_subset<boost::unordered_set<basic_block_t>>>
    control_flow_graph_t;

typedef control_flow_graph_t cfg_t;

class CFGTool : public Tool {
  struct Cmdline {
    cl::opt<std::string> jv;
    cl::alias jvAlias;
    cl::opt<std::string> Binary;
    cl::alias BinaryAlias;
    cl::opt<std::string> FunctionAddress;
    cl::opt<bool> PrintTerminatorType;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : jv("decompilation", cl::desc("Jove decompilation"), cl::Required,
             cl::cat(JoveCategory)),

          jvAlias("d", cl::desc("Alias for --decompilation."), cl::aliasopt(jv),
                  cl::cat(JoveCategory)),

          Binary("binary", cl::desc("Binary of function"), cl::Required,
                 cl::cat(JoveCategory)),

          BinaryAlias("b", cl::desc("Alias for --binary."),
                      cl::aliasopt(Binary), cl::cat(JoveCategory)),

          FunctionAddress(cl::Positional, cl::desc("<address>"), cl::Required,
                          cl::cat(JoveCategory)),

          PrintTerminatorType("terminator-type",
                              cl::desc("Print terminator type at end of BB"),
                              cl::cat(JoveCategory))

    {}
  } opts;

  decompilation_t Decompilation;

  binary_index_t BinaryIndex = invalid_binary_index;

  disas_t disas;
  tiny_code_generator_t TCG;

public:
  CFGTool() : opts(JoveCategory) {}

  int Run(void);

  std::string disassemble_basic_block(const cfg_t &, cfg_t::vertex_descriptor);
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

struct graphviz_label_writer {
  CFGTool &tool;
  const cfg_t &cfg;

  graphviz_label_writer(CFGTool &tool, const cfg_t &cfg) : tool(tool), cfg(cfg) {}

  void operator()(std::ostream &out,
                  const cfg_t::vertex_descriptor &v) const {
    std::string src = tool.disassemble_basic_block(cfg, v);

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

std::string CFGTool::disassemble_basic_block(const cfg_t &G,
                                             cfg_t::vertex_descriptor V) {
  assert(BinaryIndex != invalid_binary_index);

  binary_t &binary = Decompilation.Binaries[BinaryIndex];

  TCG.set_binary(*state_for_binary(binary).ObjectFile);

  const ELFF &E = *llvm::cast<ELFO>(state_for_binary(binary).ObjectFile.get())->getELFFile();

  tcg_uintptr_t End = G[V].Addr + G[V].Size;

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
  if (G[V].Term.Type != TERMINATOR::NONE)
    End += 4; /* delay slot */
#endif

  std::string res;

  uint64_t InstLen = 0;
  for (uintptr_t A = G[V].Addr; A < End; A += InstLen) {
    llvm::MCInst Inst;

    llvm::Expected<const uint8_t *> ExpectedContents = E.toMappedAddr(A);
    if (!ExpectedContents)
      break;

    const uint8_t *Contents = *ExpectedContents;

    std::string errmsg;
    bool Disassembled;
    {
      llvm::raw_string_ostream ErrorStrStream(errmsg);

      llvm::ArrayRef<uint8_t> ContentsRef(Contents, G[V].Size);

      Disassembled = disas.DisAsm->getInstruction(Inst, InstLen, ContentsRef, A,
                                                  ErrorStrStream);
    }

    if (!Disassembled) {
      res.append("failed to disassemble");
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

struct graphviz_edge_prop_writer {
  const cfg_t &cfg;
  graphviz_edge_prop_writer(const cfg_t &cfg) : cfg(cfg) {}

  void operator()(std::ostream &out,
                  const cfg_t::edge_descriptor &e) const {
    static const char *edge_type_styles[] = {
        "solid", "dashed", /*"invis"*/ "dotted"
    };

    const cfg_t::vertex_descriptor V = boost::source(e, cfg);

    const char *edge_type_style = cfg[V].Term.Type == TERMINATOR::INDIRECT_JUMP
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

static char tmpdir[] = {'/', 't', 'm', 'p', '/', 'X',
                        'X', 'X', 'X', 'X', 'X', '\0'};

int CFGTool::Run(void) {
  if (!fs::exists(opts.jv)) {
    WithColor::error() << "can't find decompilation.jv\n";
    return 1;
  }

  bool git = fs::is_directory(opts.jv);
  std::string jvfp = git ? opts.jv + "decompilation.jv" : opts.jv;

  ReadDecompilationFromFile(jvfp, Decompilation);

  assert(!opts.FunctionAddress.empty());

  //
  // find the binary of interest
  //
  BinaryIndex = invalid_binary_index;

  for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    const binary_t &binary = Decompilation.Binaries[BIdx];
    if (binary.Path.find(opts.Binary) == std::string::npos)
      continue;

    BinaryIndex = BIdx;
    break;
  }

  if (BinaryIndex == invalid_binary_index) {
    WithColor::error() << llvm::formatv("failed to find binary \"{0}\"\n",
                                        opts.Binary);
    return 1;
  }

  binary_t &binary = Decompilation.Binaries[BinaryIndex];

  //
  // initialize state associated with binary
  //
  llvm::StringRef Buffer(reinterpret_cast<const char *>(&binary.Data[0]),
                         binary.Data.size());
  llvm::StringRef Identifier(binary.Path);
  llvm::MemoryBufferRef MemBuffRef(Buffer, Identifier);

  llvm::Expected<std::unique_ptr<obj::Binary>> BinOrErr =
      obj::createBinary(MemBuffRef);

  if (!BinOrErr) {
    fprintf(stderr, "failed to open %s\n", opts.Binary.c_str());
    return 1;
  }

  {
    std::unique_ptr<obj::Binary> &BinRef = BinOrErr.get();

    state_for_binary(binary).ObjectFile = std::move(BinRef);
  }

  obj::Binary *B = state_for_binary(binary).ObjectFile.get();
  if (!llvm::isa<ELFO>(B)) {
    fprintf(stderr, "invalid binary\n");
    return 1;
  }

  //
  // find the function of interest
  //
  function_index_t FunctionIndex = invalid_function_index;

  assert(!opts.FunctionAddress.empty());
  uintptr_t FuncAddr = std::stoi(opts.FunctionAddress.c_str(), 0, 16);

  const auto &ICFG = binary.Analysis.ICFG;

  for (function_index_t FIdx = 0; FIdx < binary.Analysis.Functions.size(); ++FIdx) {
    const function_t &f = binary.Analysis.Functions[FIdx];

    uintptr_t EntryAddr = ICFG[boost::vertex(f.Entry, ICFG)].Addr;
    if (EntryAddr != FuncAddr)
      continue;

    FunctionIndex = FIdx;
    goto Found;
  }

  WithColor::error() << llvm::formatv(
      "failed to find function with address 0x{0:x} in {1}\n", FuncAddr,
      binary.Path);
  return 1;

Found:
  const function_t &f = binary.Analysis.Functions[FunctionIndex];

  boost::unordered_set<basic_block_t> blocks;

  reached_visitor vis(blocks);
  boost::breadth_first_search(ICFG, f.Entry, boost::visitor(vis));

  boost::keep_all e_filter;
  boost::is_in_subset<boost::unordered_set<basic_block_t>> v_filter(blocks);

  cfg_t cfg(ICFG, e_filter, v_filter);

  //
  // create temporary directory
  //
  if (!mkdtemp(tmpdir)) {
    WithColor::error() << "mkdtemp failed : " << strerror(errno) << '\n';
    return 1;
  }

  llvm::outs() << "tmpdir: " << tmpdir << '\n';

  std::string dot_path = (fs::path(tmpdir) / "cfg.dot").string();

  //
  // generate graphviz
  //
  {
    std::ofstream ofs(dot_path);

    std::map<cfg_t::vertex_descriptor, int> idx_map;
    {
      int i = 0;
      cfg_t::vertex_iterator vi, vi_end;
      for (std::tie(vi, vi_end) = boost::vertices(cfg); vi != vi_end; ++vi)
        idx_map[*vi] = i++;
    }

    boost::write_graphviz(
        ofs, cfg,
	graphviz_label_writer(*this, cfg),
        graphviz_edge_prop_writer(cfg),
	graphviz_prop_writer(),
        boost::associative_property_map<std::map<cfg_t::vertex_descriptor, int>>(idx_map));
  }

  //
  // graph-easy
  //
  bool haveGraphEasy = fs::exists("/usr/bin/vendor_perl/graph-easy") ||
                       fs::exists("/usr/bin/graph-easy");

  if (haveGraphEasy) {
    pid_t pid = fork();
    if (!pid) {
      std::string input_arg = "--input=" + dot_path;

      const char *arg_arr[] = {
        fs::exists("/usr/bin/vendor_perl/graph-easy")
            ? "/usr/bin/vendor_perl/graph-easy"
            : "/usr/bin/graph-easy",

        input_arg.c_str(),
#if 0
	"--as=ascii",
#else
        "--as=boxart",
#endif

        nullptr
      };

      print_command(&arg_arr[0]);

      close(STDIN_FILENO);
      execve(arg_arr[0], const_cast<char **>(&arg_arr[0]), ::environ);

      int err = errno;
      WithColor::error() << llvm::formatv("execve failed: {0}\n",
                                          strerror(err));
      return 1;
    }

    //
    // check exit code
    //
    if (WaitForProcessToExit(pid))
      WithColor::warning() << "graph-easy failed for " << dot_path << '\n';
  } else {
    WithColor::error() << "failed to find graph-easy executable file\n";
  }

  return 0;
}

}
