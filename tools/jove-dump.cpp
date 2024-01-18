#include "tool.h"

#include <llvm/Support/CommandLine.h>
#include <llvm/Support/DataTypes.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/ScopedPrinter.h>
#include <llvm/Support/WithColor.h>

#include <fstream>
#include <algorithm>
#include <boost/filesystem.hpp>
#include <boost/graph/breadth_first_search.hpp>
#include <boost/pending/indirect_cmp.hpp>
#include <boost/range/irange.hpp>
#include <boost/format.hpp>

namespace fs = boost::filesystem;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

class DumpTool : public Tool {
  struct Cmdline {
    cl::list<std::string> InputFilenames;
    cl::opt<bool> Compact;
    cl::opt<bool> Graphviz;
    cl::opt<bool> Statistics;
    cl::opt<bool> ListBinaries;
    cl::alias ListBinariesAlias;
    cl::opt<std::string> ListFunctions;
    cl::alias ListFunctionsAlias;
    cl::opt<std::string> ListFunctionBBs;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : InputFilenames(cl::Positional,
                         cl::desc("<input jove database>"), cl::Optional,
                         cl::cat(JoveCategory)),

          Compact("compact",
                  cl::desc("Print functions as list of basic-blocks addresses"),
                  cl::cat(JoveCategory)),

          Graphviz("graphviz",
                   cl::desc("Produce control-flow graphs for each function"),
                   cl::cat(JoveCategory)),

          Statistics("binary-stats", cl::desc("Print statistics"),
                     cl::cat(JoveCategory)),

          ListBinaries("list-binaries",
                       cl::desc("List binaries for jv"),
                       cl::cat(JoveCategory)),

          ListBinariesAlias("l", cl::desc("Alias for -list-binaries."),
                            cl::aliasopt(ListBinaries), cl::cat(JoveCategory)),

          ListFunctions("list-functions",
                        cl::desc("List functions for given binary"),
                        cl::cat(JoveCategory)),

          ListFunctionsAlias("f", cl::desc("Alias for -list-functions."),
                             cl::aliasopt(ListFunctions),
                             cl::cat(JoveCategory)),

          ListFunctionBBs(
              "list-fn-bbs",
              cl::desc("List basic blocks for functions for given binary"),
              cl::cat(JoveCategory))

    {}
  } opts;

public:
  DumpTool() : opts(JoveCategory) {}

  int Run(void) override;

  void dumpDecompilation(const jv_t &);
  void dumpInput(const std::string &Path);
};

JOVE_REGISTER_TOOL("dump", DumpTool);

typedef boost::format fmt;

struct reached_visitor : public boost::default_bfs_visitor {
  std::vector<basic_block_t> &out;

  reached_visitor(std::vector<basic_block_t> &out) : out(out) {}

  void discover_vertex(basic_block_t bb,
                       const interprocedural_control_flow_graph_t &) const {
    out.push_back(bb);
  }
};

void DumpTool::dumpDecompilation(const jv_t& jv) {
  llvm::ScopedPrinter Writer(llvm::outs());
  llvm::ListScope _(Writer, (fmt("Binaries (%u)") % jv.Binaries.size()).str());

  for (const auto &B : jv.Binaries) {
    llvm::DictScope __(Writer, B.Path.c_str());

    Writer.printBoolean("IsDynamicLinker",     B.IsDynamicLinker);
    Writer.printBoolean("IsExecutable",        B.IsExecutable);
    Writer.printBoolean("IsVDSO",              B.IsVDSO);
    Writer.printBoolean("IsPIC",               B.IsPIC);
    Writer.printBoolean("IsDynamicallyLoaded", B.IsDynamicallyLoaded);

    const auto &ICFG = B.Analysis.ICFG;

    if (is_function_index_valid(B.Analysis.EntryFunction) &&
        B.Analysis.EntryFunction < B.Analysis.Functions.size()) {
      const function_t &entryFunc =
          B.Analysis.Functions.at(B.Analysis.EntryFunction);
      Writer.printHex("Entry", ICFG[basic_block_of_index(entryFunc.Entry, ICFG)].Addr);
    }

    {
      llvm::ListScope ___(
          Writer, (fmt("Basic Blocks (%u)") % boost::num_vertices(ICFG)).str());

      icfg_t::vertex_iterator vi, vi_end;
      for (std::tie(vi, vi_end) = boost::vertices(ICFG); vi != vi_end; ++vi) {
        basic_block_t bb = *vi;

        llvm::DictScope ____(Writer, (fmt("0x%lX") % ICFG[bb].Addr).str());

        {
          auto inv_adj_it_pair = boost::inv_adjacent_vertices(bb, ICFG);

          std::vector<uintptr_t> preds;
          preds.resize(
              std::distance(inv_adj_it_pair.first, inv_adj_it_pair.second));

          std::transform(inv_adj_it_pair.first, inv_adj_it_pair.second,
                         preds.begin(), [&](basic_block_t target) -> uintptr_t {
                           return ICFG[target].Addr;
                         });

          Writer.printHexList("Predecessors", preds);
        }

        Writer.getOStream() << '\n';

        //Writer.printHex("Address", ICFG[bb].Addr);
        Writer.printNumber("Size", ICFG[bb].Size);

        {
          llvm::DictScope _____(Writer, (fmt("Term @ 0x%lX") % ICFG[bb].Term.Addr).str());

          //Writer.printHex("Address", ICFG[bb].Term.Addr);
          Writer.printString("Type", description_of_terminator(ICFG[bb].Term.Type));

          if (ICFG[bb].Term.Type == TERMINATOR::CALL) {
            Writer.printBoolean("Returns", ICFG[bb].Term._call.Returns);

            const function_t &f = B.Analysis.Functions.at(ICFG[bb].Term._call.Target);
            Writer.printString("Target", (fmt("0x%lX") % ICFG[basic_block_of_index(f.Entry, ICFG)].Addr).str());
          }

          if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP)
            Writer.printBoolean("IsLj", ICFG[bb].Term._indirect_jump.IsLj);

          if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL)
            Writer.printBoolean("Returns", ICFG[bb].Term._indirect_call.Returns);

          if (ICFG[bb].Term.Type == TERMINATOR::RETURN)
            Writer.printBoolean("Returns", ICFG[bb].Term._return.Returns);
        }

#if 0
        if (!(ICFG[bb].Analysis.Stale &&
              ICFG[bb].Analysis.live.def.none() &&
              ICFG[bb].Analysis.live.use.none() &&
              ICFG[bb].Analysis.reach.def.none()))
#endif
        {
          llvm::DictScope _____(Writer, "Analysis");

          {
            llvm::DictScope ______(Writer, "live");

            {
#if 0
              std::vector<unsigned> glbv;
              explode_tcg_global_set(glbv, ICFG[bb].Analysis.live.def);

              std::vector<std::string> descv;
              descv.resize(glbv.size());

              std::transform(glbv.begin(), glbv.end(), descv.begin(),
                             [&](unsigned glb) -> std::string {
                               return tcg._ctx.temps[glb].name;
                             });

              Writer.printList("def", descv);
#else
	      Writer.printString("def", ICFG[bb].Analysis.live.def.to_string());
#endif
            }

            {
#if 0
              std::vector<unsigned> glbv;
              explode_tcg_global_set(glbv, ICFG[bb].Analysis.live.use);

              std::vector<std::string> descv;
              descv.resize(glbv.size());

              std::transform(glbv.begin(), glbv.end(), descv.begin(),
                             [&](unsigned glb) -> std::string {
                               return tcg._ctx.temps[glb].name;
                             });

              Writer.printList("use", descv);
#else
	      Writer.printString("use", ICFG[bb].Analysis.live.use.to_string());
#endif
            }
          }

          {
            llvm::DictScope ______(Writer, "reach");

            {
#if 0
              std::vector<unsigned> glbv;
              explode_tcg_global_set(glbv, ICFG[bb].Analysis.reach.def);

              std::vector<std::string> descv;
              descv.resize(glbv.size());

              std::transform(glbv.begin(), glbv.end(), descv.begin(),
                             [&](unsigned glb) -> std::string {
                               return tcg._ctx.temps[glb].name;
                             });

              Writer.printList("def", descv);
#else
              Writer.printString("def", ICFG[bb].Analysis.reach.def.to_string());
#endif
            }
          }

#if 0
          if (ICFG[bb].Analysis.Stale)
            Writer.printBoolean("Stale", true);
#endif
        }

        Writer.getOStream() << '\n';

        if (ICFG[bb].hasDynTarget()) {
          std::vector<std::string> descv;
          descv.resize(ICFG[bb].getNumDynTargets());

          std::transform(ICFG[bb].dyn_targets_begin(),
                         ICFG[bb].dyn_targets_end(), descv.begin(),
                         [&](const auto &pair) -> std::string {
                           binary_index_t BIdx;
                           function_index_t FIdx;
                           std::tie(BIdx, FIdx) = pair;

                           const binary_t &b = jv.Binaries.at(BIdx);
                           const auto &_ICFG = b.Analysis.ICFG;
                           const function_t &callee = b.Analysis.Functions[FIdx];
                           uint64_t target_addr =
                               _ICFG[basic_block_of_index(callee.Entry, _ICFG)].Addr;

                           return (fmt("0x%lX @ %s") % target_addr %
                                   fs::path(b.path_str()).filename().string())
                               .str();
                         });

          Writer.printList("DynTargets", descv);
        }

        if (ICFG[bb].DynTargetsComplete)
          Writer.printBoolean("DynTargetsComplete", true);

        {
          auto adj_it_pair = boost::adjacent_vertices(bb, ICFG);

          std::vector<uintptr_t> succs;
          succs.resize(std::distance(adj_it_pair.first, adj_it_pair.second));

          std::transform(adj_it_pair.first, adj_it_pair.second, succs.begin(),
                         [&](basic_block_t target) -> uintptr_t {
                           return ICFG[target].Addr;
                         });

          Writer.printHexList("Successors", succs);
        }
      }
    }

    {
      llvm::ListScope ___(Writer, (fmt("Functions (%u)") % B.Analysis.Functions.size()).str());

      for (const function_t &f : B.Analysis.Functions) {
        llvm::DictScope ____(Writer, (fmt("Func @ 0x%lX") % ICFG[basic_block_of_index(f.Entry, ICFG)].Addr).str());

        //Writer.printHex("Address", ICFG[basic_block_of_index(f.Entry, ICFG)].Addr);

#if 0
        if (!(f.Analysis.Stale &&
              f.Analysis.args.none() &&
              f.Analysis.rets.none()))
#endif
        {
          llvm::DictScope _____(Writer, "Analysis");

          {
#if 0
            std::vector<unsigned> glbv;
            explode_tcg_global_set(glbv, f.Analysis.args);

            std::vector<std::string> descv;
            descv.resize(glbv.size());

            std::transform(glbv.begin(), glbv.end(), descv.begin(),
                           [&](unsigned glb) -> std::string {
                             return tcg._ctx.temps[glb].name;
                           });

            Writer.printList("Args", descv);
#else
            Writer.printString("Args", f.Analysis.args.to_string());
#endif
          }

          {
#if 0
            std::vector<unsigned> glbv;
            explode_tcg_global_set(glbv, f.Analysis.rets);

            std::vector<std::string> descv;
            descv.resize(glbv.size());

            std::transform(glbv.begin(), glbv.end(), descv.begin(),
                           [&](unsigned glb) -> std::string {
                             return tcg._ctx.temps[glb].name;
                           });

            Writer.printList("Rets", descv);
#else
            Writer.printString("Rets", f.Analysis.rets.to_string());
#endif
          }

#if 0
          if (f.Analysis.Stale)
            Writer.printBoolean("Stale", true);
#endif
        }

        Writer.printBoolean("IsABI", f.IsABI);
        Writer.printBoolean("IsSignalHandler", f.IsSignalHandler);
        Writer.printBoolean("Returns", f.Returns);
      }
    }

    if (!B.Analysis.RelocDynTargets.empty()) {
      llvm::ListScope ___(Writer, "Relocation Dynamic Targets");

      for (const auto &pair : B.Analysis.RelocDynTargets) {
        llvm::DictScope ____(Writer);

        Writer.printHex("Relocation Address", pair.first);
        if (!pair.second.empty()) {
          std::vector<std::string> descv;
          descv.resize(pair.second.size());

          std::transform(pair.second.begin(), pair.second.end(), descv.begin(),
                         [&](const auto &pair) -> std::string {
                           binary_index_t BIdx;
                           function_index_t FIdx;
                           std::tie(BIdx, FIdx) = pair;

                           auto &b = jv.Binaries[BIdx];
                           const auto &_ICFG = b.Analysis.ICFG;
                           auto &callee = b.Analysis.Functions[FIdx];
                           uintptr_t target_addr =
                               _ICFG[basic_block_of_index(callee.Entry, _ICFG)].Addr;

                           return (fmt("0x%lX @ %s") % target_addr %
                                   fs::path(b.path_str()).filename().string())
                               .str();
                         });

          Writer.printList("Relocation DynTargets", descv);
        }
      }
    }

    if (!B.Analysis.IFuncDynTargets.empty()) {
      llvm::ListScope ___(Writer, "IFunc Dynamic Targets");

      for (const auto &pair : B.Analysis.IFuncDynTargets) {
        llvm::DictScope ____(Writer);

        Writer.printHex("Resolver Address", pair.first);
        if (!pair.second.empty()) {
          std::vector<std::string> descv;
          descv.resize(pair.second.size());

          std::transform(pair.second.begin(), pair.second.end(), descv.begin(),
                         [&](const auto &pair) -> std::string {
                           binary_index_t BIdx;
                           function_index_t FIdx;
                           std::tie(BIdx, FIdx) = pair;

                           auto &b = jv.Binaries[BIdx];
                           const auto &_ICFG = b.Analysis.ICFG;
                           auto &callee = b.Analysis.Functions[FIdx];
                           uintptr_t target_addr =
                               _ICFG[basic_block_of_index(callee.Entry, _ICFG)].Addr;

                           return (fmt("0x%lX @ %s") % target_addr %
                                   fs::path(b.path_str()).filename().string())
                               .str();
                         });

          Writer.printList("DynTargets", descv);
        }
      }
    }

    if (!B.Analysis.SymDynTargets.empty()) {
      llvm::ListScope ___(Writer, "Symbol Dynamic Targets");

      for (const auto &pair : B.Analysis.SymDynTargets) {
        llvm::DictScope ____(Writer);

        Writer.printString("Name", un_ips(pair.first));
        if (!pair.second.empty()) {
          std::vector<std::string> descv;
          descv.resize(pair.second.size());

          std::transform(pair.second.begin(), pair.second.end(), descv.begin(),
                         [&](const auto &pair) -> std::string {
                           binary_index_t BIdx;
                           function_index_t FIdx;
                           std::tie(BIdx, FIdx) = pair;

                           auto &b = jv.Binaries[BIdx];
                           const auto &_ICFG = b.Analysis.ICFG;
                           auto &callee = b.Analysis.Functions[FIdx];
                           uintptr_t target_addr =
                               _ICFG[basic_block_of_index(callee.Entry, _ICFG)].Addr;

                           return (fmt("0x%lX @ %s") % target_addr %
                                   fs::path(b.path_str()).filename().string())
                               .str();
                         });

          Writer.printList("DynTargets", descv);
        }
      }
    }
  }
}


int DumpTool::Run(void) {
  if (opts.InputFilenames.empty()) {
    dumpInput(path_to_jv());
  } else {
    for (const std::string &filename : opts.InputFilenames)
      dumpInput(filename);
  }

  return 0;
}

void DumpTool::dumpInput(const std::string &Path) {
  try {
    jv_file_t jv_file(boost::interprocess::open_read_only, Path.c_str());
    std::pair<jv_t *, jv_file_t::size_type> search = jv_file.find<jv_t>("JV");

    if (search.second == 0) {
      llvm::errs() << "jv_t not found\n";
      return;
    }

    if (search.second > 1) {
      llvm::errs() << "multiple jv_t found\n";
      return;
    }

    assert(search.second == 1);

    jv_t &jv = *search.first;

    if (opts.ListBinaries) {
      for (const auto &binary : jv.Binaries) {
        if (IsVerbose())
          llvm::outs() << str_of_hash(binary.Hash) << ' ';

        llvm::outs() << binary.path_str() << '\n';
      }
    } else if (opts.Statistics) {
      for (const binary_t &binary : jv.Binaries) {
        llvm::outs() << llvm::formatv("Binary: {0}\n", binary.path_str());
        llvm::outs() << llvm::formatv(
            "  # of basic blocks: {0}\n",
            boost::num_vertices(binary.Analysis.ICFG));
        llvm::outs() << llvm::formatv("  # of functions: {0}\n",
                                      binary.Analysis.Functions.size());
      }
    } else if (!opts.ListFunctions.empty()) {
      for (unsigned BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
        const binary_t &binary = jv.Binaries[BIdx];

        if (binary.path_str().find(opts.ListFunctions) == std::string::npos)
          continue;

        const auto &ICFG = binary.Analysis.ICFG;

        for (unsigned FIdx = 0; FIdx < binary.Analysis.Functions.size();
             ++FIdx) {
          const function_t &function = binary.Analysis.Functions[FIdx];
          uintptr_t Addr =
              ICFG[basic_block_of_index(function.Entry, ICFG)].Addr;

          llvm::outs() << llvm::formatv("{0:x}\n", Addr);
        }
      }
    } else if (!opts.ListFunctionBBs.empty()) {
      llvm::ScopedPrinter Writer(llvm::outs());

      for (unsigned BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
        const binary_t &binary = jv.Binaries[BIdx];

        if (fs::path(binary.path_str()).filename().string() !=
            opts.ListFunctionBBs)
          continue;

        auto &ICFG = binary.Analysis.ICFG;

        for (const function_t &f : binary.Analysis.Functions) {
          basic_block_t entry = basic_block_of_index(f.Entry, ICFG);

          std::vector<basic_block_t> blocks;
          blocks.reserve(boost::num_vertices(ICFG));

          reached_visitor vis(blocks);
          boost::breadth_first_search(ICFG, entry, boost::visitor(vis));

          std::vector<uintptr_t> addrs;
          addrs.resize(blocks.size());

          std::transform(
              blocks.begin(), blocks.end(), addrs.begin(),
              [&](basic_block_t bb) -> uintptr_t { return ICFG[bb].Addr; });

          Writer.printHexList("Fn", addrs);
        }
      }
    } else {
      dumpDecompilation(jv);
    }

  } catch (const std::exception &e) {
    WithColor::error() << llvm::formatv("failed to dump {0}: {1}\n", Path,
                                        e.what());
  }
}
}
