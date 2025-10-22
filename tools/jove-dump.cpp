#include "tool.h"
#include "hash.h"
#include "tcg.h"

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

class DumpTool : public JVTool<ToolKind::CopyOnWrite> {
  struct Cmdline {
    cl::opt<std::string> Output;
    cl::alias OutputAlias;
    cl::opt<bool> Compact;
    cl::opt<bool> Graphviz;
    cl::opt<bool> Statistics;
    cl::opt<bool> ListBinaries;
    cl::alias ListBinariesAlias;
    cl::opt<std::string> ListFunctions;
    cl::alias ListFunctionsAlias;
    cl::opt<std::string> ListFunctionBBs;
    cl::opt<bool> TCGGlobalNames;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Output("output", cl::desc("Destination for output"),
                 cl::value_desc("filename"), cl::cat(JoveCategory)),

          OutputAlias("o", cl::desc("Alias for -output."), cl::aliasopt(Output),
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
              cl::cat(JoveCategory)),

          TCGGlobalNames("tcg-names",
                         cl::desc("Translate TCG global set bits into names"),
                         cl::init(true), cl::cat(JoveCategory))
          {}
  } opts;

  std::unique_ptr<tiny_code_generator_t> TCG;

public:
  DumpTool() : opts(JoveCategory) {}

  int Run(void) override;

  void dumpDecompilation(const jv_t &);
  void dumpInput(const std::string &Path);
};

JOVE_REGISTER_TOOL("dump", DumpTool);

typedef boost::format fmt;

void DumpTool::dumpDecompilation(const jv_t &jv) {
  if (opts.TCGGlobalNames)
    TCG = std::make_unique<tiny_code_generator_t>();

  std::unique_ptr<llvm::raw_fd_ostream> ostream;
  if (!opts.Output.empty()) {
    std::error_code EC;
    ostream = std::make_unique<llvm::raw_fd_ostream>(opts.Output.c_str(), EC);
  }

  llvm::ScopedPrinter Writer(ostream ? *ostream : llvm::outs());
  llvm::ListScope _(Writer, (fmt("Binaries (%u)") % jv.Binaries.size()).str());

  for (const auto &B : jv.Binaries) {
    llvm::DictScope __(Writer, B.Name.c_str());

    Writer.printBoolean("IsDynamicLinker",     B.IsDynamicLinker);
    Writer.printBoolean("IsExecutable",        B.IsExecutable);
    Writer.printBoolean("IsVDSO",              B.IsVDSO);
    Writer.printBoolean("IsPIC",               B.IsPIC);
    Writer.printBoolean("IsDynamicallyLoaded", B.IsDynamicallyLoaded);

    const auto &ICFG = B.Analysis.ICFG;

    if (is_function_index_valid(B.Analysis.EntryFunction)) {
      const function_t &f = B.Analysis.Functions.at(B.Analysis.EntryFunction);
      Writer.printString("Entry", (fmt("0x%lX") % entry_address_of_function(f, B)).str());
    } else {
      Writer.printString("Entry", "<invalid>");
    }

    {
      llvm::ListScope ___(
          Writer, (fmt("Basic Blocks (%u)") % ICFG.num_vertices()).str());

      for (bb_t bb : boost::make_iterator_range(ICFG.vertices())) {
        llvm::DictScope ____(Writer, (fmt("0x%lX") % ICFG[bb].Addr).str());

        if (ICFG[bb].Speculative)
          Writer.printBoolean("Speculative", ICFG[bb].Speculative);

#if 0
        {
          auto inv_adj_it_pair = ICFG.inv_adjacent_vertices(bb);

          std::vector<taddr_t> preds;
          preds.resize(
              std::distance(inv_adj_it_pair.first, inv_adj_it_pair.second));

          std::transform(inv_adj_it_pair.first, inv_adj_it_pair.second,
                         preds.begin(), [&](bb_t target) -> taddr_t {
                           return ICFG[target].Addr;
                         });

          Writer.printHexList("Predecessors", preds);
        }

        Writer.getOStream() << '\n';
#endif

        //Writer.printHex("Address", ICFG[bb].Addr);
        Writer.printNumber("Size", ICFG[bb].Size);

        {
          llvm::DictScope _____(Writer, (fmt("Term @ 0x%lX") % ICFG[bb].Term.Addr).str());

          //Writer.printHex("Address", ICFG[bb].Term.Addr);
          Writer.printString("Type", description_of_terminator(ICFG[bb].Term.Type));

          if (ICFG[bb].Term.Type == TERMINATOR::CALL) {
            //Writer.printBoolean("Returns", ICFG[bb].Term._call.Returns);
            function_index_t CalleeIdx = ICFG[bb].Term._call.Target;

            if (is_function_index_valid(CalleeIdx)) {
              const function_t &f = B.Analysis.Functions.at(CalleeIdx);
              Writer.printString("Target", (fmt("0x%lX") % entry_address_of_function(f, B)).str());
            } else {
              Writer.printString("Target", "<invalid>");
            }
          }

#if defined(TARGET_X86_64) || defined(TARGET_I386)
          if (ICFG[bb].Term.Type == TERMINATOR::CONDITIONAL_JUMP)
            Writer.printBoolean("String", ICFG[bb].Term._conditional_jump.String);
#endif

          if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP)
            Writer.printBoolean("IsLj", ICFG[bb].Term._indirect_jump.IsLj);

#if 0
          if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL)
            Writer.printBoolean("Returns", ICFG[bb].Term._indirect_call.Returns);
#endif

          if (ICFG[bb].Term.Type == TERMINATOR::RETURN)
            Writer.printBoolean("Returns", ICFG[bb].Term._return.Returns);
        }

        if (ICFG[bb].Sj)
          Writer.printBoolean("Sj", true);

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
              if (opts.TCGGlobalNames) {
                std::vector<unsigned> glbv;
                explode_tcg_global_set(glbv, ICFG[bb].Analysis.live.def);

                std::vector<std::string> descv;
                descv.resize(glbv.size());

                std::transform(glbv.begin(), glbv.end(), descv.begin(),
                               [&](unsigned glb) -> std::string {
                                 return TCG->tcg_name_of_global(glb);
                               });

                Writer.printList("def", descv);
              } else {
                Writer.printString("def", ICFG[bb].Analysis.live.def.to_string());
              }
            }

            {
              if (opts.TCGGlobalNames) {
                std::vector<unsigned> glbv;
                explode_tcg_global_set(glbv, ICFG[bb].Analysis.live.use);

                std::vector<std::string> descv;
                descv.resize(glbv.size());

                std::transform(glbv.begin(), glbv.end(), descv.begin(),
                               [&](unsigned glb) -> std::string {
                                 return TCG->tcg_name_of_global(glb);
                               });

                Writer.printList("use", descv);
              } else {
                Writer.printString("use", ICFG[bb].Analysis.live.use.to_string());
              }
            }
          }

          {
            llvm::DictScope ______(Writer, "reach");

            {
              if (opts.TCGGlobalNames) {
                std::vector<unsigned> glbv;
                explode_tcg_global_set(glbv, ICFG[bb].Analysis.reach.def);

                std::vector<std::string> descv;
                descv.resize(glbv.size());

                std::transform(glbv.begin(), glbv.end(), descv.begin(),
                               [&](unsigned glb) -> std::string {
                                 return TCG->tcg_name_of_global(glb);
                               });

                Writer.printList("def", descv);
              } else {
                Writer.printString("def", ICFG[bb].Analysis.reach.def.to_string());
              }
            }
          }

          Writer.printBoolean("Stale", ICFG[bb].Analysis.Stale.test(boost::memory_order_relaxed));
        }

        Writer.getOStream() << '\n';

        if (auto MaybeDynTargets = ICFG[bb].getDynamicTargets(jv)) {
          auto &DynTargets = *MaybeDynTargets;

          std::vector<std::string> descv;
          descv.reserve(DynTargets.size());

          DynTargets.ForEach([&](const dynamic_target_t &pair) {
            binary_index_t BIdx;
            function_index_t FIdx;
            std::tie(BIdx, FIdx) = pair;

            const auto &b = jv.Binaries.at(BIdx);
            const auto &_ICFG = b.Analysis.ICFG;
            const function_t &callee = b.Analysis.Functions.at(FIdx);
            uint64_t target_addr = entry_address_of_function(callee, b);

            descv.push_back(
                (fmt("0x%lX @ %s") % target_addr % b.Name.c_str()).str());
          });

          Writer.printList("DynTargets", descv);
        }

        {
          auto adj_it_pair = ICFG.adjacent_vertices(bb);

          std::vector<taddr_t> succs;
          succs.resize(std::distance(adj_it_pair.first, adj_it_pair.second));

          std::transform(adj_it_pair.first, adj_it_pair.second, succs.begin(),
                         [&](bb_t target) -> taddr_t {
                           return ICFG[target].Addr;
                         });

          Writer.printHexList("Successors", succs);
        }

        const ip_func_index_vec &_Parents = ICFG[bb].Parents.get<IsToolMT>();
        if (!_Parents.empty())
        {
          std::vector<taddr_t> avec;
          avec.resize(_Parents.size());

          std::transform(_Parents.cbegin(),
                         _Parents.cend(),
                         avec.begin(),
                         [&](function_index_t FIdx) -> taddr_t {
                           basic_block_index_t EntryIdx = B.Analysis.Functions.at(FIdx).Entry;
                           bb_t Entry = basic_block_of_index(EntryIdx, ICFG);
                           return ICFG[Entry].Addr;
                         });

          Writer.printHexList("Parents", avec);
        }
      }
    }

    {
      llvm::ListScope ___(Writer, (fmt("Functions (%u)") % B.Analysis.Functions.size()).str());

      for (const function_t &f : B.Analysis.Functions) {
        if (!is_binary_index_valid(f.BIdx) || !is_basic_block_index_valid(f.Entry)) {
          llvm::errs() << llvm::formatv(
              "invalid function with index {0}, skipping\n", f.Idx);
          continue;
        }

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
            if (opts.TCGGlobalNames) {
              std::vector<unsigned> glbv;
              explode_tcg_global_set(glbv, f.Analysis.args);

              std::vector<std::string> descv;
              descv.resize(glbv.size());

              std::transform(glbv.begin(), glbv.end(), descv.begin(),
                             [&](unsigned glb) -> std::string {
                               return TCG->tcg_name_of_global(glb);
                             });

              Writer.printList("Args", descv);
            } else {
              Writer.printString("Args", f.Analysis.args.to_string());
            }
          }

          {
            if (opts.TCGGlobalNames) {
              std::vector<unsigned> glbv;
              explode_tcg_global_set(glbv, f.Analysis.rets);

              std::vector<std::string> descv;
              descv.resize(glbv.size());

              std::transform(glbv.begin(), glbv.end(), descv.begin(),
                             [&](unsigned glb) -> std::string {
                               return TCG->tcg_name_of_global(glb);
                             });

              Writer.printList("Rets", descv);
            } else {
              Writer.printString("Rets", f.Analysis.rets.to_string());
            }
          }

          Writer.printBoolean("IsLeaf", f.Analysis.IsLeaf);
          if (f.Analysis.IsSj)
            Writer.printBoolean("IsSj", f.Analysis.IsSj);
          if (f.Analysis.IsLj)
            Writer.printBoolean("IsLj", f.Analysis.IsLj);

          Writer.printBoolean("Stale", f.Analysis.Stale.test(boost::memory_order_relaxed));
        }

        Writer.printBoolean("IsABI", f.IsABI);
        Writer.printBoolean("IsSignalHandler", f.IsSignalHandler);
        Writer.printBoolean("Returns", f.Returns);

        if (f.Analysis.hasCaller()) {
          std::vector<std::string> descv;
          descv.reserve(f.Analysis.numCallers(jv));

          f.Analysis.ForEachCaller(jv, [&](const caller_t &x) {
            std::string desc;

            binary_index_t BIdx;
            taddr_t TermAddr;
            std::tie(BIdx, TermAddr) = x;
            if (!is_binary_index_valid(BIdx))
              BIdx = index_of_binary(B, jv);

            const auto &b = jv.Binaries.at(BIdx);

            desc = (fmt("%s:0x%lX") % b.Name.c_str() % TermAddr).str();

            descv.push_back(std::move(desc));
          });

          Writer.printList("Callers", descv);
        }
      }
    }
  }
}


int DumpTool::Run(void) {
    if (opts.ListBinaries) {
      for (const auto &binary : jv.Binaries) {
        if (IsVerbose())
          llvm::outs() << str_of_hash(binary.Hash) << ' ';

        llvm::outs() << binary.Name.c_str() << '\n';
      }
    } else if (opts.Statistics) {
      for (const auto &binary : jv.Binaries) {
        llvm::outs() << llvm::formatv("Binary: {0}\n", binary.Name.c_str());
        llvm::outs() << llvm::formatv("  # of basic blocks: {0}\n",
                                      binary.Analysis.ICFG.num_vertices());
        llvm::outs() << llvm::formatv("  # of functions: {0}\n",
                                      binary.Analysis.Functions.size());
      }
    } else if (!opts.ListFunctions.empty()) {
      for (unsigned BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
        const auto &binary = jv.Binaries.at(BIdx);

        if (binary.name_str().find(opts.ListFunctions) == std::string::npos)
          continue;

        const auto &ICFG = binary.Analysis.ICFG;

        for (unsigned FIdx = 0; FIdx < binary.Analysis.Functions.size();
             ++FIdx) {
          const function_t &function = binary.Analysis.Functions.at(FIdx);
          taddr_t Addr =
              ICFG[basic_block_of_index(function.Entry, ICFG)].Addr;

          llvm::outs() << llvm::formatv("{0:x}\n", Addr);
        }
      }
    } else if (!opts.ListFunctionBBs.empty()) {
      llvm::ScopedPrinter Writer(llvm::outs());

      for (unsigned BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
        const auto &binary = jv.Binaries.at(BIdx);

        if (!binary.is_file())
          continue;

        if (fs::path(binary.Name.c_str()).filename().string() !=
            opts.ListFunctionBBs)
          continue;

        auto &ICFG = binary.Analysis.ICFG;

        for (const function_t &f : binary.Analysis.Functions) {
          std::vector<bb_t> bbvec;
          basic_blocks_of_function(f, binary, bbvec);

          std::vector<taddr_t> addrs;

          addrs.resize(bbvec.size());
          std::transform(
              bbvec.begin(),
              bbvec.end(), addrs.begin(),
              [&](bb_t bb) -> taddr_t { return ICFG[bb].Addr; });

          Writer.printHexList("Fn", addrs);
        }
      }
    } else {
      dumpDecompilation(jv);
    }

  return 0;
}

}
