#include "tool.h"
#include "elf.h"
#include "ida.h"
#include "explore.h"
#include "symbolizer.h"

#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/DataTypes.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/ScopedPrinter.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/WithColor.h>

#include <algorithm>
#include <boost/dll/runtime_symbol_info.hpp>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <fstream>

#include "jove_macros.h"

namespace obj = llvm::object;
namespace fs = boost::filesystem;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

class IDATool : public Tool {
  struct Cmdline {
    cl::opt<std::string> jv;
    cl::opt<std::string> Binary;
    cl::alias BinaryAlias;
    cl::opt<bool> Verbose;
    cl::alias VerboseAlias;
    cl::opt<bool> ImportFunctions;
    cl::opt<bool> ImportBlocks;
    cl::opt<bool> ImportLocalGotos;
    cl::opt<bool> NoSave;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : jv(cl::Positional, cl::desc("<input jove decompilations>"),
             cl::Required, cl::cat(JoveCategory)),

          Binary("binary", cl::desc("Operate on single given binary"),
                 cl::value_desc("path"), cl::cat(JoveCategory)),

          BinaryAlias("b", cl::desc("Alias for -binary."), cl::aliasopt(Binary),
                      cl::cat(JoveCategory)),

          Verbose("verbose",
                  cl::desc("Print extra information for debugging purposes"),
                  cl::cat(JoveCategory)),

          VerboseAlias("v", cl::desc("Alias for -verbose."),
                       cl::aliasopt(Verbose), cl::cat(JoveCategory)),

          ImportFunctions("import-functions", cl::desc("Import functions"),
                          cl::cat(JoveCategory)),

          ImportBlocks("import-blocks", cl::desc("Import basic blocks"),
                       cl::cat(JoveCategory)),

          ImportLocalGotos("import-local-gotos",
                           cl::desc("Import control flow from indirect jumps"),
                           cl::cat(JoveCategory)),

          NoSave("no-save",
                 cl::desc("Do not save decompilation before exiting"),
                 cl::cat(JoveCategory)) {}
  } opts;

  llvm::Triple TheTriple;
  llvm::SubtargetFeatures Features;

  const llvm::Target *TheTarget = nullptr;
  std::unique_ptr<const llvm::MCRegisterInfo> MRI;
  std::unique_ptr<const llvm::MCAsmInfo> AsmInfo;
  std::unique_ptr<const llvm::MCSubtargetInfo> STI;
  std::unique_ptr<const llvm::MCInstrInfo> MII;
  std::unique_ptr<llvm::MCContext> MCCtx;
  std::unique_ptr<llvm::MCDisassembler> DisAsm;
  std::unique_ptr<llvm::MCInstPrinter> IP;

  binary_index_t SingleBinaryIndex = invalid_binary_index;

  fs::path tmp_dir;

  std::string ida_dir;
  std::string ida_scripts_dir;

  decompilation_t decompilation;

public:
  IDATool() : opts(JoveCategory) {}

  int Run(void);
};

JOVE_REGISTER_TOOL("ida", IDATool);

typedef boost::format fmt;

int IDATool::Run(void) {
  if (char *env = getenv("JOVE_IDA_INSTALL_DIR")) {
    fs::path p(env);

    if (!fs::exists(p) || !fs::is_directory(p)) {
      WithColor::error() << llvm::formatv(
          "$JOVE_IDA_INSTALL_DIR ({0}) does not refer to a directory.\n", env);
      return 1;
    }

    if (!fs::exists(p / "idat") || !fs::exists(p / "idat64")) {
      WithColor::error() << llvm::formatv(
          "$JOVE_IDA_INSTALL_DIR ({0}) does not contain IDA executables.\n", env);
      return 1;
    }

    ida_dir = p.string();
  } else {
    WithColor::error() << "Specify location of IDA install with the JOVE_IDA_INSTALL_DIR environment variable\n";
    return 1;
  }

  ida_scripts_dir = (boost::dll::program_location().parent_path().parent_path().parent_path() /
               "scripts" / "ida" / "_")
                  .string();
  if (!fs::exists(ida_scripts_dir) || !fs::is_directory(ida_scripts_dir)) {
    WithColor::error() << "could not ida scripts directory at "
                       << ida_scripts_dir << '\n';
    return 1;
  }

  ReadDecompilationFromFile(opts.jv, decompilation);

  //
  // operate on single binary? (cmdline)
  //
  if (!opts.Binary.empty()) {
    binary_index_t BinaryIndex = invalid_binary_index;

    for (binary_index_t BIdx = 0; BIdx < decompilation.Binaries.size(); ++BIdx) {
      const binary_t &binary = decompilation.Binaries[BIdx];
      if (binary.Path.find(opts.Binary) == std::string::npos)
        continue;

      BinaryIndex = BIdx;
      break;
    }

    if (!is_binary_index_valid(BinaryIndex)) {
      WithColor::error() << llvm::formatv("failed to find binary \"{0}\"\n",
                                          opts.Binary);
      return 1;
    }

    SingleBinaryIndex = BinaryIndex;
  }

  //
  // prepare to process the binaries by creating a unique temporary directory
  //
  {
    static char tmpdir[] = {'/', 't', 'm', 'p', '/', 'X',
                            'X', 'X', 'X', 'X', 'X', '\0'};

    if (!mkdtemp(tmpdir)) {
      int err = errno;
      WithColor::error() << "mkdtemp failed : " << strerror(err) << '\n';
      return 1;
    }

    tmp_dir = fs::path(tmpdir);

    HumanOut() << llvm::formatv("Temporary directory: {0}\n", tmp_dir.string());
  }
  assert(fs::exists(tmp_dir) && fs::is_directory(tmp_dir));

  //
  // run jove-extract
  //
  pid_t pid = fork();
  if (!pid) {
    IgnoreCtrlC();

    std::vector<const char *> arg_vec = {
      "-d", opts.jv.c_str(),

      tmp_dir.c_str()
    };

    if (opts.Verbose)
      print_tool_command("extract", arg_vec);

    exec_tool("extract", arg_vec);

    int err = errno;
    HumanOut() << llvm::formatv("execve failed: {0}\n", strerror(err));
    exit(1);
  }

  if (int ret = WaitForProcessToExit(pid)) {
    WithColor::error() << "jove-extract failed to run\n";
    return 1;
  }

  {
    binary_t &binary = decompilation.Binaries.at(0);

    llvm::StringRef Buffer(reinterpret_cast<char *>(&binary.Data[0]),
                           binary.Data.size());
    llvm::StringRef Identifier(binary.Path);

    llvm::Expected<std::unique_ptr<obj::Binary>> BinOrErr =
        obj::createBinary(llvm::MemoryBufferRef(Buffer, Identifier));
    if (!BinOrErr) {
      HumanOut() << llvm::formatv("failed to create binary from {0}\n", binary.Path);
      return 1;
    }

    std::unique_ptr<obj::Binary> &BinRef = BinOrErr.get();

    assert(llvm::isa<ELFO>(BinRef.get()));
    ELFO &O = *llvm::cast<ELFO>(BinRef.get());

    TheTriple = O.makeTriple();
    Features = O.getFeatures();
  }

  // Initialize targets and assembly printers/parsers.
  llvm::InitializeAllTargets();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllAsmPrinters();
  llvm::InitializeAllAsmParsers();
  llvm::InitializeAllDisassemblers();

  //
  // initialize the LLVM objects necessary for disassembling instructions
  //
  std::string ArchName;
  std::string Error;

  this->TheTarget =
      llvm::TargetRegistry::lookupTarget(ArchName, TheTriple, Error);
  if (!TheTarget) {
    HumanOut() << "failed to lookup target: " << Error << '\n';
    return 1;
  }

  std::string TripleName = TheTriple.getTriple();
  std::string MCPU;

  MRI.reset(TheTarget->createMCRegInfo(TripleName));
  if (!MRI) {
    HumanOut() << "no register info for target\n";
    return 1;
  }

  llvm::MCTargetOptions Options;
  AsmInfo.reset(TheTarget->createMCAsmInfo(*MRI, TripleName, Options));
  if (!AsmInfo) {
    HumanOut() << "no assembly info\n";
    return 1;
  }

  STI.reset(TheTarget->createMCSubtargetInfo(TripleName, MCPU, Features.getString()));
  if (!STI) {
    HumanOut() << "no subtarget info\n";
    return 1;
  }

  MII.reset(TheTarget->createMCInstrInfo());
  if (!MII) {
    HumanOut() << "no instruction info\n";
    return 1;
  }

  llvm::MCObjectFileInfo MOFI;

  MCCtx = std::make_unique<llvm::MCContext>(AsmInfo.get(), MRI.get(), &MOFI);

  DisAsm.reset(TheTarget->createMCDisassembler(*STI, *MCCtx));
  if (!DisAsm) {
    HumanOut() << "no disassembler for target\n";
    return 1;
  }

  IP.reset(TheTarget->createMCInstPrinter(llvm::Triple(TripleName),
                                          AsmInfo->getAssemblerDialect(),
                                          *AsmInfo, *MII, *MRI));
  if (!IP) {
    HumanOut() << "no instruction printer\n";
    return 1;
  }

  tiny_code_generator_t tcg;
  disas_t dis(*DisAsm, std::cref(*STI), *IP);

  symbolizer_t symbolizer;

  auto process_binary = [&](binary_t &binary) -> void {
    llvm::StringRef Buffer(reinterpret_cast<char *>(&binary.Data[0]),
                           binary.Data.size());
    llvm::StringRef Identifier(binary.Path);

    llvm::Expected<std::unique_ptr<obj::Binary>> BinOrErr =
        obj::createBinary(llvm::MemoryBufferRef(Buffer, Identifier));

    if (!BinOrErr)
      return;

    binary_index_t BIdx = index_of_binary(binary, decompilation);

    fs::path chrooted_path = tmp_dir / binary.Path;
    std::string log_path = chrooted_path.string() + ".log.txt";

    fs::path flowgraphs_dir = tmp_dir / std::to_string(BIdx);
    fs::create_directories(flowgraphs_dir);


    //
    // hide split debug information from IDA Pro (XXX HACK)
    //
    std::unique_ptr<obj::Binary> &Bin = BinOrErr.get();

    if (!llvm::isa<ELFO>(Bin.get())) {
      HumanOut() << "is not ELF of expected type\n";
      return;
    }

    ELFO &O = *llvm::cast<ELFO>(Bin.get());
    const ELFF &E = *O.getELFFile();

    bool DidWeHideSplitDebugInfoFromIDA = false;

    fs::path splitDbgInfo;
    llvm::Optional<llvm::ArrayRef<uint8_t>> optionalBuildID = getBuildID(E);
    if (optionalBuildID) {
      llvm::ArrayRef<uint8_t> BuildID = *optionalBuildID;

      splitDbgInfo =
          fs::path("/usr/lib/debug") / ".build-id" /
          llvm::toHex(BuildID[0], /*LowerCase=*/true) /
          (llvm::toHex(BuildID.slice(1), /*LowerCase=*/true) + ".debug");

      if (fs::exists(splitDbgInfo)) {
        DidWeHideSplitDebugInfoFromIDA  = true;

        fs::path sav_path =
            tmp_dir / (splitDbgInfo.filename().string() + ".debug");

        if (opts.Verbose)
          WithColor::note() << llvm::formatv("XXX hiding split debug file {0}\n",
                                             sav_path.c_str());

        if (rename(splitDbgInfo.c_str(), sav_path.c_str()) < 0) {
          int err = errno;
          WithColor::warning() << llvm::formatv(
              "failed to hide split debug file: {0}\n", strerror(err));

          DidWeHideSplitDebugInfoFromIDA = false;
        }
      }
    }

    //
    // run IDA
    //
    pid = fork();
    if (!pid) {
      IgnoreCtrlC();

      std::string ida_path = ida_dir;

      if (ELFT::Is64Bits)
        ida_path.append("/idat64");
      else
        ida_path.append("/idat");

      std::vector<const char *> arg_vec = {
        ida_path.c_str(),

        "-c", "-A"
      };

      std::string script_path = ida_scripts_dir + "/export_flowgraphs.py";

      std::string script_arg("-S");
      script_arg.append(script_path);
      script_arg.push_back(' ');
      script_arg.append(log_path);
      script_arg.push_back(' ');
      script_arg.append(flowgraphs_dir.c_str());
      arg_vec.push_back(script_arg.c_str());

      arg_vec.push_back(chrooted_path.c_str());

      arg_vec.push_back(nullptr);

      if (opts.Verbose)
        print_command(&arg_vec[0]);

      execve(ida_path.c_str(), const_cast<char **>(&arg_vec[0]), ::environ);

      int err = errno;
      HumanOut() << llvm::formatv("execve failed: {0}\n", strerror(err));
      exit(1);
    }

    //
    // check exit code
    //
    int ret = WaitForProcessToExit(pid);

    if (DidWeHideSplitDebugInfoFromIDA) {
      if (opts.Verbose)
        WithColor::note() << llvm::formatv("XXX restoring split debug file {0}\n",
                                           splitDbgInfo.c_str());

      fs::path sav_path = tmp_dir / (splitDbgInfo.filename().string() + ".debug");
      if (rename(sav_path.c_str(), splitDbgInfo.c_str()) < 0) {
        int err = errno;
        HumanOut() << llvm::formatv("failed to restore split debug info file: {0}\n",
                                    strerror(err));
      }
    }

    if (opts.Verbose) {
      //
      // dump log contents
      //
      std::string log_contents;
      {
        std::ifstream ifs(log_path.c_str());
        if (ifs) {
          std::stringstream buffer;
          buffer << ifs.rdbuf();
          log_contents = buffer.str();
        }
      }
      llvm::errs() << log_contents;
    }

    if (ret) {
      WithColor::error() << "IDA failed\n";
      exit(1);
    }

    auto &ICFG = binary.Analysis.ICFG;

    fnmap_t fnmap;
    bbmap_t bbmap;

    construct_fnmap(decompilation, binary, fnmap);
    construct_bbmap(decompilation, binary, bbmap);

    auto process_flowgraph = [&](binary_t &binary,
                                 const ida_flowgraph_t &flowgraph) -> void {
      ida_flowgraph_node_t entry_node = boost::vertex(0, flowgraph);
      if (flowgraph[entry_node].HasUnknownAddress())
        return;

      uint64_t entry_addr = flowgraph[entry_node].start_ea;

      if (opts.Verbose)
        llvm::errs() << llvm::formatv("exploring function @ {0:x}\n", entry_addr);

      if (opts.ImportFunctions) {
        //
        // import functions
        //
        try {
          basic_block_index_t BBIdx = explore_basic_block(
              binary, *BinOrErr.get(), tcg, dis, entry_addr, fnmap, bbmap);

          if (!is_basic_block_index_valid(BBIdx))
            throw std::runtime_error(std::string());

          explore_function(binary, *BinOrErr.get(), tcg, dis, entry_addr, fnmap, bbmap);
        } catch (const std::exception &) {
          if (opts.Verbose)
            WithColor::warning() << llvm::formatv(
                "failed to explore function @ {0:x}\n", entry_addr);
          return;
        }
      }

      ida_flowgraph_t::vertex_iterator flowgraph_it, flowgraph_it_end;
      std::tie(flowgraph_it, flowgraph_it_end) = boost::vertices(flowgraph);

      if (!opts.ImportBlocks && !opts.ImportLocalGotos)
        return;

      //
      // import every basic block in flowgraph
      //
      std::for_each(flowgraph_it,
                    flowgraph_it_end, [&](ida_flowgraph_node_t node) {
        if (flowgraph[node].HasUnknownAddress()) {
          if (opts.Verbose)
            WithColor::warning()
                << llvm::formatv("unidentified node has label: \"{0}\"\n",
                                 flowgraph[node].label);

          return;
        }

        uint64_t node_addr = flowgraph[node].start_ea;
        try {
          basic_block_index_t BBIdx = explore_basic_block(
              binary, *BinOrErr.get(), tcg, dis, node_addr, fnmap, bbmap);

          if (!is_basic_block_index_valid(BBIdx))
            throw std::runtime_error(std::string());
        } catch (const std::exception &) {
          if (opts.Verbose)
            WithColor::warning() << llvm::formatv(
                "failed to explore block @ {0:x}\n", node_addr);
        }
      });

      if (!opts.ImportLocalGotos)
        return;

      //
      // examine indirect jumps
      //
      for_each_if(
          flowgraph_it, flowgraph_it_end,
          [&](ida_flowgraph_node_t node) -> bool {
            return boost::out_degree(node, flowgraph) > 0 &&
                   flowgraph[node].HasKnownAddress() &&
                   exists_indirect_jump_at_address(flowgraph[node].start_ea,
                                                   binary, bbmap);
          },
          [&](ida_flowgraph_node_t node) {
            uint64_t node_addr = flowgraph[node].start_ea;
            basic_block_t indjmp_bb =
                basic_block_at_address(node_addr, binary, bbmap);
            uint64_t indjmp_addr = ICFG[indjmp_bb].Term.Addr;

            assert(ICFG[indjmp_bb].Term.Type == TERMINATOR::INDIRECT_JUMP);

            //
            // collect, sort our targets
            //
            struct {
              std::vector<basic_block_t> succ_vec;
              std::vector<uint64_t> succ_addr_vec; /* sorted */
            } our;

            {
              auto &v = our.succ_vec;

              auto it_pair = boost::adjacent_vertices(indjmp_bb, ICFG);
              v.reserve(std::distance(it_pair.first, it_pair.second));
              std::copy(it_pair.first, it_pair.second, std::back_inserter(v));
            }

            {
              auto &v = our.succ_addr_vec;

              v.resize(our.succ_vec.size());
              std::transform(our.succ_vec.begin(),
                             our.succ_vec.end(),
                             v.begin(),
                             [&](basic_block_t succ) -> tcg_uintptr_t {
                               return ICFG[succ].Addr;
                             });

              std::sort(v.begin(), v.end());
            }

            //
            // collect, sort IDA targets
            //
            struct {
              std::vector<ida_flowgraph_node_t> succ_vec;
              std::vector<uint64_t> succ_addr_vec; /* sorted */

              std::vector<ida_flowgraph_node_t> valid_succ_vec;
              std::vector<uint64_t> valid_succ_addr_vec; /* sorted */
            } ida;

            {
              auto &v = ida.succ_vec;

              auto it_pair = boost::adjacent_vertices(node, flowgraph);
              v.reserve(std::distance(it_pair.first, it_pair.second));
              std::copy(it_pair.first, it_pair.second, std::back_inserter(v));
            }

            {
              auto &v = ida.succ_addr_vec;

              v.resize(ida.succ_vec.size());
              std::transform(ida.succ_vec.begin(),
                             ida.succ_vec.end(), v.begin(),
                             [&](ida_flowgraph_node_t succ) -> uint64_t {
                               return flowgraph[succ].start_ea;
                             });

              std::sort(v.begin(), v.end());
            }

            {
              auto &v = ida.valid_succ_vec;

              auto it_pair = boost::adjacent_vertices(node, flowgraph);
              v.reserve(std::distance(it_pair.first, it_pair.second));
              std::copy_if(it_pair.first, it_pair.second, std::back_inserter(v),
                           [&](ida_flowgraph_node_t node) -> bool {
                             return flowgraph[node].HasKnownAddress();
                           });
            }

            {
              auto &v = ida.valid_succ_addr_vec;

              v.resize(ida.valid_succ_vec.size());
              std::transform(ida.valid_succ_vec.begin(),
                             ida.valid_succ_vec.end(), v.begin(),
                             [&](ida_flowgraph_node_t succ) -> uint64_t {
                               return flowgraph[succ].start_ea;
                             });

              std::sort(v.begin(), v.end());
            }

            //
            // print message to user describing indirect jump targets that were
            // processed
            //
            {
              std::vector<uint64_t> v(our.succ_addr_vec.begin(),
                                      our.succ_addr_vec.end());
              std::copy_if(ida.succ_addr_vec.begin(),
                           ida.succ_addr_vec.end(), std::back_inserter(v),
                           [&](uint64_t ida_target) -> bool {
                             return !std::binary_search(
                                 our.succ_addr_vec.begin(),
                                 our.succ_addr_vec.end(), ida_target);
                           });
              std::sort(v.begin(), v.end());

              std::string msgPreamble =
                  symbolizer.addr2desc(binary, indjmp_addr) + " -> { ";
              llvm::errs() << msgPreamble;
              for (unsigned i = 0; i < v.size(); ++i) {
                uint64_t succ_addr = v[i];

                bool is_our =
                    std::binary_search(our.succ_addr_vec.begin(),
                                       our.succ_addr_vec.end(), succ_addr);

                bool is_ida =
                    std::binary_search(ida.succ_addr_vec.begin(),
                                       ida.succ_addr_vec.end(), succ_addr);
                assert(is_our || is_ida);

                const char *color_cstr;
                const char *color_end_cstr;
                if (is_our && is_ida) {
                  color_cstr = "";
                  color_end_cstr = "";
                } else {
                  color_cstr = is_our ? __ANSI_YELLOW : __ANSI_GREEN;
                  color_end_cstr = __ANSI_NORMAL_COLOR;
                }

                if (i > 0)
                  llvm::errs() << ",\n" << std::string(msgPreamble.size(), ' ');

                std::string desc = symbolizer.addr2desc(binary, succ_addr);
                if (desc == "??")
                  color_cstr = __ANSI_RED;

                llvm::errs()
                    << color_cstr
                    << desc
                    << color_end_cstr;
              }
              llvm::errs() << " }";

              if (opts.Verbose)
                llvm::errs() << " (function "
                             << symbolizer.addr2desc(binary, entry_addr) << ")";

              llvm::errs() << '\n';
            }

            //
            // add control flow edges to every basic_block corresponding to a
            // target of the indirect jump
            //
            {
              auto &v = ida.valid_succ_addr_vec;

              for_each_if(
                  v.begin(), v.end(),
                  [&](uint64_t start_ea) -> bool {
                    return exists_basic_block_at_address(start_ea, binary,
                                                         bbmap);
                  },
                  [&](uint64_t start_ea) {
                    basic_block_t succ_bb =
                        basic_block_at_address(start_ea, binary, bbmap);
                    boost::add_edge(indjmp_bb, succ_bb, ICFG);
                  });
            }
          });
      };

    //
    // round up the flow graph files
    //
    std::vector<fs::path> v;

    std::copy(fs::directory_iterator(flowgraphs_dir), fs::directory_iterator(),
              std::back_inserter(v));

    std::sort(v.begin(), v.end()); // sort, since directory iteration
                                   // is not ordered on some file systems

    for (auto it = v.begin(); it != v.end(); ++it) {
      ida_flowgraph_t flowgraph;

      std::string p = (*it).string();

      if (opts.Verbose)
        llvm::errs() << llvm::formatv("parsing {0}...\n", p);

      if (!ReadIDAFlowgraphFromGDLFile(p.c_str(), flowgraph)) {
        WithColor::error() << llvm::formatv("failed to parse {0}\n", p);
        continue;
      }

      process_flowgraph(binary, flowgraph);
    }
  };


  if (is_binary_index_valid(SingleBinaryIndex))
    process_binary(decompilation.Binaries.at(SingleBinaryIndex));
  else
    for_each_binary(decompilation, process_binary);

  if (opts.NoSave)
    return 0;

  WriteDecompilationToFile(opts.jv, decompilation);

  return 0;
}

}
