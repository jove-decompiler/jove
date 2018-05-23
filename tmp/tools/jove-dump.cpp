#include "tcgcommon.hpp"

#include <memory>
#include <fstream>
#include <sstream>
#include <numeric>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/Support/FileSystem.h>

#include "jove/jove.h"
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/graph/adj_list_serialize.hpp>

namespace fs = boost::filesystem;
namespace po = boost::program_options;
namespace obj = llvm::object;

namespace jove {

static struct {
  fs::path input;

  struct {
    bool fns;
  } dump;
} cmdline;

static int parse_command_line_arguments(int argc, char **argv);
static int dump(void);

}

int main(int argc, char **argv) {
  llvm::StringRef ToolName = argv[0];
  llvm::sys::PrintStackTraceOnErrorSignal(ToolName);
  llvm::PrettyStackTraceProgram X(argc, argv);
  llvm::llvm_shutdown_obj Y;

  return jove::parse_command_line_arguments(argc, argv) ||
         jove::dump();
}

namespace jove {

int dump(void) {
  decompilation_t decompilation;
  {
    std::ifstream ifs(cmdline.input.string());

    boost::archive::text_iarchive ia(ifs);
    ia >> decompilation;
  }

  for (binary_t &binary : decompilation.Binaries) {
    printf("%s\n", binary.Path.c_str());

    printf("  %lu Functions.\n", binary.Analysis.Functions.size());
    printf("  %lu Basic Blocks.\n", boost::num_vertices(binary.Analysis.ICFG));
    printf("  %lu Branches.\n", boost::num_edges(binary.Analysis.ICFG));
  }

  return 0;
}

int parse_command_line_arguments(int argc, char **argv) {
  fs::path &ifp = cmdline.input;
  bool &fns = cmdline.dump.fns;

  try {
    po::options_description desc("Allowed options");
    desc.add_options()
      ("help,h", "produce help message")

      ("input,i", po::value<fs::path>(&ifp),
       "input decompilation")

      ("functions,f", po::value<bool>(&fns)->default_value(false),
       "print information related to functions");

    po::positional_options_description p;
    p.add("input", -1);

    po::variables_map vm;
    po::store(
        po::command_line_parser(argc, argv).options(desc).positional(p).run(),
        vm);
    po::notify(vm);

    if (vm.count("help") || !vm.count("input")) {
      printf("Usage: %s [-f] decompilation.jv\n", argv[0]);
      std::string desc_s;
      {
        std::ostringstream oss(desc_s);
        oss << desc;
      }

      puts(desc_s.c_str());
      return 1;
    }

    if (!fs::exists(ifp)) {
      fprintf(stderr, "given input %s does not exist\n", ifp.string().c_str());
      return 1;
    }
  } catch (std::exception &e) {
    fprintf(stderr, "%s\n", e.what());
    return 1;
  }

  return 0;
}

}
