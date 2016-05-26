#include "binary.h"
#include "translator.h"
#include <config-target.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/MC/MCInstrAnalysis.h>
#include <llvm/ADT/Triple.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Bitcode/ReaderWriter.h>
#include <boost/icl/interval_map.hpp>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>
#include <tuple>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Object/Binary.h>

#define JOVEDBG

using namespace std;
using namespace llvm;
using namespace object;
namespace po = boost::program_options;
namespace fs = boost::filesystem;

namespace jove {
static tuple<fs::path, fs::path, bool>
parse_command_line_arguments(int argc, char **argv);

static void verify_arch(const ObjectFile *);
static void print_obj_info(const ObjectFile *);

}

using namespace jove;

int main(int argc, char **argv) {
  fs::path ifp, ofp;
  bool noopt;

  tie(ifp, ofp, noopt) = parse_command_line_arguments(argc, argv);

#if 0
  StringMap<cl::Option *> &optMap(cl::getRegisteredOptions());

  {
    auto optIt = optMap.find("print-after-all");
    if (optIt != optMap.end())
      ((cl::opt<bool> *)(*optIt).second)->setValue(true);
  }
#endif

  //
  // parse binary
  //
  ErrorOr<OwningBinary<Binary>> BinaryOrErr = createBinary(ifp.string());
  if (error_code EC = BinaryOrErr.getError()) {
    cerr << "error loading binary: " << EC.message() << endl;
    return 1;
  }

  ObjectFile* O = dyn_cast<ObjectFile>(BinaryOrErr.get().getBinary());
  if (!O) {
    cerr << "error: provided file is not object" << endl;
    return 1;
  }

  verify_arch(O);

#ifdef JOVEDBG
  print_obj_info(O);
#endif

  //
  // initialize translator
  //
  translator T(*O, ifp.stem().string(), noopt);

  //
  // run translator
  //
  T.run();

  if (verifyModule(T.module(), &errs())) {
    errs().flush();
    abort();
  }

  fs::create_directory(ofp);
  fs::create_directory(ofp / "analysis");
  fs::create_directory(ofp / "binary");
  fs::create_directory(ofp / "bitcode");

  fs::copy_file(ifp, ofp / "binary" / ifp.filename());

  error_code ec;
  raw_fd_ostream of((ofp / "bitcode" / "decompilation").string(), ec, sys::fs::F_RW);
  WriteBitcodeToFile(&T.module(), of);

  return 0;
}

namespace jove {

tuple<fs::path, fs::path, bool> parse_command_line_arguments(int argc,
                                                             char **argv) {
  fs::path ifp, ofp;
  bool noopt = false;

  try {
    po::options_description desc("Allowed options");
    desc.add_options()
      ("help,h", "produce help message")

      ("input,i", po::value<fs::path>(&ifp), "input binary")

      ("output,o", po::value<fs::path>(&ofp), "output bitcode file path")

      ("noopt,s", po::value<bool>(&noopt),
      "produce unoptimized LLVM");

    po::positional_options_description p;
    p.add("input", -1);

    po::variables_map vm;
    po::store(
        po::command_line_parser(argc, argv).options(desc).positional(p).run(),
        vm);
    po::notify(vm);

    if (vm.count("help") || !vm.count("input")) {
      cout << "Usage: jove-init-<arch> [-o output] binary\n";
      cout << desc;
      exit(1);
    }

    if (!fs::exists(ifp)) {
      cerr << "given input does not exist " << ifp << endl;
      exit(1);
    }

    if (!vm.count("output")) {
      ofp = ifp;
      ofp.replace_extension("jv");
      ofp = ofp.filename();
    }
  } catch (exception &e) {
    cerr << e.what() << endl;
    abort();
  }

  return make_tuple(ifp, ofp, noopt);
}

void verify_arch(const ObjectFile *Obj) {
  Triple::ArchType archty;

#if defined(TARGET_AARCH64)
  archty = Triple::ArchType::aarch64;
#elif defined(TARGET_ARM)
  archty = Triple::ArchType::arm;
#elif defined(TARGET_X86_64)
  archty = Triple::ArchType::x86_64;
#elif defined(TARGET_I386)
  archty = Triple::ArchType::x86;
#elif defined(TARGET_MIPS)
  archty = Triple::ArchType::mipsel;
#endif

  if (Obj->getArch() != archty) {
    cerr << "error: architecture mismatch (run trans-obj-<arch>)" << endl;
    exit(1);
  }
}

#ifdef JOVEDBG
void print_obj_info(const ObjectFile *Obj) {
  cout << "File: " << Obj->getFileName().str() << "\n";
  cout << "Format: " << Obj->getFileFormatName().str() << "\n";
  cout << "Arch: " << Triple::getArchTypeName((Triple::ArchType)Obj->getArch())
       << "\n";
  cout << "AddressSize: " << (8 * Obj->getBytesInAddress()) << "bit\n";
}
#endif

}
