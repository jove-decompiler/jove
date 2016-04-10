#include "translator.h"
#include <llvm/MC/MCInstrAnalysis.h>
#include <llvm/ADT/Triple.h>
#include <llvm/Object/Binary.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <boost/icl/interval_map.hpp>
#include <boost/program_options.hpp>
#include <boost/filesystem/path.hpp>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>
#include <tuple>

using namespace std;
using namespace llvm;
using namespace object;
namespace po = boost::program_options;
namespace fs = boost::filesystem;

namespace jove {
static tuple<fs::path, fs::path, bool>
parse_command_line_arguments(int argc, char **argv);
static OwningBinary<Binary>&& parse_binary(const fs::path&);
}

int main(int argc, char **argv) {
  fs::path ifp, ofp;
  bool static_mode;

  tie(ifp, ofp, static_mode) = jove::parse_command_line_arguments(argc, argv);

  //
  // parse binary
  //
  OwningBinary<Binary> B(jove::parse_binary(ifp));
  ObjectFile *O = cast<ObjectFile>(B.getBinary());

  //
  // create bitcode
  //
  unique_ptr<LLVMContext> C(make_unique<LLVMContext>());
  unique_ptr<Module> M = make_unique<Module>(ifp.stem().string(), *C);

  //
  // initialize translator
  //
  jove::translator T(*O, *C, *M);

  //
  // translate every exported function
  //

  return 0;
}

namespace jove {

tuple<fs::path, fs::path, bool> parse_command_line_arguments(int argc, char **argv) {
  string ifp, ofp;
  bool static_mode, dynamic_mode;

  try {
    po::options_description desc("Allowed options");
    desc.add_options()
      ("help,h", "produce help message")

      ("input,i", po::value<string>(&ifp), "input binary")

      ("output,o", po::value<string>(&ofp), "output bitcode file path")

      ("static,s", po::value<bool>(&static_mode),
      "produce bitcode for static analysis")

      ("dynamic,d", po::value<bool>(&dynamic_mode),
      "produce bitcode for dynamic analysis");

    po::positional_options_description p;
    p.add("input", -1);

    po::variables_map vm;
    po::store(
        po::command_line_parser(argc, argv).options(desc).positional(p).run(),
        vm);
    po::notify(vm);

    if (vm.count("help") || !vm.count("input") || !vm.count("output") ||
        static_mode == dynamic_mode) {
      cout << "Usage: jove-init-<arch> [--static] [--dynamic] [-o] binary\n";
      cout << desc;
      exit(1);
    }
  } catch (exception &e) {
    cerr << e.what() << endl;
    exit(1);
  }

  return make_tuple(ifp, ofp, static_mode);
}

static void verify_arch(const ObjectFile *);
static void print_obj_info(const ObjectFile *);

static OwningBinary<Binary>&& parse_binary(const fs::path& fp) {
  ErrorOr<OwningBinary<Binary>> BinaryOrErr = createBinary(fp.string());
  if (error_code EC = BinaryOrErr.getError()) {
    cerr << "error: " << EC.message() << endl;
    exit(1);
  }

  ObjectFile* O = dyn_cast<ObjectFile>(BinaryOrErr.get().getBinary());
  if (!O) {
    cerr << "error: provided file is not object" << endl;
    exit(1);
  }

  verify_arch(O);

#ifdef JOVEDBG
  print_obj_info(O);
#endif

  return move(BinaryOrErr.get());
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

void print_obj_info(const ObjectFile *Obj) {
  cout << "File: " << Obj->getFileName().str() << "\n";
  cout << "Format: " << Obj->getFileFormatName().str() << "\n";
  cout << "Arch: " << Triple::getArchTypeName((Triple::ArchType)Obj->getArch())
       << "\n";
  cout << "AddressSize: " << (8 * Obj->getBytesInAddress()) << "bit\n";
}
}
