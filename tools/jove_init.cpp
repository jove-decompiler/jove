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
#include <boost/filesystem/path.hpp>
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

static ObjectFile *O;
static unique_ptr<translator> T;

static void createImportedFunctions();
static void createExportedFunctions();
static void createExportedVariables();
static void createThreadLocalVariables();
static void createSectionData();
}

using namespace jove;

int main(int argc, char **argv) {
  fs::path ifp, ofp;
  bool static_mode;

  tie(ifp, ofp, static_mode) = parse_command_line_arguments(argc, argv);

  //
  // parse binary
  //
  ErrorOr<OwningBinary<Binary>> BinaryOrErr = createBinary(ifp.string());
  if (error_code EC = BinaryOrErr.getError()) {
    cerr << "error: " << EC.message() << endl;
    exit(1);
  }

  O = dyn_cast<ObjectFile>(BinaryOrErr.get().getBinary());
  if (!O) {
    cerr << "error: provided file is not object" << endl;
    exit(1);
  }

  verify_arch(O);

#ifdef JOVEDBG
  print_obj_info(O);
#endif

  //
  // initialize translator
  //
  T.reset(new translator(*O, ifp.stem().string()));

  //
  // create declarations for imported functions
  //
  createImportedFunctions();

  //
  // create definitions for exported functions
  //
  createExportedFunctions();

  //
  // create definitions for exported global variables
  //
  createExportedVariables();

  //
  // create definitions for thread-local global variables
  //
  createThreadLocalVariables();

  //
  // create section data, taking into account relocations
  //
  createSectionData();

  if (verifyModule(T->module(), &errs())) {
    errs().flush();
    abort();
  }

  error_code ec;
  raw_fd_ostream of(ifp.stem().string() + ".bc", ec, sys::fs::F_RW);
  WriteBitcodeToFile(&T->module(), of);

  return 0;
}

namespace jove {

tuple<fs::path, fs::path, bool> parse_command_line_arguments(int argc, char **argv) {
  string ifp, ofp;
  bool static_mode = false, dynamic_mode = false;

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

void createImportedFunctions() {
  vector<symbol_t> syms;
  imported_functions_of_binary(*O, syms);
}

void createExportedFunctions() {
  vector<symbol_t> syms;
  exported_functions_of_binary(*O, syms);

  vector<address_t> addrs(syms.size());
  transform(syms.begin(), syms.end(), addrs.begin(),
            [](const symbol_t &s) { return s.addr; });

  T->translate(addrs);

  for (symbol_t s : syms) {
    Function* llf = T->function_of_addr(s.addr);

    if (!llf)
      continue;

    llf->setName(s.name);
  }
}

void createExportedVariables() {}
void createThreadLocalVariables() {}
void createSectionData() {}
}
