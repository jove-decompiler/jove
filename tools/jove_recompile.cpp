#include "config-target.h"
#include "recompiler.h"
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <cstdint>
#include <iostream>
#include <llvm/ADT/Triple.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Object/Binary.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/raw_ostream.h>

using namespace std;
using namespace llvm;
using namespace object;
namespace po = boost::program_options;
namespace fs = boost::filesystem;

namespace jove {

static tuple<fs::path, fs::path, bool>
parse_command_line_arguments(int argc, char **argv);

static void print_obj_info(const ObjectFile *);
}

using namespace jove;

int main(int argc, char **argv) {
  fs::path ifp, ofp;
  bool noopt;

  tie(ifp, ofp, noopt) = parse_command_line_arguments(argc, argv);

  //
  // parse binary
  //
  fs::path bin_fp = *fs::directory_iterator(ifp / "binary");
  Expected<OwningBinary<Binary>> BinaryOrErr = createBinary(bin_fp.string());
  if (!BinaryOrErr) {
    cerr << "error loading binary" << endl;
    return 1;
  }

  ObjectFile *O = dyn_cast<ObjectFile>(BinaryOrErr.get().getBinary());
  if (!O) {
    cerr << "error: provided file is not object" << endl;
    return 1;
  }

  print_obj_info(O);

  llvm::LLVMContext C;

  unique_ptr<Module> M;
  {
    ErrorOr<unique_ptr<MemoryBuffer>> MBOrEror(
        MemoryBuffer::getFile((ifp / "bitcode" / "decompilation").string()));

    if (std::error_code EC = MBOrEror.getError()) {
      cerr << "failed to read bitcode file " << EC.message() << endl;
      return 1;
    }
    M = move(*parseBitcodeFile(MBOrEror.get()->getMemBufferRef(), C));
  }

  unique_ptr<recompiler> R = create_recompiler(*O, *M);

  fs::path objfp = fs::unique_path();
  fs::path lnkfp = fs::unique_path();

  R->compile(objfp);
  R->link(objfp, lnkfp);

  M->dump();

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

      ("noopt,s", po::value<bool>(&noopt), "produce unoptimized LLVM");

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

    if (!fs::is_directory(ifp) &&
        !fs::is_directory(ifp.replace_extension("jv"))) {
      cerr << "given input " << ifp << " is not jove decompilation " << endl;
      exit(1);
    }
  } catch (exception &e) {
    cerr << e.what() << endl;
    abort();
  }

  return make_tuple(ifp, ofp, noopt);
}

void print_obj_info(const ObjectFile *Obj) {
  cout << "File: " << Obj->getFileName().str() << "\n";
  cout << "Format: " << Obj->getFileFormatName().str() << "\n";
  cout << "Arch: "
       << Triple::getArchTypeName((Triple::ArchType)Obj->getArch()).str()
       << "\n";
  cout << "AddressSize: " << (8 * Obj->getBytesInAddress()) << "bit\n";
}

}
