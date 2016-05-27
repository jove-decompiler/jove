#include "config-target.h"
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <cstdint>
#include <iostream>
#include <llvm/ADT/Triple.h>
#include <llvm/Bitcode/ReaderWriter.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Object/Binary.h>
#include <llvm/Object/ELF.h>
#include <llvm/Object/ELFObjectFile.h>
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
static void needed_shared_libraries_of_binary(const ObjectFile *,
                                              vector<fs::path> &);
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
  ErrorOr<OwningBinary<Binary>> BinaryOrErr = createBinary(bin_fp.string());
  if (error_code EC = BinaryOrErr.getError()) {
    cerr << "error loading binary: " << EC.message() << endl;
    return 1;
  }

  ObjectFile *O = dyn_cast<ObjectFile>(BinaryOrErr.get().getBinary());
  if (!O) {
    cerr << "error: provided file is not object" << endl;
    return 1;
  }

  print_obj_info(O);

  vector<fs::path> libs;
  needed_shared_libraries_of_binary(O, libs);

  for (fs::path lib : libs)
    cout << lib << endl;

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
  cout << "Arch: " << Triple::getArchTypeName((Triple::ArchType)Obj->getArch())
       << "\n";
  cout << "AddressSize: " << (8 * Obj->getBytesInAddress()) << "bit\n";
}

static void needed_shared_libraries_of_elf_binary(const ObjectFile *,
                                                  vector<fs::path> &);
static void needed_shared_libraries_of_coff_binary(const ObjectFile *,
                                                   vector<fs::path> &);

void needed_shared_libraries_of_binary(const ObjectFile *O,
                                       vector<fs::path> &libs) {
  if (O->isELF())
    return needed_shared_libraries_of_elf_binary(O, libs);
  else if (O->isCOFF())
    return needed_shared_libraries_of_coff_binary(O, libs);
}

template <class T> static T errorOrDefault(ErrorOr<T> Val, T Default = T()) {
  return Val ? *Val : Default;
}

template <class ELFT>
static bool compareAddr(uint64_t VAddr, const Elf_Phdr_Impl<ELFT> *Phdr) {
  return VAddr < Phdr->p_vaddr;
}

template <typename ELFT>
static void needed_shared_libraries_of_elf(const ELFFile<ELFT> *ELF,
                                           vector<fs::path> &libs) {
  typedef typename ELFFile<ELFT>::Elf_Shdr Elf_Shdr;
  typedef typename ELFFile<ELFT>::Elf_Sym Elf_Sym;
  typedef typename ELFFile<ELFT>::Elf_Rel Elf_Rel;
  typedef typename ELFFile<ELFT>::Elf_Rela Elf_Rela;
  typedef typename ELFFile<ELFT>::Elf_Phdr Elf_Phdr;
  typedef typename ELFFile<ELFT>::Elf_Dyn_Range Elf_Dyn_Range;

  const Elf_Phdr *DynamicProgHeader = nullptr;
  SmallVector<const Elf_Phdr *, 4> LoadSegments;

  for (const Elf_Phdr &Phdr : ELF->program_headers()) {
    switch (Phdr.p_type) {
    case ELF::PT_DYNAMIC:
      DynamicProgHeader = &Phdr;
      break;
    case ELF::PT_LOAD:
     if (Phdr.p_filesz == 0)
       break;
      LoadSegments.push_back(&Phdr);
      break;
    }
  }

  ErrorOr<Elf_Dyn_Range> dyntbl_ = ELF->dynamic_table(DynamicProgHeader);
  if (dyntbl_.getError())
    return;

  Elf_Dyn_Range dyntbl = *dyntbl_;

  const char *StringTableBegin = nullptr;
  uint64_t StringTableSize = 0;

  auto toMappedAddr = [&](uint64_t VAddr) -> const uint8_t * {
    const Elf_Phdr **I = upper_bound(LoadSegments.begin(), LoadSegments.end(),
                                     VAddr, compareAddr<ELFT>);
    if (I == LoadSegments.begin())
      return nullptr;
    --I;
    const Elf_Phdr &Phdr = **I;
    uint64_t Delta = VAddr - Phdr.p_vaddr;
    if (Delta >= Phdr.p_filesz)
      return nullptr;
    return ELF->base() + Phdr.p_offset + Delta;
  };

  for (const auto &Entry : dyntbl) {
    switch (Entry.d_tag) {
    case ELF::DT_STRTAB:
      StringTableBegin = StringTableBegin
                             ? StringTableBegin
                             : (const char *)toMappedAddr(Entry.getPtr());
      break;
    case ELF::DT_STRSZ:
      StringTableSize = Entry.getVal();
      break;
    }
  }


  if (!StringTableBegin)
    return;

  StringRef DynamicStringTable = StringRef(StringTableBegin, StringTableSize);

  for (const auto &Entry : dyntbl) {
    if (Entry.d_tag != ELF::DT_NEEDED)
      continue;

    if (Entry.d_un.d_val >= DynamicStringTable.size())
      continue;

    libs.push_back(
        StringRef(DynamicStringTable.data() + Entry.d_un.d_val).str());
  }
}

void needed_shared_libraries_of_elf_binary(const ObjectFile *O,
                                           vector<fs::path> &libs) {
  if (const ELF32LEObjectFile *ELFObj = dyn_cast<ELF32LEObjectFile>(O))
    needed_shared_libraries_of_elf(ELFObj->getELFFile(), libs);
  else if (const ELF32BEObjectFile *ELFObj = dyn_cast<ELF32BEObjectFile>(O))
    needed_shared_libraries_of_elf(ELFObj->getELFFile(), libs);
  else if (const ELF64LEObjectFile *ELFObj = dyn_cast<ELF64LEObjectFile>(O))
    needed_shared_libraries_of_elf(ELFObj->getELFFile(), libs);
  else if (const ELF64BEObjectFile *ELFObj = dyn_cast<ELF64BEObjectFile>(O))
    needed_shared_libraries_of_elf(ELFObj->getELFFile(), libs);
}

void needed_shared_libraries_of_coff_binary(const ObjectFile *,
                                                   vector<fs::path> &) {
}

}
