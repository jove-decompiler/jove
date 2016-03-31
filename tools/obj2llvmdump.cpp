#include <config-target.h>
#include <llvm/Object/Binary.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/ADT/Triple.h>
//#include <llvm/ADT/ArrayRef.h>
#include <string>
#include <sstream>
#include <cstdint>
#include <tuple>
#include <iostream>
#include <boost/program_options.hpp>
#include <boost/icl/interval_map.hpp>
#include "qemutcg.h"

using namespace std;
using namespace llvm;
using namespace llvm::object;
namespace po = boost::program_options;

namespace trans_obj {
static tuple<string, uint64_t> parse_command_line_arguments(int argc,
                                                            char **argv);
void verify_arch(const ObjectFile*);
void print_obj_info(const ObjectFile*);
void build_section_data_map(
    const ObjectFile*,
    vector<ArrayRef<uint8_t>> &sectdata,
    boost::icl::interval_map<uint64_t, unsigned> &sectaddrmap);
}

int main(int argc, char** argv) {
  string bfp;
  uint64_t va;

  tie(bfp, va) = trans_obj::parse_command_line_arguments(argc, argv);

  ErrorOr<OwningBinary<Binary>> BinaryOrErr = createBinary(bfp);
  if (std::error_code EC = BinaryOrErr.getError()) {
    cerr << "error: " << EC.message() << endl;
    return 1;
  }

  Binary &Binary = *BinaryOrErr.get().getBinary();
  ObjectFile *Obj = dyn_cast<ObjectFile>(&Binary);
  if (!Obj) {
    cerr << "error: provided file is not object" << endl;
    return 1;
  }

  trans_obj::verify_arch(Obj);
  trans_obj::print_obj_info(Obj);

  vector<ArrayRef<uint8_t>> sectdata;
  boost::icl::interval_map<uint64_t, unsigned> sectaddrmap;
  trans_obj::build_section_data_map(Obj, sectdata, sectaddrmap);

  auto sectit = sectaddrmap.find(va);
  if (sectit == sectaddrmap.end()) {
    cerr << "error: section not found for given address " << hex << va << endl;
    return 1;
  }
  unsigned sectidx = (*sectit).second - 1;

  libqemutcg_init();
  libqemutcg_set_code(sectdata.at(sectidx).data(), (*sectit).first.lower());
  libqemutcg_translate(va);

  return 0;
}

namespace trans_obj {

static tuple<string, uint64_t> parse_command_line_arguments(int argc,
                                                            char **argv) {
  string bfp;
  string va_s;

  try {
    po::options_description desc("Allowed options");
    desc.add_options()
      ("help,h", "produce help message")

      ("input,i", po::value<string>(&bfp),
       "specify input file path")

      ("virtual-address,v", po::value<string>(&va_s),
       "specify virtual address of basic block to translate to TCG")
    ;

    po::positional_options_description p;
    p.add("input", -1);

    po::variables_map vm;
    po::store(
        po::command_line_parser(argc, argv).options(desc).positional(p).run(),
        vm);
    po::notify(vm);

    if (vm.count("help") || !vm.count("input") ||
        !vm.count("virtual-address")) {
      cout << "Usage: trans-obj-<arch> {--virtual-address,-v} va object\n";
      cout << desc;
      exit(0);
    }
  } catch (exception &e) {
    cerr << e.what() << endl;
    exit(1);
  }

  uint64_t va;   
  stringstream ss;
  ss << std::hex << va_s;
  ss >> va;

  return make_tuple(bfp, va);
}

void print_obj_info(const ObjectFile* Obj) {
  cout << "File: " << Obj->getFileName().str() << "\n";
  cout << "Format: " << Obj->getFileFormatName().str() << "\n";
  cout << "Arch: "
         << Triple::getArchTypeName((Triple::ArchType)Obj->getArch())
         << "\n";
  cout << "AddressSize: " << (8*Obj->getBytesInAddress()) << "bit\n";
}

void verify_arch(const ObjectFile* Obj) {
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

template <class T> T errorOrDefault(ErrorOr<T> Val, T Default = T()) {
  if (!Val) {
    cerr << "warning: " << Val.getError().message() << endl;
    return Default;
  }

  return *Val;
}

template <typename ELFT>
void build_section_data_map_from_elf(
    const ELFFile<ELFT> *Elf, vector<ArrayRef<uint8_t>> &sectdata,
    boost::icl::interval_map<uint64_t, unsigned> &sectaddrmap) {
  unsigned i = 1;
  for (const auto &Shdr : Elf->sections()) {
    boost::icl::discrete_interval<uint64_t> intervl =
        boost::icl::discrete_interval<uint64_t>::right_open(
            Shdr.sh_addr, Shdr.sh_addr + Shdr.sh_size);

#if 0
    cout << errorOrDefault(Elf->getSectionName(&Shdr)).str() << '[' << hex << Shdr.sh_addr
         << ", " << Shdr.sh_addr + Shdr.sh_size << ')' << endl;
#endif

    sectdata.push_back(errorOrDefault(Elf->getSectionContents(&Shdr)));
    sectaddrmap.add(make_pair(intervl, i));
    ++i;
  }
}

void build_section_data_map(
    const ObjectFile *Obj, vector<ArrayRef<uint8_t>> &sectdata,
    boost::icl::interval_map<uint64_t, unsigned> &sectaddrmap) {
  if (Obj->isELF()) {
    if (const ELF32LEObjectFile *ELFObj = dyn_cast<ELF32LEObjectFile>(Obj))
      build_section_data_map_from_elf(ELFObj->getELFFile(), sectdata,
                                      sectaddrmap);
    else if (const ELF32BEObjectFile *ELFObj = dyn_cast<ELF32BEObjectFile>(Obj))
      build_section_data_map_from_elf(ELFObj->getELFFile(), sectdata,
                                      sectaddrmap);
    else if (const ELF64LEObjectFile *ELFObj = dyn_cast<ELF64LEObjectFile>(Obj))
      build_section_data_map_from_elf(ELFObj->getELFFile(), sectdata,
                                      sectaddrmap);
    else if (const ELF64BEObjectFile *ELFObj = dyn_cast<ELF64BEObjectFile>(Obj))
      build_section_data_map_from_elf(ELFObj->getELFFile(), sectdata,
                                      sectaddrmap);
    else
      abort();
  } else {
    cerr << "error: object file type unimplemented" << endl;
    exit(1);
  }
}

}
