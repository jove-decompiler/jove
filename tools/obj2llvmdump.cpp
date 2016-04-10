#include <config-target.h>
#include "qemutcg.h"
#include "obj2llvmdump_c.h"
#include "mc.h"
#include <llvm/MC/MCInstrAnalysis.h>
#include <llvm/ADT/Triple.h>
#include <llvm/Object/Binary.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Object/COFF.h>
#include <llvm/MC/MCRegisterInfo.h>
//#include <llvm/ADT/ArrayRef.h>
#include <boost/icl/interval_map.hpp>
#include <boost/program_options.hpp>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>
#include <tuple>

using namespace std;
using namespace llvm;
using namespace object;
namespace po = boost::program_options;

namespace trans_obj {
static tuple<string, uint64_t> parse_command_line_arguments(int argc,
                                                            char **argv);
static void verify_arch(const ObjectFile *);
static void print_obj_info(const ObjectFile *);
static void build_section_data_map(
    const ObjectFile *, vector<ArrayRef<uint8_t>> &sectdata,
    boost::icl::interval_map<uint64_t, unsigned> &sectaddrmap);
static void translate_bb(uint64_t addr, const uint8_t* sectdata,
                         uint64_t sectstart);
}

int main(int argc, char **argv) {
  string bfp;
  uint64_t va;

  tie(bfp, va) = trans_obj::parse_command_line_arguments(argc, argv);

  ErrorOr<OwningBinary<Binary>> BinaryOrErr = createBinary(bfp);
  if (error_code EC = BinaryOrErr.getError()) {
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
#if 0
  trans_obj::print_obj_info(Obj);
#endif

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
  libmc_init(Obj);

  libqemutcg_set_code(sectdata.at(sectidx).data(), sectdata.at(sectidx).size(),
                      (*sectit).first.lower());
  trans_obj::translate_bb(va, sectdata.at(sectidx).data(),
                          (*sectit).first.lower());

  return 0;
}

namespace trans_obj {

void translate_bb(uint64_t addr, const uint8_t* sectdata,
                  uint64_t sectstart) {
  libqemutcg_translate(addr);
  obj2llvmdump_print_ops();

  //
  // output branch type
  //
  uint64_t last_instr_addr = obj2llvmdump_last_tcg_op_addr();
  MCInst Inst;
  const MCInstrAnalysis *MIA = libmc_instranalyzer();
  uint64_t size = libmc_analyze_instr(
      Inst, sectdata + (last_instr_addr - sectstart), last_instr_addr);

#if 0
  cout << "addr " << hex << last_instr_addr << endl;
  cout << "size " << dec << size << endl;
#endif

  const MCInstrInfo *MII = libmc_instrinfo();
  const MCRegisterInfo *MRI = libmc_reginfo();
  if (MIA) {
    if (MIA->isReturn(Inst)) {
      cout << "Return" << endl;
    } else if (MIA->isBranch(Inst)) {
      cout << "Branch" << endl;
      if (MIA->isConditionalBranch(Inst)) {
        cout << "Conditional Branch" << endl;
      }
      if (MIA->isUnconditionalBranch(Inst)) {
        cout << "Unconditional Branch" << endl;
      }
      if (MIA->isIndirectBranch(Inst)) {
        cout << "Indirect Branch" << endl;
      }
    } else if (MIA->isCall(Inst)) {
      cout << "Call" << endl;
    }

    if (MIA->isConditionalBranch(Inst) || MIA->isUnconditionalBranch(Inst) ||
        MIA->isCall(Inst)) {
      uint64_t target;
      MIA->evaluateBranch(Inst, last_instr_addr, size, target);
      cout << "Target: 0x" << hex << target << endl;
    }
  } else {
    const MCInstrDesc &Desc = MII->get(Inst.getOpcode());
    if (Desc.isReturn()) {
      cout << "Return" << endl;
    } else if (Desc.isBranch()) {
      cout << "Branch" << endl;
      if (Desc.isConditionalBranch()) {
        cout << "Conditional Branch" << endl;
      }
      if (Desc.isUnconditionalBranch()) {
        cout << "Unconditional Branch" << endl;
      }
      if (Desc.isIndirectBranch()) {
        cout << "Indirect Branch" << endl;
      }
    } else if (Desc.isCall()) {
      cout << "Call" << endl;
    }
  }

  /* Architecture-specific notes: identifying returns from function calls
   *
   * MIPS:
   * The 'JR' "Jump Register" instruction is used to transfer control to the
   * callee's return address. This instruction "[executes] the instruction
   * following the jump, in the branch delay slot, before jumping." Therefore we
   * must consider the second-to-last instruction which was translated to
   * identify that this is an exit basic block.
   *
   * ARMv7 (thumb):
   * The 'bx' "Branch Exchange" instruction is used to transfer control to the
   * callee's return address. It is a general-purpose Indirect Branch
   * instruction, so we must determine whether the register being used is 'lr'
   * (the "Link register") to know decisively whether this is an exit basic
   * block.
   *
   **/

  /* Architecture-specific notes: identifying function calls
   *
   * MIPS:
   * The 'JAL' "Jump and Link" instruction is used to transfer control to the
   * callee and store a return address in the '$31' "Link Register" (by
   * convention). This instruction "[executes] the instruction following the
   * jump, in the branch delay slot, before jumping." Therefore we must consider
   * the second-to-last instruction which was translated to identify the
   * presence of a function call.
   *
   **/
  cout << '\'' << MII->getName(Inst.getOpcode()) << '\'' << endl;
  for (const MCOperand &opr : Inst) {
    if (opr.isReg() && opr.getReg() != 0 /* NoRegister */)
      cout << "REG " << dec << '(' << opr.getReg() << ')' << ':'
           << '\'' << MRI->getName(opr.getReg()) << '\'' << endl;
  }
}

tuple<string, uint64_t> parse_command_line_arguments(int argc, char **argv) {
  string bfp;
  string va_s;

  try {
    po::options_description desc("Allowed options");
    desc.add_options()
      ("help,h", "produce help message")

      ("input,i", po::value<string>(&bfp), "specify input file path")

#if 0
      ("sections,d", po::value<string>(&va_s),
      "translates all executable sections")
#endif

      ("virtual-address,v", po::value<string>(&va_s),
      "specify virtual address of basic block to translate");

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
      abort();
    }
  } catch (exception &e) {
    cerr << e.what() << endl;
    abort();
  }

  uint64_t va;
  stringstream ss;
  ss << hex << va_s;
  ss >> va;

  return make_tuple(bfp, va);
}

void print_obj_info(const ObjectFile *Obj) {
  cout << "File: " << Obj->getFileName().str() << "\n";
  cout << "Format: " << Obj->getFileFormatName().str() << "\n";
  cout << "Arch: " << Triple::getArchTypeName((Triple::ArchType)Obj->getArch())
       << "\n";
  cout << "AddressSize: " << (8 * Obj->getBytesInAddress()) << "bit\n";
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
    abort();
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
  unsigned SectionNumber = 0;
  for (const auto &Shdr : Elf->sections()) {
    ++SectionNumber;
    boost::icl::discrete_interval<uint64_t> intervl =
        boost::icl::discrete_interval<uint64_t>::right_open(
            Shdr.sh_addr, Shdr.sh_addr + Shdr.sh_size);

#if 0
    cout << errorOrDefault(Elf->getSectionName(&Shdr)).str() << '[' << hex << Shdr.sh_addr
         << ", " << Shdr.sh_addr + Shdr.sh_size << ')' << endl;
#endif

    sectdata.push_back(errorOrDefault(Elf->getSectionContents(&Shdr)));
    sectaddrmap.add(make_pair(intervl, SectionNumber));
  }
}

void build_section_data_map_from_coff(
    const COFFObjectFile *COFF, vector<ArrayRef<uint8_t>> &sectdata,
    boost::icl::interval_map<uint64_t, unsigned> &sectaddrmap) {
  unsigned SectionNumber = 0;
  for (const auto &Shdr : COFF->sections()) {
    ++SectionNumber;
    const coff_section *S = COFF->getCOFFSection(Shdr);

    if (S->Characteristics & COFF::IMAGE_SCN_CNT_UNINITIALIZED_DATA)
      continue;

    uint64_t RVA = S->VirtualAddress;
    uint64_t VA = COFF->getImageBase() + RVA;
    boost::icl::discrete_interval<uint64_t> intervl =
        boost::icl::discrete_interval<uint64_t>::right_open(
            VA, VA + COFF->getSectionSize(S));

#if 0
    StringRef SectNm;
    if (COFF->getSectionName(S, SectNm))
      abort();
    cout << SectNm.str() << " : " << '[' << hex << intervl.lower() << ", "
         << intervl.upper() << ')' << endl;
#endif

    ArrayRef<uint8_t> SectContents;
    if (COFF->getSectionContents(S, SectContents))
      abort();
    sectdata.push_back(SectContents);
    sectaddrmap.add(make_pair(intervl, SectionNumber));
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
  } else if (Obj->isCOFF()) {
    const COFFObjectFile *COFFObj = dyn_cast<COFFObjectFile>(Obj);
    assert(COFFObj);
    build_section_data_map_from_coff(COFFObj, sectdata, sectaddrmap);
  } else {
    cerr << "error: object file type unimplemented" << endl;
    abort();
  }
}
}
