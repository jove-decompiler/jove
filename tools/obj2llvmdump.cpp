#include <config-target.h>
#include "binary.h"
#include "qemutcg.h"
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

using namespace jove;

using namespace std;
using namespace llvm;
using namespace object;
namespace po = boost::program_options;

namespace obj2llvm {
static tuple<string, uint64_t> parse_command_line_arguments(int argc,
                                                            char **argv);
static void verify_arch(const ObjectFile *);
static void print_obj_info(const ObjectFile *);
static void translate_bb(uint64_t addr, const uint8_t* sectdata,
                         uint64_t sectstart);
}

int main(int argc, char **argv) {
  string bfp;
  uint64_t a;

  tie(bfp, a) = obj2llvm::parse_command_line_arguments(argc, argv);

  ErrorOr<OwningBinary<Binary>> BinaryOrErr = createBinary(bfp);
  if (error_code EC = BinaryOrErr.getError()) {
    cerr << "error: " << EC.message() << endl;
    return 1;
  }

  Binary &Binary = *BinaryOrErr.get().getBinary();
  ObjectFile *O = dyn_cast<ObjectFile>(&Binary);
  if (!O) {
    cerr << "error: provided file is not object" << endl;
    return 1;
  }

  obj2llvm::verify_arch(O);
  obj2llvm::print_obj_info(O);

  boost::icl::interval_map<jove::address_t, jove::section_number_t> addrspace;
  jove::address_to_section_map_of_binary(*O, addrspace);

  auto sectit = addrspace.find(a);
  if (sectit == addrspace.end())
    exit(45);

  ArrayRef<uint8_t> contents = jove::section_contents_of_binary(*O, (*sectit).second);

  libqemutcg_init();
  libmc_init(O);

  libqemutcg_set_code(contents.data(), contents.size(),
                      (*sectit).first.lower());
  obj2llvm::translate_bb(a, contents.data(), (*sectit).first.lower());

  return 0;
}

namespace obj2llvm {

void translate_bb(uint64_t addr, const uint8_t* sectdata,
                  uint64_t sectstart) {
  address_t na = addr + libqemutcg_translate(addr);
  libqemutcg_print_ops();

  //
  // output branch type
  //
  uint64_t last_instr_addr = libqemutcg_last_tcg_op_addr();
  MCInst Inst;
  uint64_t size = libmc_analyze_instr(
      Inst, sectdata + (last_instr_addr - sectstart), last_instr_addr);

  const MCInstrInfo *MII = libmc_instrinfo();
  const MCRegisterInfo *MRI = libmc_reginfo();
  const MCInstrDesc &Desc = MII->get(Inst.getOpcode());
  const MCInstrAnalysis *MIA = libmc_instranalyzer();

#if 0
  cout << "addr " << hex << last_instr_addr << endl;
  cout << "size " << dec << size << endl;
#endif

  if (MIA) {
    cout << "MCInstrAnalysis" << endl;
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
    cout << "MCInstrDesc" << endl;
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
  cout << "Next instruction: 0x" << hex << na << endl;
}

tuple<string, uint64_t> parse_command_line_arguments(int argc, char **argv) {
  string bfp;
  string a_s;

  try {
    po::options_description desc("Allowed options");
    desc.add_options()
      ("help,h", "produce help message")

      ("input,i", po::value<string>(&bfp), "specify input file path")

#if 0
      ("sections,d", po::value<string>(&a_s),
      "translates all executable sections")
#endif

      ("virtual-address,v", po::value<string>(&a_s),
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
      cout << "Usage: trans-obj-<arch> {--virtual-address,-v} object\n";
      cout << desc;
      abort();
    }
  } catch (exception &e) {
    cerr << e.what() << endl;
    abort();
  }

  uint64_t a;
  stringstream ss;
  ss << hex << a_s;
  ss >> a;

  return make_tuple(bfp, a);
}

void print_obj_info(const ObjectFile *O) {
  cout << "File: " << O->getFileName().str() << "\n";
  cout << "Format: " << O->getFileFormatName().str() << "\n";
  cout << "Arch: " << Triple::getArchTypeName((Triple::ArchType)O->getArch())
       << "\n";
  cout << "AddressSize: " << (8 * O->getBytesInAddress()) << "bit\n";
}

void verify_arch(const ObjectFile *O) {
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

  if (O->getArch() != archty) {
    cerr << "error: architecture mismatch (run trans-obj-<arch>)" << endl;
    abort();
  }
}

}
