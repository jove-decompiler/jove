#include "mc.h"
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <config-target.h>
#include <iostream>
#include <llvm/ADT/Triple.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrAnalysis.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/Object/COFF.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/ARMBuildAttributes.h>
#include <llvm/Support/LEB128.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Object/ELFTypes.h>
#include <llvm/Object/ELF.h>

using namespace std;
using namespace llvm;
using namespace object;

namespace jove {

void libmc_init() {
#if defined(TARGET_AARCH64)
  LLVMInitializeAArch64TargetInfo();
  LLVMInitializeAArch64TargetMC();
  LLVMInitializeAArch64Disassembler();
#elif defined(TARGET_ARM)
  LLVMInitializeARMTargetInfo();
  LLVMInitializeARMTargetMC();
  LLVMInitializeARMDisassembler();
#elif defined(TARGET_X86_64)
  LLVMInitializeX86TargetInfo();
  LLVMInitializeX86TargetMC();
  LLVMInitializeX86Disassembler();
#elif defined(TARGET_I386)
  LLVMInitializeX86TargetInfo();
  LLVMInitializeX86TargetMC();
  LLVMInitializeX86Disassembler();
#elif defined(TARGET_MIPS)
  LLVMInitializeMipsTargetInfo();
  LLVMInitializeMipsTargetMC();
  LLVMInitializeMipsDisassembler();
#endif
}

typedef ELFType<support::little, false> ARMElfType;
typedef ELF32LEObjectFile ARMElfObjFile;
typedef ELF32LEFile ARMElfFile;
typedef ARMElfFile::Elf_Shdr ARMElfShdr;

template <class T> static T errorOrDefault(ErrorOr<T> Val, T Default = T()) {
  return Val ? *Val : Default;
}

template <class T> static T unwrapOrDefault(Expected<T> EO, T Default = T()) {
  return EO ? *EO : Default;
}

static const ARMElfShdr *armObjAttributesSection(const ARMElfFile *ELF) {
  for (const ARMElfShdr &Sec : unwrapOrDefault(ELF->sections())) {
    if (Sec.sh_type == ELF::SHT_ARM_ATTRIBUTES)
      return &Sec;
  }

  return nullptr;
}

// from llvm/include/llvm/Support/ARMTargetParser.def
static const char *arm_cpu_arch_names[] = {
    "armv2",        // Pre_v4   = 0,
    "armv4",        // v4       = 1,   // e.g. SA110
    "armv4t",       // v4T      = 2,   // e.g. ARM7TDMI
    "armv5t",       // v5T      = 3,   // e.g. ARM9TDMI
    "armv5te",      // v5TE     = 4,   // e.g. ARM946E_S
    "armv5tej",     // v5TEJ    = 5,   // e.g. ARM926EJ_S
    "armv6",        // v6       = 6,   // e.g. ARM1136J_S
    "armv6kz",      // v6KZ     = 7,   // e.g. ARM1176JZ_S
    "armv6t2",      // v6T2     = 8,   // e.g. ARM1156T2_S
    "armv6k",       // v6K      = 9,   // e.g. ARM1176JZ_S
    "armv7",        // v7       = 10,  // e.g. Cortex A8, Cortex M3
    "armv6-m",      // v6_M     = 11,  // e.g. Cortex M1
    "armv6-m",      // v6S_M    = 12,  // v6_M with the System extensions
    "armv7-m",      // v7E_M    = 13,  // v7_M with DSP extensions
    "armv8-a",      // v8_A     = 14,  // v8_A AArch32
    "armv8-m.base", // v8_M_Base= 16,  // v8_M_Base AArch32
    "armv8-m.main", // v8_M_Main= 17,  // v8_M_Main AArch32
};

static llvm::Triple getArchTriple(const ObjectFile *Obj) {
  llvm::Triple TheTriple("unknown-unknown-unknown");
  Triple::ArchType arch = static_cast<Triple::ArchType>(Obj->getArch());

  const ARMElfObjFile *ELFObj;
  const ARMElfShdr *aaShdr;
  if (arch == Triple::arm &&
      (ELFObj = dyn_cast<ARMElfObjFile>(Obj)) &&
      (aaShdr = armObjAttributesSection(ELFObj->getELFFile()))) {
    const char *arm_cpu_arch_nm = nullptr;

    ArrayRef<uint8_t> aaSCont = *ELFObj->getELFFile()->getSectionContents(aaShdr);

    size_t Offset = 1;
    while (Offset < aaSCont.size()) {
      uint32_t SectionLength = *reinterpret_cast<const support::ulittle32_t *>(
          aaSCont.data() + Offset);

      auto parseInteger = [](const uint8_t *Data,
                             uint32_t &Offset) -> uint64_t {
        unsigned Length;
        uint64_t Value = decodeULEB128(Data + Offset, &Length);
        Offset = Offset + Length;
        return Value;
      };

      auto parseAttributeList = [&TheTriple, &arm_cpu_arch_nm, parseInteger](
          const uint8_t *Data, uint32_t &Offset, uint32_t Length) -> void {
        while (Offset < Length) {
          unsigned Length;
          uint64_t Tag = decodeULEB128(Data + Offset, &Length);
          Offset += Length;

          if (Tag != ARMBuildAttrs::CPU_arch)
            continue;

          ARMBuildAttrs::CPUArch cpu_arch =
              static_cast<ARMBuildAttrs::CPUArch>(parseInteger(Data, Offset));
          arm_cpu_arch_nm = arm_cpu_arch_names[cpu_arch];
          TheTriple.setArchName(arm_cpu_arch_nm);
        }
      };

      auto parseSubsection = [parseAttributeList](const uint8_t *Data,
                                                  uint32_t Length) -> void {
        uint32_t Offset = sizeof(uint32_t); /* SectionLength */
        const char *VendorName = reinterpret_cast<const char *>(Data + Offset);
        size_t VendorNameLength = std::strlen(VendorName);
        Offset = Offset + VendorNameLength + 1;

        while (Offset < Length) {
          uint8_t Tag = Data[Offset];
          Offset = Offset + sizeof(Tag);

          uint32_t Size =
              *reinterpret_cast<const support::ulittle32_t *>(Data + Offset);
          Offset = Offset + sizeof(Size);

          if (Size > Length) {
            cerr << "warning: subsection length greater than section length"
                 << endl;
            return;
          }

          if (Tag == ARMBuildAttrs::File)
            parseAttributeList(Data, Offset, Length);
        }
      };

      parseSubsection(aaSCont.data() + Offset, SectionLength);
      Offset = Offset + SectionLength;
    }

    if (arm_cpu_arch_nm)
      return TheTriple;
  }

  TheTriple.setArch(arch);
  return TheTriple;
}

mc_t::mc_t(const ObjectFile *Obj, const char *arch_triple)
    : TheTriple(arch_triple ? Triple(arch_triple) : getArchTriple(Obj)) {
  if (Obj->isELF())
    TheTriple.setObjectFormat(Triple::ELF);
  if (Obj->isCOFF())
    TheTriple.setObjectFormat(Triple::COFF);
  if (Obj->isMachO())
    TheTriple.setObjectFormat(Triple::MachO);

  string Error;
  TheTarget = TargetRegistry::lookupTarget("", TheTriple, Error);

  if (!TheTarget) {
    cerr << "error looking up llvm target: " << Error << endl;
    abort();
  }

  string TripleName = TheTriple.getTriple();
  MRI = TheTarget->createMCRegInfo(TripleName);
  AsmInfo = TheTarget->createMCAsmInfo(*MRI, TripleName);
  STI = TheTarget->createMCSubtargetInfo(TripleName, string(), string());
  MII = TheTarget->createMCInstrInfo();

  assert(MRI);
  assert(AsmInfo);
  assert(STI);
  assert(MII);

  MOFI = new MCObjectFileInfo;
  Ctx = new MCContext(AsmInfo, MRI, MOFI);

  DisAsm = TheTarget->createMCDisassembler(*STI, *Ctx);
  assert(DisAsm);
  IP = TheTarget->createMCInstPrinter(
      Triple(TripleName), AsmInfo->getAssemblerDialect(), *AsmInfo, *MII, *MRI);
  assert(IP);
  IP->setPrintImmHex(true);

  MIA = TheTarget->createMCInstrAnalysis(MII);
}

bool mc_t::analyze_instruction(MCInst &Inst, uint64_t &size,
                               const void *mcinsts, uint64_t addr) {
  constexpr unsigned max_instr_len = 32;

  ArrayRef<uint8_t> coderef(static_cast<const uint8_t *>(mcinsts),
                            max_instr_len);

  raw_null_ostream nullos;
  return DisAsm->getInstruction(Inst, size, coderef, addr, nullos, nullos);
}

std::string mc_t::disassemble_instruction(const MCInst &MI) {
  string Str;
  {
    raw_string_ostream CvtOS(Str);
    IP->printInst(&MI, CvtOS, "", *STI);
  }
  boost::algorithm::trim(Str);
  boost::algorithm::replace_all(Str, "\t", " ");
  return Str;
}

std::string mc_t::disassemble_bytes(const void *mcinst, uint64_t addr) {
  MCInst MI;
  uint64_t size;
  if (analyze_instruction(MI, size, mcinst, addr))
    return disassemble_instruction(MI);
  else
    return "<bad encoding>";
}
}
