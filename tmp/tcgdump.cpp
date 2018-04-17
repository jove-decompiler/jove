#include "tcg.hpp"
#include "stubs.hpp"

#include <iostream>
#include <boost/filesystem.hpp>
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

namespace fs = boost::filesystem;
namespace obj = llvm::object;

int main(int argc, char** argv) {
  if (argc != 2 || !fs::exists(argv[1])) {
    std::cerr << "usage: " << argv[0] << " objfile" << std::endl;
    return 1;
  }

  //
  // initialize TCG
  //
  CPUState _cpu_state;
  _cpu_state.singlestep_enabled = 0;

  //memset(&_cpu_state, 0, sizeof(_cpu_state));

  CPUArchState _cpu_arch_state;

  //memset(&_cpu_arch_state, 0, sizeof(_cpu_state));

  _cpu_state.env_ptr = &_cpu_arch_state;

  TCGContext _tcg_ctx;
  tcg_context_init(&_tcg_ctx);
  _tcg_ctx.cpu = &_cpu_state;

#if 0
  auto generate_tcg = [&](target_ulong pc) -> void {
    tcg_func_start(&_tcg_ctx);

    TranslationBlock tb;
    tb.pc = pc;

    DisasContext dc;
    DisasContextBase& db = dc.base;

    db.tb = &tb;
    db.pc_first = tb.pc;
    db.pc_next = db.pc_first;
    db.is_jmp = DISAS_NEXT;
    db.num_insns = 0;
    db.singlestep_enabled = _cpu_state.singlestep_enabled;

    i386_tr_tb_start(&db, &_cpu_state);
    for (;;) {
      db.num_insns++;

      i386_tr_insn_start(&db, &_cpu_state);
      i386_tr_translate_insn(&db, &_cpu_state);

      /* Stop translation if translate_insn so indicated.  */
      if (db.is_jmp != DISAS_NEXT)
        break;

      /* Stop translation if the output buffer is full,
         or we have executed all of the allowed instructions.  */
      if (tcg_op_buf_full()) {
        db.is_jmp = DISAS_TOO_MANY;
        break;
      }
    }

    i386_tr_tb_stop(&db, &_cpu_state);
    gen_tb_end(&tb, db.num_insns);
  };
#endif

  // Initialize targets and assembly printers/parsers.
  llvm::InitializeAllTargetInfos();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllDisassemblers();

  llvm::Expected<obj::OwningBinary<obj::Binary>> BinaryOrErr =
      obj::createBinary(argv[1]);

  if (!BinaryOrErr ||
      !llvm::isa<obj::ObjectFile>(BinaryOrErr.get().getBinary())) {
    std::cerr << "failed to open " << argv[1] << std::endl;
    return 1;
  }

  obj::ObjectFile &O =
      *llvm::cast<obj::ObjectFile>(BinaryOrErr.get().getBinary());

  std::string ArchName;
  llvm::Triple TheTriple = O.makeTriple();
  std::string Error;

  const llvm::Target *TheTarget =
      llvm::TargetRegistry::lookupTarget(ArchName, TheTriple, Error);
  if (!TheTarget) {
    std::cerr << "failed to lookup target: " << Error << std::endl;
    return 1;
  }

  std::string TripleName = TheTriple.getTriple();
  std::string MCPU;
  llvm::SubtargetFeatures Features = O.getFeatures();

  std::unique_ptr<const llvm::MCRegisterInfo> MRI(
      TheTarget->createMCRegInfo(TripleName));
  if (!MRI) {
    std::cerr << "no register info for target" << std::endl;
    return 1;
  }

  std::unique_ptr<const llvm::MCAsmInfo> AsmInfo(
      TheTarget->createMCAsmInfo(*MRI, TripleName));
  if (!AsmInfo) {
    std::cerr << "no assembly info" << std::endl;
    return 1;
  }

  std::unique_ptr<const llvm::MCSubtargetInfo> STI(
      TheTarget->createMCSubtargetInfo(TripleName, MCPU, Features.getString()));
  if (!STI) {
    std::cerr << "no subtarget info" << std::endl;
    return 1;
  }

  std::unique_ptr<const llvm::MCInstrInfo> MII(TheTarget->createMCInstrInfo());
  if (!MII) {
    std::cerr << "no instruction info" << std::endl;
    return 1;
  }

  llvm::MCObjectFileInfo MOFI;
  llvm::MCContext Ctx(AsmInfo.get(), MRI.get(), &MOFI);
  // FIXME: for now initialize MCObjectFileInfo with default values
  MOFI.InitMCObjectFileInfo(llvm::Triple(TripleName), false, Ctx);

  std::unique_ptr<llvm::MCDisassembler> DisAsm(
      TheTarget->createMCDisassembler(*STI, Ctx));
  if (!DisAsm) {
    std::cerr << "no disassembler for target" << std::endl;
    return 1;
  }

  int AsmPrinterVariant = AsmInfo->getAssemblerDialect();
  std::unique_ptr<llvm::MCInstPrinter> IP(TheTarget->createMCInstPrinter(
      llvm::Triple(TripleName), AsmPrinterVariant, *AsmInfo, *MII, *MRI));
  if (!IP) {
    std::cerr << "no instruction printer" << std::endl;
    return 1;
  }

  llvm::StringRef SectNm;
  for (obj::SymbolRef Sym : O.symbols()) {
    if (!Sym.getName() || Sym.getName()->empty() ||
        !Sym.getType() || Sym.getType().get() != obj::SymbolRef::ST_Function ||
        !Sym.getSection() || Sym.getSection().get() == O.section_end() ||
        !Sym.getAddress() ||
        !(Sym.getAddress().get() >= Sym.getSection().get()->getAddress()) ||
        Sym.getSection().get()->getName(SectNm))
      continue;

    obj::SectionRef Sect = *Sym.getSection().get();

    uint64_t Addr = Sym.getAddress().get();
    uint64_t Base = Sect.getAddress();
    uint64_t Offset = Addr - Base;

    std::cout << Sym.getName()->str() << " @ " << SectNm.str() << "+0x"
              << std::hex << Offset << std::endl;

    llvm::StringRef BytesStr;
    Sect.getContents(BytesStr);
    llvm::ArrayRef<uint8_t> Bytes(
        reinterpret_cast<const uint8_t *>(BytesStr.data()), BytesStr.size());

    llvm::MCInst Inst;
    uint64_t Size;
    llvm::raw_ostream &DebugOut = llvm::nulls();
    llvm::raw_ostream &CommentStream = llvm::nulls();
    bool Disassembled = DisAsm->getInstruction(Inst, Size, Bytes.slice(Offset),
                                               Addr, DebugOut, CommentStream);
    if (!Disassembled) {
      std::cerr << "failed to disassemble 0x" << std::hex << Addr << std::endl;
      continue;
    }

    std::string str;
    {
      llvm::raw_string_ostream StrStream(str);
      IP->printInst(&Inst, StrStream, "", *STI);
    }
    std::cout << str << std::endl;
  }

  return 0;
}
