static unsigned long guest_base_addr;
#define g2h(x) ((void *)((((unsigned long)(target_ulong)(x)) - guest_base_addr) + guest_base))

#include "tcg.hpp"
#include "stubs.hpp"

//
// global stubs
//
TraceEvent _TRACE_GUEST_MEM_BEFORE_EXEC_EVENT = {0};
TraceEvent _TRACE_GUEST_MEM_BEFORE_TRANS_EVENT = {0};
uint16_t _TRACE_OBJECT_CLASS_DYNAMIC_CAST_ASSERT_DSTATE;
int singlestep;
int qemu_loglevel;
int trace_events_enabled_count;
unsigned long guest_base;
FILE *qemu_logfile;
bool qemu_log_in_addr_range(uint64_t addr) { return false; }
const char *lookup_symbol(target_ulong orig_addr) { return nullptr; }
void target_disas(FILE *out, CPUState *cpu, target_ulong code,
                  target_ulong size) {}
void cpu_abort(CPUState *cpu, const char *fmt, ...) {
  abort();
}

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

int qemu_log(const char *fmt, ...) {
  int size;
  va_list ap;

  /* Determine required size */

  va_start(ap, fmt);
  size = vsnprintf(nullptr, 0, fmt, ap);
  va_end(ap);

  if (size < 0)
    return 0;

  size++; /* For '\0' */
  char *p = (char *)malloc(size);
  if (!p)
    return 0;

  va_start(ap, fmt);
  size = vsnprintf(p, size, fmt, ap);
  va_end(ap);

  if (size < 0) {
    free(p);
    return 0;
  }

  std::cout << p;
  free(p);

  return size;
}

int main(int argc, char** argv) {
  if (argc != 2 || !fs::exists(argv[1])) {
    std::cerr << "usage: " << argv[0] << " objfile" << std::endl;
    return 1;
  }

  //
  // initialize TCG
  //
  CPUState _cpu_state;
  memset(&_cpu_state, 0, sizeof(_cpu_state));

  CPUArchState _cpu_arch_state;
  memset(&_cpu_arch_state, 0, sizeof(_cpu_state));

#if defined(TARGET_X86_64)
  _cpu_arch_state.eflags = 514;
  _cpu_arch_state.hflags = 0x0040c0b3;
  _cpu_arch_state.hflags2 = 1;
  _cpu_arch_state.a20_mask = -1;
  _cpu_arch_state.cr[0] = 0x80010001;
  _cpu_arch_state.cr[4] = 0x00000220;
  _cpu_arch_state.mxcsr = 0x00001f80;
  _cpu_arch_state.xcr0 = 3;
  _cpu_arch_state.msr_ia32_misc_enable = 1;
  _cpu_arch_state.pat = 0x0007040600070406ULL;
  _cpu_arch_state.smbase = 0x30000;
  _cpu_arch_state.features[0] = 126614525;
  _cpu_arch_state.features[1] = 2147491841;
  _cpu_arch_state.features[5] = 563346429;
  _cpu_arch_state.features[6] = 5;
  _cpu_arch_state.user_features[0] = 2;
#elif defined(TARGET_AARCH64)
#endif

  _cpu_state.env_ptr = &_cpu_arch_state;

  TCGContext _tcg_ctx;
  tcg_context_init(&_tcg_ctx);
  _tcg_ctx.cpu = &_cpu_state;

  auto generate_tcg = [&](target_ulong pc) -> void {
    tcg_func_start(&_tcg_ctx);

    TranslationBlock tb;
    memset(&tb, 0, sizeof(tb));
    tb.pc = pc;
#if defined(TARGET_X86_64)
    tb.flags = _cpu_arch_state.hflags;
#elif defined(TARGET_AARCH64)
#endif

    DisasContext dc;
    memset(&dc, 0, sizeof(dc));

    DisasContextBase& db = dc.base;
    db.tb = &tb;
    db.pc_first = tb.pc;
    db.pc_next = db.pc_first;
    db.is_jmp = DISAS_NEXT;
    db.num_insns = 0;
    db.singlestep_enabled = _cpu_state.singlestep_enabled;

    gen_intermediate_code(&_cpu_state, &tb);
    tcg_dump_ops(&_tcg_ctx);
  };

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
    std::cout << str << std::endl << std::endl;

    guest_base_addr = Base;
    guest_base = reinterpret_cast<unsigned long>(BytesStr.bytes_begin());
    generate_tcg(Addr);
  }

  return 0;
}
