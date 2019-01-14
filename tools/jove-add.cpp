#include "tcgcommon.hpp"
#include "sha3.hpp"

#include <tuple>
#include <memory>
#include <sstream>
#include <fstream>
#include <boost/filesystem.hpp>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/Object/ELF.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/WithColor.h>

#include "jove/jove.h"
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <boost/icl/split_interval_map.hpp>
#include <boost/format.hpp>

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace opts {
  static cl::opt<std::string> Input("input",
    cl::desc("Input binary"),
    cl::Required);

  static cl::opt<std::string> Output("output",
    cl::desc("Output decompilation"),
    cl::Required);

  static cl::opt<bool> Verbose("verbose",
    cl::desc("Print extra information for debugging purposes"));
}

namespace jove {
static int add(void);
}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::ParseCommandLineOptions(argc, argv, "Jove Add\n");

  if (!fs::exists(opts::Input)) {
    WithColor::error() << "input binary does not exist\n";
    return 1;
  }

  return jove::add();
}

namespace jove {

typedef boost::format fmt;

static bool verify_arch(const obj::ObjectFile &);

typedef std::tuple<llvm::MCDisassembler &,
                   const llvm::MCSubtargetInfo &,
                   llvm::MCInstPrinter &> disas_t;

struct section_properties_t {
  llvm::StringRef name;
  llvm::ArrayRef<uint8_t> contents;

  bool operator==(const section_properties_t &sect) const {
    return name == sect.name;
  }

  bool operator<(const section_properties_t &sect) const {
    return name < sect.name;
  }
};

typedef std::set<section_properties_t> section_properties_set_t;
static boost::icl::split_interval_map<std::uintptr_t, section_properties_set_t>
    sectm;

static function_index_t translate_function(binary_t &, tiny_code_generator_t &,
                                           disas_t &, target_ulong Addr);

/// Represents a contiguous uniform range in the file. We cannot just create a
/// range directly because when creating one of these from the .dynamic table
/// the size, entity size and virtual address are different entries in arbitrary
/// order (DT_REL, DT_RELSZ, DT_RELENT for example).
struct DynRegionInfo {
  DynRegionInfo() = default;
  DynRegionInfo(const void *A, uint64_t S, uint64_t ES)
      : Addr(A), Size(S), EntSize(ES) {}

  /// Address in current address space.
  const void *Addr = nullptr;
  /// Size in bytes of the region.
  uint64_t Size = 0;
  /// Size of each entity in the region.
  uint64_t EntSize = 0;

  template <typename Type>
    llvm::ArrayRef<Type> getAsArrayRef() const {
    const Type *Start = reinterpret_cast<const Type *>(Addr);
    if (!Start)
      return {Start, Start};
    if (EntSize != sizeof(Type) || Size % EntSize)
      abort();
    return {Start, Start + (Size / EntSize)};
  }
};

template <class T>
static T unwrapOrError(llvm::Expected<T> EO) {
  if (EO)
    return *EO;

  std::string Buf;
  {
    llvm::raw_string_ostream OS(Buf);
    llvm::logAllUnhandledErrors(EO.takeError(), OS, "");
  }
  WithColor::error() << Buf << '\n';
  exit(1);
}

#if defined(__x86_64__) || defined(__aarch64__)
typedef typename obj::ELF64LEObjectFile ELFO;
typedef typename obj::ELF64LEFile ELFT;
#elif defined(__i386__)
typedef typename obj::ELF32LEObjectFile ELFO;
typedef typename obj::ELF32LEFile ELFT;
#endif

int add(void) {
  tiny_code_generator_t tcg;

  // Initialize targets and assembly printers/parsers.
  llvm::InitializeNativeTarget();
  llvm::InitializeNativeTargetDisassembler();

  llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> FileOrErr =
      llvm::MemoryBuffer::getFileOrSTDIN(opts::Input);

  if (std::error_code EC = FileOrErr.getError()) {
    WithColor::error() << "failed to open " << opts::Input << '\n';
    return 1;
  }

  std::unique_ptr<llvm::MemoryBuffer> &Buffer = FileOrErr.get();

  llvm::Expected<std::unique_ptr<obj::Binary>> BinOrErr =
      obj::createBinary(Buffer->getMemBufferRef());

  if (!BinOrErr) {
    WithColor::error() << "failed to create binary from" << opts::Input << '\n';
    return 1;
  }

  std::unique_ptr<obj::Binary> &Bin = BinOrErr.get();

  if (!llvm::isa<ELFO>(Bin.get())) {
    WithColor::error() << "is not ELF of expected type\n";
    return 1;
  }

  ELFO &O = *llvm::cast<ELFO>(Bin.get());

  if (!verify_arch(O)) {
    WithColor::error() << "architecture mismatch of input\n";
    return 1;
  }

  std::string ArchName;
  llvm::Triple TheTriple = O.makeTriple();
  std::string Error;

  const llvm::Target *TheTarget =
      llvm::TargetRegistry::lookupTarget(ArchName, TheTriple, Error);
  if (!TheTarget) {
    WithColor::error() << "failed to lookup target: " << Error << '\n';
    return 1;
  }

  std::string TripleName = TheTriple.getTriple();
  std::string MCPU;
  llvm::SubtargetFeatures Features = O.getFeatures();

  std::unique_ptr<const llvm::MCRegisterInfo> MRI(
      TheTarget->createMCRegInfo(TripleName));
  if (!MRI) {
    WithColor::error() << "no register info for target\n";
    return 1;
  }

  std::unique_ptr<const llvm::MCAsmInfo> AsmInfo(
      TheTarget->createMCAsmInfo(*MRI, TripleName));
  if (!AsmInfo) {
    WithColor::error() << "no assembly info\n";
    return 1;
  }

  std::unique_ptr<const llvm::MCSubtargetInfo> STI(
      TheTarget->createMCSubtargetInfo(TripleName, MCPU, Features.getString()));
  if (!STI) {
    WithColor::error() << "no subtarget info\n";
    return 1;
  }

  std::unique_ptr<const llvm::MCInstrInfo> MII(TheTarget->createMCInstrInfo());
  if (!MII) {
    WithColor::error() << "no instruction info\n";
    return 1;
  }

  llvm::MCObjectFileInfo MOFI;
  llvm::MCContext Ctx(AsmInfo.get(), MRI.get(), &MOFI);
  // FIXME: for now initialize MCObjectFileInfo with default values
  MOFI.InitMCObjectFileInfo(llvm::Triple(TripleName), false, Ctx);

  std::unique_ptr<llvm::MCDisassembler> DisAsm(
      TheTarget->createMCDisassembler(*STI, Ctx));
  if (!DisAsm) {
    WithColor::error() << "no disassembler for target\n";
    return 1;
  }

  int AsmPrinterVariant = AsmInfo->getAssemblerDialect();
  std::unique_ptr<llvm::MCInstPrinter> IP(TheTarget->createMCInstPrinter(
      llvm::Triple(TripleName), AsmPrinterVariant, *AsmInfo, *MII, *MRI));
  if (!IP) {
    WithColor::error() << "no instruction printer\n";
    return 1;
  }

  //
  // initialize the decompilation of the given binary by exploring every defined
  // exported function
  //
  decompilation_t decompilation;
  if (fs::exists(opts::Output)) {
    std::ifstream ifs(opts::Output);

    boost::archive::binary_iarchive ia(ifs);
    ia >> decompilation;
  }

  decompilation.Binaries.resize(decompilation.Binaries.size() + 1);
  binary_t &binary = decompilation.Binaries.back();

  binary.Path = fs::canonical(opts::Input).string();
  binary.Data.resize(Buffer->getBufferSize());
  memcpy(&binary.Data[0], Buffer->getBufferStart(), binary.Data.size());

  auto write_decompilation = [&](void) -> void {
    std::ofstream ofs(opts::Output);

    boost::archive::binary_oarchive oa(ofs);
    oa << decompilation;
  };

  const ELFT &E = *O.getELFFile();

  typedef typename ELFT::Elf_Dyn Elf_Dyn;
  typedef typename ELFT::Elf_Dyn_Range Elf_Dyn_Range;
  typedef typename ELFT::Elf_Phdr Elf_Phdr;
  typedef typename ELFT::Elf_Phdr_Range Elf_Phdr_Range;
  typedef typename ELFT::Elf_Shdr Elf_Shdr;
  typedef typename ELFT::Elf_Shdr_Range Elf_Shdr_Range;
  typedef typename ELFT::Elf_Sym Elf_Sym;
  typedef typename ELFT::Elf_Sym_Range Elf_Sym_Range;

  //
  // build section map
  //
  llvm::Expected<Elf_Shdr_Range> sections = E.sections();
  if (!sections) {
    WithColor::error() << "error: could not get ELF sections\n";
    return 1;
  }

  for (const Elf_Shdr &Sec : *sections) {
    if (!(Sec.sh_flags & llvm::ELF::SHF_ALLOC))
      continue;

    llvm::Expected<llvm::ArrayRef<uint8_t>> contents =
        E.getSectionContents(&Sec);

    if (!contents)
      continue;

    llvm::Expected<llvm::StringRef> name = E.getSectionName(&Sec);

    if (!name)
      continue;

    boost::icl::interval<std::uintptr_t>::type intervl =
        boost::icl::interval<std::uintptr_t>::right_open(
            Sec.sh_addr, Sec.sh_addr + Sec.sh_size);

    section_properties_t sectprop;
    sectprop.name = *name;
    sectprop.contents = *contents;

    section_properties_set_t sectprops = {sectprop};
    sectm.add(std::make_pair(intervl, sectprops));

    if (opts::Verbose)
      llvm::outs() <<
        (fmt("%-20s [0x%lx, 0x%lx)")
         % sectprop.name.str()
         % intervl.lower()
         % intervl.upper()).str() << '\n';
  }

  disas_t dis(*DisAsm, std::cref(*STI), *IP);

  //
  // iterate dynamic defined functions
  //
  auto checkDRI = [&E](DynRegionInfo DRI) -> DynRegionInfo {
    if (DRI.Addr < E.base() ||
        (const uint8_t *)DRI.Addr + DRI.Size > E.base() + E.getBufSize())
      abort();
    return DRI;
  };

  llvm::SmallVector<const Elf_Phdr *, 4> LoadSegments;
  DynRegionInfo DynamicTable;
  {
    auto createDRIFrom = [&E, &checkDRI](const Elf_Phdr *P,
                                         uint64_t EntSize) -> DynRegionInfo {
      return checkDRI({E.base() + P->p_offset, P->p_filesz, EntSize});
    };

    for (const Elf_Phdr &Phdr : unwrapOrError(E.program_headers())) {
      if (Phdr.p_type == llvm::ELF::PT_DYNAMIC) {
        DynamicTable = createDRIFrom(&Phdr, sizeof(Elf_Dyn));
        continue;
      }
      if (Phdr.p_type != llvm::ELF::PT_LOAD || Phdr.p_filesz == 0)
        continue;
      LoadSegments.push_back(&Phdr);
    }
  }

  assert(DynamicTable.Addr);

  DynRegionInfo DynSymRegion;
  llvm::StringRef DynSymtabName;
  llvm::StringRef DynamicStringTable;

  bool IsStaticallyLinked = true;

  {
    auto createDRIFrom = [&E, &checkDRI](const Elf_Shdr *S) -> DynRegionInfo {
      return checkDRI({E.base() + S->sh_offset, S->sh_size, S->sh_entsize});
    };

    for (const Elf_Shdr &Sec : unwrapOrError(E.sections())) {
      switch (Sec.sh_type) {
      case llvm::ELF::SHT_DYNSYM:
        DynSymRegion = createDRIFrom(&Sec);
        DynSymtabName = unwrapOrError(E.getSectionName(&Sec));
        DynamicStringTable = unwrapOrError(E.getStringTableForSymtab(Sec));
        break;
      }
    }
  }

  //
  // parse dynamic table
  //
  {
    auto dynamic_table = [&DynamicTable](void) -> Elf_Dyn_Range {
      return DynamicTable.getAsArrayRef<Elf_Dyn>();
    };

    auto toMappedAddr = [&](uint64_t VAddr) -> const uint8_t * {
      const Elf_Phdr *const *I =
          std::upper_bound(LoadSegments.begin(), LoadSegments.end(), VAddr,
                           [](uint64_t VAddr, const Elf_Phdr *Phdr) {
                             return VAddr < Phdr->p_vaddr;
                           });
      if (I == LoadSegments.begin())
        abort();
      --I;
      const Elf_Phdr &Phdr = **I;
      uint64_t Delta = VAddr - Phdr.p_vaddr;
      if (Delta >= Phdr.p_filesz)
        abort();
      return E.base() + Phdr.p_offset + Delta;
    };

    const char *StringTableBegin = nullptr;
    uint64_t StringTableSize = 0;
    for (const Elf_Dyn &Dyn : dynamic_table()) {
      switch (Dyn.d_tag) {
      case llvm::ELF::DT_STRTAB:
        StringTableBegin = (const char *)toMappedAddr(Dyn.getPtr());
        break;
      case llvm::ELF::DT_STRSZ:
        StringTableSize = Dyn.getVal();
        break;
      case llvm::ELF::DT_NEEDED:
        IsStaticallyLinked = false;
        break;
      }
    };

    if (StringTableBegin)
      DynamicStringTable = llvm::StringRef(StringTableBegin, StringTableSize);
  }

  auto dynamic_symbols = [&DynSymRegion](void) -> Elf_Sym_Range {
    return DynSymRegion.getAsArrayRef<Elf_Sym>();
  };

  //
  // if the ELF has a PT_INTERP program header, then we'll explore the entry
  // point. if not, we'll only consider it if it's statically-linked (i.e. it's
  // the dynamic linker)
  //
  struct {
    bool Found;
  } Interp;

  Interp.Found = false;

  llvm::Expected<Elf_Phdr_Range> program_hdrs = E.program_headers();
  if (program_hdrs) {
    for (const Elf_Phdr &Phdr : *program_hdrs) {
      if (Phdr.p_type != llvm::ELF::PT_INTERP)
        continue;

      if (Interp.Found) {
        WithColor::error()
            << "malformed ELF: multiple PT_INTERP program headers\n";
        return 1;
      }

      Interp.Found = true;
    }
  }

  if (Interp.Found || IsStaticallyLinked) {
    llvm::outs() << "translating entry point @ "
                 << (fmt("%#lx") % E.getHeader()->e_entry).str() << '\n';

    binary.Analysis.EntryFunction =
        translate_function(binary, tcg, dis, E.getHeader()->e_entry);
  } else {
    binary.Analysis.EntryFunction = invalid_function_index;
  }

  binary.IsDynamicLinker = !Interp.Found;

  for (const Elf_Sym &Sym : dynamic_symbols()) {
    if (Sym.isUndefined())
      continue;
    if (Sym.getType() != llvm::ELF::STT_FUNC)
      continue;

    llvm::StringRef SymName = unwrapOrError(Sym.getName(DynamicStringTable));
    llvm::outs() << "translating " << SymName << "...\n";
    translate_function(binary, tcg, dis, Sym.st_value);
  }

  write_decompilation();
  return 0;
}

static basic_block_index_t translate_basic_block(binary_t &,
                                                 tiny_code_generator_t &,
                                                 disas_t &,
                                                 const target_ulong Addr);

static std::unordered_map<std::uintptr_t, basic_block_index_t> BBMap;
static std::unordered_map<std::uintptr_t, function_index_t> FuncMap;

static function_index_t translate_function(binary_t &binary,
                                           tiny_code_generator_t &tcg,
                                           disas_t &dis,
                                           target_ulong Addr) {
  {
    auto it = FuncMap.find(Addr);
    if (it != FuncMap.end())
      return (*it).second;
  }

  function_index_t res = binary.Analysis.Functions.size();
  FuncMap[Addr] = res;
  binary.Analysis.Functions.resize(res + 1);
  binary.Analysis.Functions[res].Entry =
      translate_basic_block(binary, tcg, dis, Addr);

  return res;
}

basic_block_index_t translate_basic_block(binary_t &binary,
                                          tiny_code_generator_t &tcg,
                                          disas_t &dis,
                                          const target_ulong Addr) {
  {
    auto it = BBMap.find(Addr);
    if (it != BBMap.end())
      return (*it).second;
  }

  auto sectit = sectm.find(Addr);
  if (sectit == sectm.end()) {
    WithColor::error() << "warning: no section @ " << (fmt("%#lx") % Addr).str()
                       << '\n';
    return invalid_basic_block_index;
  }
  const section_properties_t &sectprop = *(*sectit).second.begin();
  tcg.set_section((*sectit).first.lower(), sectprop.contents.data());

  unsigned Size = 0;
  jove::terminator_info_t T;
  do {
    unsigned size;
    std::tie(size, T) = tcg.translate(Addr + Size);

    Size += size;
  } while (T.Type == TERMINATOR::NONE);

  if (T.Type == TERMINATOR::UNKNOWN) {
    WithColor::error() << "error: unknown terminator @ "
                       << (fmt("%#lx") % Addr).str() << '\n';

    llvm::MCDisassembler &DisAsm = std::get<0>(dis);
    const llvm::MCSubtargetInfo &STI = std::get<1>(dis);
    llvm::MCInstPrinter &IP = std::get<2>(dis);

    uint64_t InstLen;
    for (target_ulong A = Addr; A < Addr + Size; A += InstLen) {
      std::ptrdiff_t Offset = A - (*sectit).first.lower();

      llvm::MCInst Inst;
      bool Disassembled =
          DisAsm.getInstruction(Inst, InstLen, sectprop.contents.slice(Offset),
                                A, llvm::nulls(), llvm::nulls());

      if (!Disassembled) {
        WithColor::error() << "failed to disassemble "
                           << (fmt("%#lx") % Addr).str() << '\n';
        break;
      }

      IP.printInst(&Inst, llvm::errs(), "", STI);
      llvm::errs() << '\n';
    }

#if 0
    tcg.dump_operations();
    fputc('\n', stdout);
#endif

    return invalid_basic_block_index;
  }

  auto is_invalid_terminator = [&](void) -> bool {
    if (T.Type == TERMINATOR::CALL) {
      if (sectm.find(T._call.Target) == sectm.end())
        return true;
    }

    return false;
  };

  if (is_invalid_terminator()) {
    WithColor::error() << "assuming unreachable code\n";
    T.Type = TERMINATOR::UNREACHABLE;
  }

  basic_block_index_t bbidx = boost::num_vertices(binary.Analysis.ICFG);
  basic_block_t bb = boost::add_vertex(binary.Analysis.ICFG);
  {
    basic_block_properties_t &bbprop = binary.Analysis.ICFG[bb];
    bbprop.Addr = Addr;
    bbprop.Size = Size;
    bbprop.Term.Type = T.Type;
    bbprop.Term.Addr = T.Addr;
  }

  BBMap[Addr] = bbidx;

  //
  // conduct analysis of last instruction (the terminator of the block) and
  // (recursively) descend into branch targets, translating basic blocks
  //
  auto control_flow = [&](std::uintptr_t Target) -> void {
    assert(Target);

    basic_block_index_t succidx;

    auto it = BBMap.find(Target);
    succidx = it != BBMap.end()
                  ? (*it).second
                  : translate_basic_block(binary, tcg, dis, Target);

    if (succidx != invalid_basic_block_index) {
      basic_block_t succ = boost::vertex(succidx, binary.Analysis.ICFG);
      boost::add_edge(bb, succ, binary.Analysis.ICFG);
    }
  };

  switch (T.Type) {
  case TERMINATOR::UNCONDITIONAL_JUMP:
    control_flow(T._unconditional_jump.Target);
    break;

  case TERMINATOR::CONDITIONAL_JUMP:
    control_flow(T._conditional_jump.Target);
    control_flow(T._conditional_jump.NextPC);
    break;

  case TERMINATOR::CALL:
    binary.Analysis.ICFG[bb].Term._call.Target =
        translate_function(binary, tcg, dis, T._call.Target);

    control_flow(T._call.NextPC);
    break;

  case TERMINATOR::INDIRECT_CALL:
    control_flow(T._indirect_call.NextPC);
    break;

  case TERMINATOR::INDIRECT_JUMP:
  case TERMINATOR::RETURN:
  case TERMINATOR::UNREACHABLE:
    break;

  default:
    abort();
  }

  return bbidx;
}

bool verify_arch(const obj::ObjectFile &Obj) {
#if defined(__x86_64__)
  const llvm::Triple::ArchType archty = llvm::Triple::ArchType::x86_64;
#elif defined(__i386__)
  const llvm::Triple::ArchType archty = llvm::Triple::ArchType::x86;
#elif defined(__aarch64__)
  const llvm::Triple::ArchType archty = llvm::Triple::ArchType::aarch64;
#endif

  return Obj.getArch() == archty;
}

void _qemu_log(const char *cstr) { llvm::outs() << cstr; }

}
