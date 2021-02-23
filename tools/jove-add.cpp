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
#include <llvm/Support/FormatVariadic.h>

#include "jove/jove.h"
#include <boost/range/adaptor/reversed.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/serialization/bitset.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <boost/icl/split_interval_map.hpp>
#include <boost/format.hpp>

#include <signal.h>

#ifdef __mips64
#include <unistd.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#endif

extern "C" {
void __attribute__((noinline))
     __attribute__((visibility("default")))
UserBreakPoint(void) {
  puts(__func__);
}
}

//
// TODO consolidate this into a header or something
//
static void __warn(const char *file, int line);

#ifndef WARN
#define WARN()                                                                 \
  do {                                                                         \
    __warn(__FILE__, __LINE__);                                                \
  } while (0)
#endif

#ifndef WARN_ON
#define WARN_ON(condition)                                                     \
  ({                                                                           \
    int __ret_warn_on = !!(condition);                                         \
    if (unlikely(__ret_warn_on))                                               \
      WARN();                                                                  \
    unlikely(__ret_warn_on);                                                   \
  })
#endif

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace opts {
static cl::OptionCategory JoveCategory("Specific Options");

static cl::opt<std::string> Input("input",
                                  cl::desc("Path to DSO"),
                                  cl::Required, cl::value_desc("filename"),
                                  cl::cat(JoveCategory));

static cl::alias InputAlias("i", cl::desc("Alias for -input."),
                            cl::aliasopt(Input), cl::cat(JoveCategory));

static cl::opt<std::string> Output("output", cl::desc("Jove decompilation"),
                                   cl::Required, cl::value_desc("filename"),
                                   cl::cat(JoveCategory));

static cl::alias OutputAlias("o", cl::desc("Alias for -output."),
                             cl::aliasopt(Output), cl::cat(JoveCategory));

static cl::opt<bool>
    Verbose("verbose",
            cl::desc("Print extra information for debugging purposes"),
            cl::cat(JoveCategory));

static cl::alias VerboseAlias("v", cl::desc("Alias for -verbose."),
                              cl::aliasopt(Verbose), cl::cat(JoveCategory));

static cl::opt<std::string> BreakOnAddr(
    "break-on-addr",
    cl::desc("Allow user to set a debugger breakpoint on TCGDumpBreakPoint, "
             "and triggered when basic block address matches given address"),
    cl::cat(JoveCategory));
} // namespace opts

namespace jove {
static int add(void);
}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::HideUnrelatedOptions({&opts::JoveCategory, &llvm::ColorCategory});
  cl::AddExtraVersionPrinter([](llvm::raw_ostream &OS) -> void {
    OS << "jove version " JOVE_VERSION "\n";
  });
  cl::ParseCommandLineOptions(argc, argv, "Jove Add\n");

  if (!fs::exists(opts::Input)) {
    WithColor::error() << "input binary does not exist\n";
    return 1;
  }

#ifndef __mips64
  return jove::add();
#else
  long rc = jove::add();
  syscall(__NR_exit_group, rc);
  __builtin_trap();
  __builtin_unreachable();
#endif
}

namespace jove {

struct section_t {
  llvm::StringRef Name;
  llvm::ArrayRef<uint8_t> Contents;
  uintptr_t Addr;
  unsigned Size;

  bool initArray;
  bool finiArray;

  struct {
    boost::icl::split_interval_set<uintptr_t> Intervals;
    std::map<unsigned, llvm::Constant *> Constants;
    std::map<unsigned, llvm::Type *> Types;
  } Stuff;
};

typedef boost::format fmt;

typedef std::tuple<llvm::MCDisassembler &,
                   const llvm::MCSubtargetInfo &,
                   llvm::MCInstPrinter &> disas_t;

static decompilation_t decompilation;

struct section_properties_t {
  llvm::StringRef name;
  llvm::ArrayRef<uint8_t> contents;

  bool w, x;
  bool initArray;
  bool finiArray;

  bool operator==(const section_properties_t &sect) const {
    return name == sect.name;
  }

  bool operator<(const section_properties_t &sect) const {
    return name < sect.name;
  }
};

typedef std::set<section_properties_t> section_properties_set_t;
static boost::icl::split_interval_map<std::uintptr_t, section_properties_set_t>
    SectMap;

static function_index_t translate_function(binary_t &, tiny_code_generator_t &,
                                           disas_t &, target_ulong Addr);

static basic_block_index_t translate_basic_block(binary_t &,
                                                 tiny_code_generator_t &,
                                                 disas_t &,
                                                 const target_ulong Addr);

#include "elf.hpp"

// taken from llvm/lib/DebugInfo/Symbolize/Symbolize.cpp
static llvm::Optional<llvm::ArrayRef<uint8_t>> getBuildID(const ELFF &Obj) {
  auto PhdrsOrErr = Obj.program_headers();
  if (!PhdrsOrErr) {
    consumeError(PhdrsOrErr.takeError());
    return {};
  }
  for (const auto &P : *PhdrsOrErr) {
    if (P.p_type != llvm::ELF::PT_NOTE)
      continue;
    llvm::Error Err = llvm::Error::success();
    for (auto N : Obj.notes(P, Err))
      if (N.getType() == llvm::ELF::NT_GNU_BUILD_ID &&
          N.getName() == llvm::ELF::ELF_NOTE_GNU)
        return N.getDesc();
  }
  return {};
}

static std::map<uintptr_t, std::vector<uintptr_t>> FunctionCallsToFixup;

static boost::icl::split_interval_map<uintptr_t, basic_block_index_t> BBMap;
static std::unordered_map<std::uintptr_t, function_index_t> FuncMap;

static struct {
  uintptr_t Addr;
  bool Active;
} BreakOn = {.Active = false};

int add(void) {
  if (!opts::BreakOnAddr.empty()) {
    BreakOn.Active = true;
    BreakOn.Addr = std::stoi(opts::BreakOnAddr.c_str(), 0, 16);
  }

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
#if 0
    WithColor::error() << llvm::formatv("failed to create binary from {0}\n",
                                        opts::Input);
#endif

    //
    // if this happens, we assume the given bytes do not constitute an object
    // file, and treat them as data mmapped into memory; they have no symbol
    // information.
    //
    decompilation.Binaries.resize(decompilation.Binaries.size() + 1);

    binary_t &binary = decompilation.Binaries.back();

    //
    // initialize fields
    //
    binary.IsDynamicLinker = false;
    binary.IsExecutable = false;
    binary.IsVDSO = false;

    binary.IsPIC = true;
    binary.IsDynamicallyLoaded = false;

    binary.Path = fs::canonical(opts::Input).string();
    binary.Data.resize(Buffer->getBufferSize());
    memcpy(&binary.Data[0], Buffer->getBufferStart(), binary.Data.size());

    {
      struct sigaction sa;

      sigemptyset(&sa.sa_mask);
      sa.sa_flags = 0;
      sa.sa_handler = SIG_IGN;

      sigaction(SIGINT, &sa, nullptr);
    }

    {
      std::ofstream ofs(opts::Output);

      boost::archive::binary_oarchive oa(ofs);
      oa << decompilation;
    }

    return 0;
  }

  std::unique_ptr<obj::Binary> &Bin = BinOrErr.get();

  if (!llvm::isa<ELFO>(Bin.get())) {
    WithColor::error() << "is not ELF of expected type\n";
    return 1;
  }

  ELFO &O = *llvm::cast<ELFO>(Bin.get());

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

  llvm::MCTargetOptions Options;
  std::unique_ptr<const llvm::MCAsmInfo> AsmInfo(
      TheTarget->createMCAsmInfo(*MRI, TripleName, Options));
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
  if (fs::exists(opts::Output)) {
    std::ifstream ifs(opts::Output);

    boost::archive::binary_iarchive ia(ifs);
    ia >> decompilation;
  }

  decompilation.Binaries.resize(decompilation.Binaries.size() + 1);
  binary_t &binary = decompilation.Binaries.back();

  binary.IsDynamicLinker = false;
  binary.IsExecutable = false;
  binary.IsVDSO = false;

  binary.IsPIC = true;
  binary.IsDynamicallyLoaded = false;

  binary.Path = fs::canonical(opts::Input).string();
  binary.Data.resize(Buffer->getBufferSize());
  memcpy(&binary.Data[0], Buffer->getBufferStart(), binary.Data.size());

  const ELFF &E = *O.getELFFile();

  switch (E.getHeader()->e_type) {
  case llvm::ELF::ET_NONE:
    WithColor::error() << "given binary has unknown type\n";
    return 1;

  case llvm::ELF::ET_REL:
    WithColor::error() << "given binary is object file?\n";
    return 1;

  case llvm::ELF::ET_EXEC:
    binary.IsPIC = false;
    break;

  case llvm::ELF::ET_DYN:
    break;

  case llvm::ELF::ET_CORE:
    WithColor::error() << "given binary is core file\n";
    return 1;

  default:
    abort();
    break;
  }

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

    if (!Sec.sh_size)
      continue;

    section_properties_t sectprop;

    {
      llvm::Expected<llvm::StringRef> name = E.getSectionName(&Sec);

      if (!name) {
        std::string Buf;
        {
          llvm::raw_string_ostream OS(Buf);
          llvm::logAllUnhandledErrors(name.takeError(), OS, "");
        }

        WithColor::note() << llvm::formatv("could not get section name ({0})\n",
                                           Buf);
        continue;
      }

      sectprop.name = *name;
    }

    if ((Sec.sh_flags & llvm::ELF::SHF_TLS) &&
        sectprop.name == std::string(".tbss"))
      continue;

    if (Sec.sh_type == llvm::ELF::SHT_NOBITS) {
      sectprop.contents = llvm::ArrayRef<uint8_t>();
    } else {
      llvm::Expected<llvm::ArrayRef<uint8_t>> contents =
          E.getSectionContents(&Sec);

      if (!contents) {
        std::string Buf;
        {
          llvm::raw_string_ostream OS(Buf);
          llvm::logAllUnhandledErrors(contents.takeError(), OS, "");
        }

        WithColor::note() << llvm::formatv(
            "could not get section {0} contents ({1})\n", sectprop.name, Buf);
        continue;
      }

      sectprop.contents = *contents;
    }

    sectprop.w = !!(Sec.sh_flags & llvm::ELF::SHF_WRITE);
    sectprop.x = !!(Sec.sh_flags & llvm::ELF::SHF_EXECINSTR);

    sectprop.initArray = Sec.sh_type == llvm::ELF::SHT_INIT_ARRAY;
    sectprop.finiArray = Sec.sh_type == llvm::ELF::SHT_FINI_ARRAY;

    boost::icl::interval<std::uintptr_t>::type intervl =
        boost::icl::interval<std::uintptr_t>::right_open(
            Sec.sh_addr, Sec.sh_addr + Sec.sh_size);

    {
      auto it = SectMap.find(intervl);
      if (it != SectMap.end()) {
        WithColor::error() << "the following sections intersect: "
                           << (*(*it).second.begin()).name << " and "
                           << sectprop.name << '\n';
        return 1;
      }
    }

    SectMap.add({intervl, {sectprop}});

    if (opts::Verbose)
      llvm::outs() <<
        (fmt("%-20s [0x%lx, 0x%lx)")
         % sectprop.name.str()
         % intervl.lower()
         % intervl.upper()).str() << '\n';
  }

  const unsigned NumSections = SectMap.iterative_size();

  //
  // create sections table and address -> section index map
  //
  std::vector<section_t> SectTable;
  SectTable.resize(NumSections);

  boost::icl::interval_map<uintptr_t, unsigned> SectIdxMap;

  {
    uintptr_t minAddr = std::numeric_limits<uintptr_t>::max(), maxAddr = 0;
    unsigned i = 0;
    for (const auto &pair : SectMap) {
      section_t &Sect = SectTable[i];

      minAddr = std::min(minAddr, pair.first.lower());
      maxAddr = std::max(maxAddr, pair.first.upper());

      SectIdxMap.add({pair.first, i});

      const section_properties_t &prop = *pair.second.begin();
      Sect.Addr = pair.first.lower();
      Sect.Size = pair.first.upper() - pair.first.lower();
      Sect.Name = prop.name;
      Sect.Contents = prop.contents;
      Sect.Stuff.Intervals.insert(
          boost::icl::interval<uintptr_t>::right_open(0, Sect.Size));
      Sect.initArray = prop.initArray;
      Sect.finiArray = prop.finiArray;

      ++i;
    }
  }

  disas_t dis(*DisAsm, std::cref(*STI), *IP);

  DynRegionInfo DynamicTable(O.getFileName());
  loadDynamicTable(&E, &O, DynamicTable);

  assert(DynamicTable.Addr);

  auto dynamic_table = [&DynamicTable](void) -> Elf_Dyn_Range {
    return DynamicTable.getAsArrayRef<Elf_Dyn>();
  };

  DynRegionInfo DynSymRegion(O.getFileName());
  llvm::StringRef DynamicStringTable;

  bool IsStaticallyLinked = true;

  for (const Elf_Shdr &Sec : unwrapOrError(E.sections())) {
    if (Sec.sh_type == llvm::ELF::SHT_DYNSYM) {
      DynSymRegion = createDRIFrom(&Sec, &O);

      if (llvm::Expected<llvm::StringRef> ExpectedStringTable = E.getStringTableForSymtab(Sec)) {
	DynamicStringTable = *ExpectedStringTable;
      } else {
        std::string Buf;
        {
          llvm::raw_string_ostream OS(Buf);
          llvm::logAllUnhandledErrors(ExpectedStringTable.takeError(), OS, "");
        }

	WithColor::warning() <<
	  llvm::formatv("couldn't get string table from SHT_DYNSYM: {0}\n", Buf);
      }

      break;
    }
  }

  auto dynamic_symbols = [&DynSymRegion](void) -> Elf_Sym_Range {
    return DynSymRegion.getAsArrayRef<Elf_Sym>();
  };

  std::set<uintptr_t> FunctionEntrypoints;
  std::set<uintptr_t> BasicBlockAddresses;

  uintptr_t initFunctionAddr = 0;
  //
  // parse dynamic table
  //
  {
    const char *StringTableBegin = nullptr;
    uint64_t StringTableSize = 0;
    for (const Elf_Dyn &Dyn : dynamic_table()) {
      if (unlikely(Dyn.getTag() == llvm::ELF::DT_NULL))
	break; /* marks end of dynamic table. */

      llvm::errs() << llvm::formatv("{0}:{1} Elf_Dyn {2}\n",
                                    __FILE__, __LINE__,
                                    E.getDynamicTagAsString(Dyn.getTag()));

      switch (Dyn.d_tag) {
      case llvm::ELF::DT_STRTAB:
        if (llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(Dyn.getPtr()))
          StringTableBegin = reinterpret_cast<const char *>(*ExpectedPtr);
        break;
      case llvm::ELF::DT_STRSZ:
        if (uint64_t sz = Dyn.getVal())
          StringTableSize = sz;
        break;
      case llvm::ELF::DT_SYMTAB:
        if (llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(Dyn.getPtr())) {
          const uint8_t *Ptr = *ExpectedPtr;

          if (DynSymRegion.EntSize && Ptr != DynSymRegion.Addr)
            WithColor::warning()
                << "SHT_DYNSYM section header and DT_SYMTAB disagree about "
                   "the location of the dynamic symbol table\n";

          DynSymRegion.Addr = Ptr;
          DynSymRegion.EntSize = sizeof(Elf_Sym);
        }
        break;
      case llvm::ELF::DT_NEEDED:
        IsStaticallyLinked = false;
        break;
      case llvm::ELF::DT_INIT:
        initFunctionAddr = Dyn.getVal();
        break;
      }
    }

    if (StringTableBegin) {
      assert(StringTableSize);

      if (DynamicStringTable.size() < StringTableSize)
	DynamicStringTable = llvm::StringRef(StringTableBegin, StringTableSize);
    }
  }

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

  if (uintptr_t EntryAddr = E.getHeader()->e_entry) {
    llvm::outs() << "translating entry point @ "
                 << (fmt("%#lx") % EntryAddr).str() << '\n';

    binary.Analysis.EntryFunction =
        translate_function(binary, tcg, dis, EntryAddr);
  } else {
    binary.Analysis.EntryFunction = invalid_function_index;
  }

  //
  // search local symbols
  //
  {
    const Elf_Shdr *SymTab = nullptr;

    for (const Elf_Shdr &Sect : unwrapOrError(E.sections())) {
      if (Sect.sh_type == llvm::ELF::SHT_SYMTAB) {
        assert(!SymTab);
        SymTab = &Sect;
      }
    }

    if (SymTab) {
      llvm::StringRef StrTable =
          unwrapOrError(E.getStringTableForSymtab(*SymTab));
      for (const Elf_Sym &Sym : unwrapOrError(E.symbols(SymTab))) {
        if (Sym.isUndefined())
          continue;
        if (Sym.getType() != llvm::ELF::STT_FUNC)
          continue;

        llvm::Expected<llvm::StringRef> ExpectedSymName = Sym.getName(StrTable);
        if (!ExpectedSymName)
          continue;

        llvm::StringRef SymName = *ExpectedSymName;

        llvm::outs() << llvm::formatv("translating {0} @ 0x{1:x}\n",
                                      SymName,
                                      Sym.st_value);
        FunctionEntrypoints.insert(Sym.st_value);
      }
    }
  }

  llvm::Optional<llvm::ArrayRef<uint8_t>> optionalBuildID = getBuildID(E);
  if (optionalBuildID) {
    llvm::ArrayRef<uint8_t> BuildID = *optionalBuildID;

    fs::path splitDbgInfo =
        fs::path("/usr/lib/debug") / ".build-id" /
        llvm::toHex(BuildID[0], /*LowerCase=*/true) /
        (llvm::toHex(BuildID.slice(1), /*LowerCase=*/true) + ".debug");

    if (fs::exists(splitDbgInfo)) {
      WithColor::note() << llvm::formatv("found split debug info file {0}\n",
                                         splitDbgInfo.c_str());

      llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> FileOrErr =
          llvm::MemoryBuffer::getFileOrSTDIN(splitDbgInfo.c_str());

      if (std::error_code EC = FileOrErr.getError()) {
        WithColor::error() << "failed to open debug info file " << opts::Input
                           << '\n';
        return 1;
      }

      std::unique_ptr<llvm::MemoryBuffer> &Buffer = FileOrErr.get();

      llvm::Expected<std::unique_ptr<obj::Binary>> split_BinOrErr =
          obj::createBinary(Buffer->getMemBufferRef());

      if (!split_BinOrErr) {
        WithColor::error() << "failed to create binary from split debug info "
                           << splitDbgInfo.c_str() << '\n';
        return 1;
      }

      std::unique_ptr<obj::Binary> &split_Bin = split_BinOrErr.get();

      if (!llvm::isa<ELFO>(split_Bin.get())) {
        WithColor::error() << "split debug info is not ELF of expected type\n";
        return 1;
      }

      ELFO &split_O = *llvm::cast<ELFO>(split_Bin.get());

      const ELFF &split_E = *split_O.getELFFile();

      //
      // search symbols
      //
      {
        const Elf_Shdr *SymTab = nullptr;

        for (const Elf_Shdr &Sect : unwrapOrError(split_E.sections())) {
          if (Sect.sh_type == llvm::ELF::SHT_SYMTAB) {
            assert(!SymTab);
            SymTab = &Sect;
            break;
          }
        }

        if (SymTab) {
          llvm::StringRef StrTable =
              unwrapOrError(split_E.getStringTableForSymtab(*SymTab));
          for (const Elf_Sym &Sym : unwrapOrError(split_E.symbols(SymTab))) {
            if (Sym.isUndefined())
              continue;
            if (Sym.getType() != llvm::ELF::STT_FUNC)
              continue;

            llvm::Expected<llvm::StringRef> ExpectedSymName = Sym.getName(StrTable);
            if (!ExpectedSymName)
              continue;

            llvm::StringRef SymName = *ExpectedSymName;
            if (SymName.empty())
              continue;

            //
            // since these are local symbols, we cannot rely on them being ABIs,
            // or functions at all, for that matter. We know that each entry
            // point is the start of a basic block, however.
            //
            llvm::outs() << llvm::formatv("translating (bb) {0} @ 0x{1:x}\n",
                                          SymName, Sym.st_value);

#if defined(__mips64) || defined(__mips__)
            BasicBlockAddresses.insert(Sym.st_value); /* XXX */
#else
            FunctionEntrypoints.insert(Sym.st_value);
#endif
          }
        }
      }
    }
  }

  //
  // translate constructors
  //
  if (initFunctionAddr)
    FunctionEntrypoints.insert(initFunctionAddr);

  // TODO init.array

  //
  // translate all exported functions
  //
  for (const Elf_Sym &Sym : dynamic_symbols()) {
    if (Sym.isUndefined())
      continue;
    if (Sym.getType() != llvm::ELF::STT_FUNC)
      continue;

    llvm::Expected<llvm::StringRef> ExpectedSymName = Sym.getName(DynamicStringTable);
    if (!ExpectedSymName) {
      if (opts::Verbose) {
	std::string Buf;
	{
	  llvm::raw_string_ostream OS(Buf);
	  llvm::logAllUnhandledErrors(ExpectedSymName.takeError(), OS, "");
	}

	WithColor::error() << llvm::formatv("{0}: could not get symbol name: {1}\n",
					   __func__, Buf);
      }
      continue;
    }

    llvm::StringRef SymName = *ExpectedSymName;
    llvm::outs() << llvm::formatv("translating {0} @ 0x{1:x}\n",
                                  SymName,
                                  Sym.st_value);

    FunctionEntrypoints.insert(Sym.st_value);
  }

  //
  // translate all IFunc resolver functions
  //
  for (const Elf_Sym &Sym : dynamic_symbols()) {
    if (Sym.isUndefined())
      continue;
    if (Sym.getType() != llvm::ELF::STT_GNU_IFUNC)
      continue;

    llvm::Expected<llvm::StringRef> ExpectedSymName = Sym.getName(DynamicStringTable);
    if (!ExpectedSymName)
      continue;

    llvm::StringRef SymName = *ExpectedSymName;

    llvm::outs() << llvm::formatv("translating ifunc {0} resolver @ 0x{1:x}\n",
                                  SymName, Sym.st_value);
    FunctionEntrypoints.insert(Sym.st_value);
  }

  //
  // translate all ifunc resolvers
  //
  auto process_elf_rela = [&](const Elf_Shdr &Sec, const Elf_Rela &R) -> void {
      constexpr unsigned long irelative_reloc_ty =
#if defined(__x86_64__)
          llvm::ELF::R_X86_64_IRELATIVE
#elif defined(__i386__)
          llvm::ELF::R_386_IRELATIVE
#elif defined(__aarch64__)
          llvm::ELF::R_AARCH64_IRELATIVE
#elif defined(__mips64) || defined(__mips__)
          std::numeric_limits<unsigned long>::max()
#else
#error
#endif
          ;

    unsigned reloc_ty = R.getType(E.isMips64EL());
    if (reloc_ty != irelative_reloc_ty)
      return;

    uintptr_t ifunc_resolver_addr = R.r_addend;
    if (!ifunc_resolver_addr) {
      // TODO refactor
      auto it = SectIdxMap.find(R.r_offset);
      assert(it != SectIdxMap.end());

      section_t &Sect = SectTable[(*it).second];
      unsigned Off = R.r_offset - Sect.Addr;

      assert(!Sect.Contents.empty());
      ifunc_resolver_addr = *reinterpret_cast<const uintptr_t *>(&Sect.Contents[Off]);
    }
    assert(ifunc_resolver_addr);

    llvm::outs() << llvm::formatv("translating ifunc resolver @ 0x{0:x}\n",
                                  ifunc_resolver_addr);

    FunctionEntrypoints.insert(ifunc_resolver_addr);
  };

  for (const Elf_Shdr &Sec : *sections) {
    if (Sec.sh_type == llvm::ELF::SHT_RELA) {
      for (const Elf_Rela &Rela : unwrapOrError(E.relas(&Sec)))
        process_elf_rela(Sec, Rela);
    } else if (Sec.sh_type == llvm::ELF::SHT_REL) {
      for (const Elf_Rel &Rel : unwrapOrError(E.rels(&Sec))) {
        Elf_Rela Rela;
        Rela.r_offset = Rel.r_offset;
        Rela.r_info = Rel.r_info;
        Rela.r_addend = 0;

        process_elf_rela(Sec, Rela);
      }
    }
  }

  //
  // process the functions in the higher addresses before the preceeding code.
  // this heuristic can resolve situations like the following:
  //
  // error: control flow to 0x10a330 in
  // /lib/i386-linux-gnu/libc-2.27.so doesn't lie on instruction boundary
  //
  //  10a326:       65 33 15 18 00 00 00    xor    %gs:0x18,%edx
  //  10a32d:       ff d2                   call   *%edx <-- this is actually noreturn
  //  10a32f:       00                      add    %dl,-0x77(%ebp) <-- this is garbage
  //
  //0010a330 <__nss_next@@GLIBC_2.0>:
  //  10a330:       55                      push   %ebp
  //  10a326:       65 33 15 18 00 00 00    xor    %gs:0x18,%edx
  //
  for (uintptr_t Entrypoint : boost::adaptors::reverse(BasicBlockAddresses))
    translate_basic_block(binary, tcg, dis, Entrypoint);

  for (uintptr_t Entrypoint : boost::adaptors::reverse(FunctionEntrypoints))
    translate_function(binary, tcg, dis, Entrypoint);

  do {
    std::map<uintptr_t, std::vector<uintptr_t>>
        LocalFunctionCallsToFixup = FunctionCallsToFixup;
    FunctionCallsToFixup.clear();

    auto &ICFG = binary.Analysis.ICFG;
    for (const auto &pair : boost::adaptors::reverse(LocalFunctionCallsToFixup)) {
      for (uintptr_t CallSiteAddr : pair.second) {
        auto it = BBMap.find(CallSiteAddr);
        assert(it != BBMap.end());

        basic_block_index_t bbidx = (*it).second - 1;

        if (!(bbidx < boost::num_vertices(ICFG))) {
          WithColor::note() << llvm::formatv("bbidx is {0} but num verts is {1}\n",
                                             bbidx,
                                             boost::num_vertices(ICFG));
          continue;
        }

        //assert(bbidx < boost::num_vertices(ICFG));

        basic_block_t bb = boost::vertex(bbidx, ICFG);

        if (ICFG[bb].Term.Type != TERMINATOR::CALL) {
          WithColor::note() << llvm::formatv(
              "{0:x} should be call but is {1} [{2:x}, {3:x}) TA={4:x}\n",
              CallSiteAddr,
              description_of_terminator(ICFG[bb].Term.Type),
              (*it).first.lower(),
              (*it).first.upper(),
              ICFG[bb].Term.Addr);
          continue;
        }

        assert(ICFG[bb].Term.Type == TERMINATOR::CALL);
        assert(ICFG[bb].Term._call.Target == invalid_function_index);
        ICFG[bb].Term._call.Target =
            translate_function(binary, tcg, dis, pair.first);
        assert(is_function_index_valid(ICFG[bb].Term._call.Target));
      }
    }
  } while (!FunctionCallsToFixup.empty());

#if 0
  if (EntryAddr) {
    assert(FunctionCallsToFixup.empty());
    binary.Analysis.EntryFunction =
        translate_function(binary, tcg, dis, EntryAddr);
    assert(is_function_index_valid(binary.Analysis.EntryFunction));
    assert(FunctionCallsToFixup.empty());
  }
#endif

  {
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = SIG_IGN;

    sigaction(SIGINT, &sa, nullptr);
  }

  {
    std::ofstream ofs(opts::Output);

    boost::archive::binary_oarchive oa(ofs);
    oa << decompilation;
  }

  return 0;
}

static function_index_t translate_function(binary_t &binary,
                                           tiny_code_generator_t &tcg,
                                           disas_t &dis,
                                           target_ulong Addr) {
  {
    auto it = FuncMap.find(Addr);
    if (it != FuncMap.end())
      return (*it).second;
  }

  basic_block_index_t bbidx =
    translate_basic_block(binary, tcg, dis, Addr);

  if (unlikely(!is_basic_block_index_valid(bbidx)))
    return invalid_function_index;

  function_index_t res = binary.Analysis.Functions.size();
  FuncMap[Addr] = res;
  binary.Analysis.Functions.resize(res + 1);
  binary.Analysis.Functions[res].Entry = bbidx;
  binary.Analysis.Functions[res].Analysis.Stale = true;
  binary.Analysis.Functions[res].IsABI = false;
  binary.Analysis.Functions[res].IsSignalHandler = false;

  return res;
}

static bool does_function_definitely_return(binary_index_t BIdx,
                                            function_index_t FIdx);

basic_block_index_t translate_basic_block(binary_t &binary,
                                          tiny_code_generator_t &tcg,
                                          disas_t &dis,
                                          const target_ulong Addr) {
  auto &ICFG = binary.Analysis.ICFG;

  //
  // does this new basic block start in the middle of a previously-created
  // basic block?
  //
  {
    auto it = BBMap.find(Addr);
    if (it != BBMap.end()) {
      basic_block_index_t bbidx = (*it).second - 1;
      basic_block_t bb = boost::vertex(bbidx, ICFG);

      assert(bbidx < boost::num_vertices(ICFG));

      uintptr_t beg = ICFG[bb].Addr;

      if (beg == Addr) {
        assert(ICFG[bb].Addr == (*it).first.lower());
        return bbidx;
      }

      //
      // before splitting the basic block, let's check to make sure that the
      // new block doesn't start in the middle of an instruction. if that would
      // occur, then we will assume the control-flow is invalid
      //
      {
        llvm::MCDisassembler &DisAsm = std::get<0>(dis);
        const llvm::MCSubtargetInfo &STI = std::get<1>(dis);
        llvm::MCInstPrinter &IP = std::get<2>(dis);

        auto sectit = SectMap.find(beg);
        assert(sectit != SectMap.end());
        const section_properties_t &SectProp = *(*sectit).second.begin();

        uint64_t InstLen = 0;
        for (target_ulong A = beg; A < beg + ICFG[bb].Size; A += InstLen) {
          llvm::MCInst Inst;

          std::string errmsg;
          bool Disassembled;
          {
            llvm::raw_string_ostream ErrorStrStream(errmsg);

            std::ptrdiff_t SectOffset = A - (*sectit).first.lower();
            Disassembled = DisAsm.getInstruction(
                Inst, InstLen, SectProp.contents.slice(SectOffset), A,
                ErrorStrStream);
          }

          if (!Disassembled)
            WithColor::error() << llvm::formatv(
                "failed to disassemble {0:x} {1}\n", A, errmsg);

          //assert(Disassembled);

          if (A == Addr)
            goto on_insn_boundary;
        }

        WithColor::error() << llvm::formatv(
            "control flow to {0:x} in {1} doesn't lie on instruction boundary\n",
            Addr, binary.Path);

        return invalid_basic_block_index;

on_insn_boundary:
        //
        // proceed.
        //
        ;
      }

      unsigned deg = boost::out_degree(bb, ICFG);

      std::vector<basic_block_t> out_verts;
      {
        icfg_t::out_edge_iterator e_it, e_it_end;
        for (std::tie(e_it, e_it_end) = boost::out_edges(bb, ICFG);
             e_it != e_it_end; ++e_it)
          out_verts.push_back(boost::target(*e_it, ICFG));
      }

      // if we get here, we know that beg != Addr
      assert(Addr > beg);

      ptrdiff_t off = Addr - beg;
      assert(off > 0);

      boost::icl::interval<uintptr_t>::type orig_intervl = (*it).first;

      basic_block_index_t newbbidx = boost::num_vertices(ICFG);
      basic_block_t newbb = boost::add_vertex(ICFG);
      {
        basic_block_properties_t &newbbprop = ICFG[newbb];
        newbbprop.Addr = beg;
        newbbprop.Size = off;
        newbbprop.Term.Type = TERMINATOR::NONE;
        newbbprop.Term.Addr = 0; /* XXX? */
        newbbprop.DynTargetsComplete = false;
        newbbprop.Term._call.Target = invalid_function_index;
        newbbprop.Term._call.Returns = false;
        newbbprop.Term._indirect_call.Returns = false;
        newbbprop.Term._return.Returns = false;
        newbbprop.InvalidateAnalysis();
      }

      ICFG[bb].InvalidateAnalysis();

      std::swap(ICFG[bb], ICFG[newbb]);
      ICFG[newbb].Addr = Addr;
      ICFG[newbb].Size -= off;

      assert(ICFG[newbb].Addr + ICFG[newbb].Size == orig_intervl.upper());

      boost::clear_out_edges(bb, ICFG);
      assert(boost::out_degree(bb, ICFG) == 0);

      boost::add_edge(bb, newbb, ICFG);

      for (basic_block_t out_vert : out_verts) {
        boost::add_edge(newbb, out_vert, ICFG);
      }

      assert(ICFG[bb].Term.Type == TERMINATOR::NONE);
      assert(boost::out_degree(bb, ICFG) == 1);

      assert(boost::out_degree(newbb, ICFG) == deg);

      boost::icl::interval<uintptr_t>::type intervl1 =
          boost::icl::interval<uintptr_t>::right_open(
              ICFG[bb].Addr, ICFG[bb].Addr + ICFG[bb].Size);

      boost::icl::interval<uintptr_t>::type intervl2 =
          boost::icl::interval<uintptr_t>::right_open(
              ICFG[newbb].Addr, ICFG[newbb].Addr + ICFG[newbb].Size);

      assert(boost::icl::disjoint(intervl1, intervl2));

      if (opts::Verbose) {
        llvm::outs() << "intervl1: [" << (fmt("%#lx") % intervl1.lower()).str()
                     << ", " << (fmt("%#lx") % intervl1.upper()).str() << ")\n";

        llvm::outs() << "intervl2: [" << (fmt("%#lx") % intervl2.lower()).str()
                     << ", " << (fmt("%#lx") % intervl2.upper()).str() << ")\n";

        llvm::outs() << "orig_intervl: ["
                     << (fmt("%#lx") % orig_intervl.lower()).str() << ", "
                     << (fmt("%#lx") % orig_intervl.upper()).str() << ")\n";
      }
     
      unsigned n = BBMap.iterative_size();
      BBMap.erase((*it).first);
      assert(BBMap.iterative_size() == n - 1);

      assert(BBMap.find(intervl1) == BBMap.end());
      assert(BBMap.find(intervl2) == BBMap.end());

      {
        auto _it = BBMap.find(intervl1);
        if (_it != BBMap.end()) {
          const auto &intervl = (*_it).first;
          WithColor::error() << "can't add interval1 to BBMap: ["
                             << (fmt("%#lx") % intervl1.lower()).str() << ", "
                             << (fmt("%#lx") % intervl1.upper()).str()
                             << "), BBMap already contains ["
                             << (fmt("%#lx") % intervl.lower()).str() << ", "
                             << (fmt("%#lx") % intervl.upper()).str() << ")\n";
          abort();
        }
      }

      {
        auto _it = BBMap.find(intervl2);
        if (_it != BBMap.end()) {
          const auto &intervl = (*_it).first;
          llvm::errs() << " Addr=" << (fmt("%#lx") % Addr).str() << '\n';

          WithColor::error() << "can't add interval2 to BBMap: ["
                             << (fmt("%#lx") % intervl2.lower()).str() << ", "
                             << (fmt("%#lx") % intervl2.upper()).str()
                             << "), BBMap already contains ["
                             << (fmt("%#lx") % intervl.lower()).str() << ", "
                             << (fmt("%#lx") % intervl.upper()).str() << ")\n";
          abort();
        }
      }

      BBMap.add({intervl1, 1 + bbidx});
      BBMap.add({intervl2, 1 + newbbidx});

      {
        auto _it = BBMap.find(intervl1);
        assert(_it != BBMap.end());
        assert((*_it).second == 1 + bbidx);
      }

      {
        auto _it = BBMap.find(intervl2);
        assert(_it != BBMap.end());
        assert((*_it).second == 1 + newbbidx);
      }

      return newbbidx;
    }
  }

  auto sectit = SectMap.find(Addr);
  if (sectit == SectMap.end()) {
    if (opts::Verbose)
      WithColor::note() << llvm::formatv("no section @ {0:x}\n", Addr);
    return invalid_basic_block_index;
  }
  const section_properties_t &sectprop = *(*sectit).second.begin();
  if (!sectprop.x) {
    if (opts::Verbose)
      WithColor::note() << llvm::formatv("section is not executable @ {0:x}\n",
                                         Addr);
    return invalid_basic_block_index;
  }

  tcg.set_section((*sectit).first.lower(), sectprop.contents.data());

  unsigned Size = 0;
  jove::terminator_info_t T;
  do {
    if (BreakOn.Active) {
      if (Addr == BreakOn.Addr) {
        ::UserBreakPoint();
      }
    }

    unsigned size;
    std::tie(size, T) = tcg.translate(Addr + Size);

    Size += size;

    {
      boost::icl::interval<uintptr_t>::type intervl =
          boost::icl::interval<uintptr_t>::right_open(Addr, Addr + Size);
      auto it = BBMap.find(intervl);
      if (it == BBMap.end())
        continue; /* proceed */

      const boost::icl::interval<uintptr_t>::type &_intervl = (*it).first;

      if (opts::Verbose)
        WithColor::error() << "can't translate further ["
                           << (fmt("%#lx") % intervl.lower()).str() << ", "
                           << (fmt("%#lx") % intervl.upper()).str()
                           << "), BBMap already contains ["
                           << (fmt("%#lx") % _intervl.lower()).str() << ", "
                           << (fmt("%#lx") % _intervl.upper()).str() << ")\n";

      assert(intervl.lower() < _intervl.lower());

      // assert(intervl.upper() == _intervl.upper());

      if (intervl.upper() != _intervl.upper() && opts::Verbose) {
        WithColor::warning() << "we've translated into another basic block:"
                             << (fmt("%#lx") % intervl.lower()).str() << ", "
                             << (fmt("%#lx") % intervl.upper()).str()
                             << "), BBMap already contains ["
                             << (fmt("%#lx") % _intervl.lower()).str() << ", "
                             << (fmt("%#lx") % _intervl.upper()).str() << ")\n";
      }

      //
      // solution here is to prematurely end the basic block with a NONE
      // terminator, and with a next_insn address of _intervl.lower()
      //
      Size = _intervl.lower() - intervl.lower();
      T.Type = TERMINATOR::NONE;
      T.Addr = 0; /* XXX? */
      T._none.NextPC = _intervl.lower();
      break;
    }
  } while (T.Type == TERMINATOR::NONE);

  if (T.Type == TERMINATOR::UNKNOWN) {
    WithColor::error() << llvm::formatv("unknown terminator @ {0:x}\n", Addr);

    llvm::MCDisassembler &DisAsm = std::get<0>(dis);
    const llvm::MCSubtargetInfo &STI = std::get<1>(dis);
    llvm::MCInstPrinter &IP = std::get<2>(dis);

    uint64_t InstLen;
    for (target_ulong A = Addr; A < Addr + Size; A += InstLen) {
      std::ptrdiff_t Offset = A - (*sectit).first.lower();

      llvm::MCInst Inst;
      bool Disassembled = DisAsm.getInstruction(
          Inst, InstLen, sectprop.contents.slice(Offset), A, llvm::nulls());

      if (!Disassembled) {
        WithColor::error() << llvm::formatv("failed to disassemble {0:x}\n",
                                            Addr);
        break;
      }

      IP.printInst(&Inst, A, "", STI, llvm::errs());
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
      if (SectMap.find(T._call.Target) == SectMap.end())
        return true;
    }

    return false;
  };

  if (is_invalid_terminator()) {
    WithColor::error() << "assuming unreachable code\n";
    T.Type = TERMINATOR::UNREACHABLE;
  }

  basic_block_index_t bbidx = boost::num_vertices(ICFG);
  basic_block_t bb = boost::add_vertex(ICFG);
  {
    basic_block_properties_t &bbprop = ICFG[bb];
    bbprop.Addr = Addr;
    bbprop.Size = Size;
    bbprop.Term.Type = T.Type;
    bbprop.Term.Addr = T.Addr;
    bbprop.DynTargetsComplete = false;
    bbprop.Term._call.Target = invalid_function_index;
    bbprop.Term._call.Returns = false;
    bbprop.Term._indirect_call.Returns = false;
    bbprop.Term._return.Returns = false;
    bbprop.InvalidateAnalysis();

    boost::icl::interval<uintptr_t>::type intervl =
        boost::icl::interval<uintptr_t>::right_open(bbprop.Addr,
                                                    bbprop.Addr + bbprop.Size);
    assert(BBMap.find(intervl) == BBMap.end());

    BBMap.add({intervl, 1 + bbidx});
  }

  //
  // conduct analysis of last instruction (the terminator of the block) and
  // (recursively) descend into branch targets, translating basic blocks
  //
  auto control_flow = [&](std::uintptr_t Target) -> void {
    assert(Target);

    basic_block_index_t succidx =
        translate_basic_block(binary, tcg, dis, Target);

    if (succidx == invalid_basic_block_index) {
      WithColor::note() << llvm::formatv(
          "control_flow: invalid edge {0:x} -> {1:x}\n", T.Addr, Target);
      return;
    }

    basic_block_t _bb;
    {
      auto it = T.Addr ? BBMap.find(T.Addr) : BBMap.find(Addr);
      assert(it != BBMap.end());

      basic_block_index_t _bbidx = (*it).second - 1;
      _bb = boost::vertex(_bbidx, ICFG);
      assert(T.Type == ICFG[_bb].Term.Type);
    }

    basic_block_t succ = boost::vertex(succidx, ICFG);
    bool isNewTarget = boost::add_edge(_bb, succ, ICFG).second;

    (void)isNewTarget;
  };

  switch (T.Type) {
  case TERMINATOR::UNCONDITIONAL_JUMP:
    control_flow(T._unconditional_jump.Target);
    break;

  case TERMINATOR::CONDITIONAL_JUMP:
    control_flow(T._conditional_jump.Target);
    control_flow(T._conditional_jump.NextPC);
    break;

  case TERMINATOR::CALL: {
    function_index_t FIdx =
        translate_function(binary, tcg, dis, T._call.Target);

    ICFG[bb].Term._call.Target = FIdx;

#if 0
    ICFG[bb].Term._call.Target = invalid_function_index;
    FunctionCallsToFixup[T._call.Target].push_back(T.Addr);
#endif

    //control_flow(T._call.NextPC);

    if (is_function_index_valid(FIdx) &&
        does_function_definitely_return(0, FIdx))
      control_flow(T._call.NextPC);

    break;
  }

  case TERMINATOR::INDIRECT_CALL:
    //control_flow(T._indirect_call.NextPC);
    break;

  case TERMINATOR::INDIRECT_JUMP:
  case TERMINATOR::RETURN:
  case TERMINATOR::UNREACHABLE:
    break;

  case TERMINATOR::NONE:
    control_flow(T._none.NextPC);
    break;

  default:
    abort();
  }

  return bbidx;
}

template <typename GraphTy>
struct dfs_visitor : public boost::default_dfs_visitor {
  typedef typename GraphTy::vertex_descriptor VertTy;

  std::vector<VertTy> &out;

  dfs_visitor(std::vector<VertTy> &out) : out(out) {}

  void discover_vertex(VertTy v, const GraphTy &) const { out.push_back(v); }
};

bool does_function_definitely_return(binary_index_t BIdx,
                                     function_index_t FIdx) {
  assert(is_binary_index_valid(BIdx));
  assert(is_function_index_valid(FIdx));

  binary_t &b = decompilation.Binaries.at(BIdx);
  function_t &f = b.Analysis.Functions.at(FIdx);
  auto &ICFG = b.Analysis.ICFG;

  assert(is_basic_block_index_valid(f.Entry));

  std::vector<basic_block_t> BasicBlocks;
  std::vector<basic_block_t> ExitBasicBlocks;

  std::map<basic_block_t, boost::default_color_type> color;
  dfs_visitor<interprocedural_control_flow_graph_t> vis(BasicBlocks);
  boost::depth_first_visit(
      ICFG, boost::vertex(f.Entry, ICFG), vis,
      boost::associative_property_map<
          std::map<basic_block_t, boost::default_color_type>>(color));

  //
  // ExitBasicBlocks
  //
  std::copy_if(BasicBlocks.begin(),
               BasicBlocks.end(),
               std::back_inserter(ExitBasicBlocks),
               [&](basic_block_t bb) -> bool {
                 return ICFG[bb].Term.Type == TERMINATOR::RETURN ||
                        IsDefinitelyTailCall(ICFG, bb);
               });

  return !ExitBasicBlocks.empty();
}

void _qemu_log(const char *cstr) { llvm::outs() << cstr; }

} // namespace jove

void __warn(const char *file, int line) {
  WithColor::warning() << llvm::formatv("{0}:{1}\n", file, line);
}
