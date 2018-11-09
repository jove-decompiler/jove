#include "tcgcommon.hpp"

#include <tuple>
#include <numeric>
#include <memory>
#include <sstream>
#include <fstream>
#include <boost/filesystem.hpp>
#include <llvm/Bitcode/BitcodeWriter.h>
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
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/DataTypes.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/ScopedPrinter.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/ToolOutputFile.h>
#include <llvm/Support/WithColor.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "jove/jove.h"
#include <boost/icl/interval_set.hpp>
#include <boost/icl/split_interval_map.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <boost/dynamic_bitset.hpp>
#include <boost/format.hpp>

#define GET_INSTRINFO_ENUM
#include "LLVMGenInstrInfo.hpp"

#define GET_REGINFO_ENUM
#include "LLVMGenRegisterInfo.hpp"

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace opts {
  static cl::opt<std::string> jv("decompilation",
    cl::desc("Jove decompilation"),
    cl::Required);

  static cl::opt<std::string> Binary("binary",
    cl::desc("Binary to decompile"),
    cl::Required);

  static cl::opt<std::string> Output("output",
    cl::desc("LLVM bitcode"),
    cl::Required);

  static cl::opt<bool> Verbose("verbose",
    cl::desc("Print extra information for debugging purposes"));
}

namespace jove {
static int llvm(void);
}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::ParseCommandLineOptions(argc, argv, "Jove LLVM\n");

  if (!fs::exists(opts::jv)) {
    llvm::errs() << "decompilation does not exist\n";
    return 1;
  }

  return jove::llvm();
}

namespace jove {

typedef boost::format fmt;

static decompilation_t decompilation;

static binary_index_t binary_idx = invalid_binary_index;

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

// we have a BB & Func map for each binary_t
struct binary_state_t {
  std::unordered_map<uintptr_t, function_index_t> FuncMap;
  std::unordered_map<uintptr_t, basic_block_index_t> BBMap;
  boost::icl::split_interval_map<uintptr_t, section_properties_set_t> SectMap;
};

static std::vector<binary_state_t> BinStateVec;

#if 0
typedef std::set<binary_index_t> binary_index_set_t;
static boost::icl::split_interval_map<std::uintptr_t, binary_index_set_t>
    AddressSpace;
#endif

typedef std::tuple<llvm::MCDisassembler &, const llvm::MCSubtargetInfo &,
                   llvm::MCInstPrinter &>
    disas_t;

static void initModuleSectionVariables(llvm::Module &);

int llvm(void) {
  bool git = fs::is_directory(opts::jv);

  //
  // parse the existing decompilation file
  //
  {
    std::ifstream ifs(git ? (opts::jv + "/decompilation.jv") : opts::jv);

    boost::archive::binary_iarchive ia(ifs);
    ia >> decompilation;
  }

  //
  // find the given binary in the decompilation
  //
  for (unsigned idx = 0; idx < decompilation.Binaries.size(); ++idx) {
    binary_t &binary = decompilation.Binaries[idx];

    if (fs::path(binary.Path).filename().string() == opts::Binary) {
      binary_idx = idx;
      break;
    }
  }

  if (binary_idx == invalid_binary_index) {
    WithColor::error() << "binary " << opts::Binary
                       << " not found in given decompilation\n";
    return 1;
  }

  tiny_code_generator_t tcg;

  // Initialize targets and assembly printers/parsers.
  llvm::InitializeAllTargetInfos();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllDisassemblers();

  llvm::Triple TheTriple;
  llvm::SubtargetFeatures Features;

  //
  // initialize state associated with every binary
  //
  BinStateVec.resize(decompilation.Binaries.size());
  for (binary_index_t i = 0; i < decompilation.Binaries.size(); ++i) {
    binary_t &binary = decompilation.Binaries[i];
    binary_state_t &st = BinStateVec[i];

    //
    // build FuncMap
    //
    for (function_index_t f_idx = 0; f_idx < binary.Analysis.Functions.size();
         ++f_idx) {
      function_t &f = binary.Analysis.Functions[f_idx];
      assert(f.Entry != invalid_basic_block_index);
      basic_block_t EntryBB = boost::vertex(f.Entry, binary.Analysis.ICFG);
      st.FuncMap[binary.Analysis.ICFG[EntryBB].Addr] = f_idx;
    }

    //
    // build BBMap
    //
    for (basic_block_index_t bb_idx = 0;
         bb_idx < boost::num_vertices(binary.Analysis.ICFG); ++bb_idx) {
      basic_block_t bb = boost::vertex(bb_idx, binary.Analysis.ICFG);

      st.BBMap[binary.Analysis.ICFG[bb].Addr] = bb_idx;
    }

    //
    // build section map
    //
    llvm::StringRef Buffer(reinterpret_cast<char *>(&binary.Data[0]),
                           binary.Data.size());
    llvm::StringRef Identifier(binary.Path);
    llvm::MemoryBufferRef MemBuffRef(Buffer, Identifier);

    llvm::Expected<std::unique_ptr<obj::Binary>> BinOrErr =
        obj::createBinary(MemBuffRef);
    if (!BinOrErr) {
      WithColor::error() << "failed to create binary from " << binary.Path
                         << '\n';
      return 1;
    }

    std::unique_ptr<obj::Binary> &Bin = BinOrErr.get();

    typedef typename obj::ELF64LEObjectFile ELFO;
    typedef typename obj::ELF64LEFile ELFT;

    if (!llvm::isa<ELFO>(Bin.get())) {
      WithColor::error() << binary.Path << " is not ELF64LEObjectFile\n";
      return 1;
    }

    ELFO &O = *llvm::cast<ELFO>(Bin.get());

    TheTriple = O.makeTriple();
    Features = O.getFeatures();

    const ELFT &E = *O.getELFFile();

    typedef typename ELFT::Elf_Shdr Elf_Shdr;
    typedef typename ELFT::Elf_Shdr_Range Elf_Shdr_Range;

    llvm::Expected<Elf_Shdr_Range> sections = E.sections();
    if (!sections) {
      WithColor::error() << "error: could not get ELF sections for binary "
                         << binary.Path << '\n';
      return 1;
    }

    if (opts::Verbose)
      llvm::outs() << binary.Path << '\n';

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
      st.SectMap.add(std::make_pair(intervl, sectprops));

      if (opts::Verbose)
        llvm::outs() << (fmt("%-20s [0x%lx, 0x%lx)") %
                         std::string(sectprop.name) % intervl.lower() %
                         intervl.upper())
                            .str()
                     << '\n';
    }
  }

  //
  // initialize the LLVM objects necessary for disassembling instructions
  //
  std::string ArchName;
  std::string Error;

  const llvm::Target *TheTarget =
      llvm::TargetRegistry::lookupTarget(ArchName, TheTriple, Error);
  if (!TheTarget) {
    WithColor::error() << "failed to lookup target: " << Error << '\n';
    return 1;
  }

  std::string TripleName = TheTriple.getTriple();
  std::string MCPU;

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

  int AsmPrinterVariant = 1 /* AsmInfo->getAssemblerDialect() */; // Intel
  std::unique_ptr<llvm::MCInstPrinter> IP(TheTarget->createMCInstPrinter(
      llvm::Triple(TripleName), AsmPrinterVariant, *AsmInfo, *MII, *MRI));
  if (!IP) {
    WithColor::error() << "no instruction printer\n";
    return 1;
  }

  disas_t dis(*DisAsm, std::cref(*STI), *IP);

  llvm::LLVMContext Context;
  llvm::Module Module(opts::Binary, Context);

  //
  // stage 1 - create section global variables
  //
  initModuleSectionVariables(Module);

  std::error_code EC;
  llvm::ToolOutputFile Out(opts::Output, EC, llvm::sys::fs::F_None);
  if (EC) {
    WithColor::error() << EC.message() << '\n';
    return 1;
  }

  llvm::WriteBitcodeToFile(Module, Out.os());

  // Declare success.
  Out.keep();

  return 0;
}

void initModuleSectionVariables(llvm::Module &) {
}

static void translate_function(binary_index_t binary_idx,
                                           tiny_code_generator_t &tcg,
                                           disas_t &dis,
                                           target_ulong Addr) {
#if 0
  binary_t &binary = decompilation.Binaries[binary_idx];
  auto &FuncMap = BinStateVec[binary_idx].FuncMap;

  {
    auto it = FuncMap.find(Addr);
    if (it != FuncMap.end())
      return (*it).second;
  }

  function_index_t res = binary.Analysis.Functions.size();
  FuncMap[Addr] = res;
  binary.Analysis.Functions.resize(res + 1);
  binary.Analysis.Functions[res].Entry =
      translate_basic_block(binary_idx, tcg, dis, Addr);
#endif
}

#if 0
basic_block_index_t translate_basic_block(binary_index_t binary_idx,
                                          tiny_code_generator_t &tcg,
                                          disas_t &dis,
                                          const target_ulong Addr) {
  auto &BBMap = BinStateVec[binary_idx].BBMap;

  {
    auto it = BBMap.find(Addr);
    if (it != BBMap.end())
      return (*it).second;
  }

  auto &SectMap = BinStateVec[binary_idx].SectMap;
  auto sectit = SectMap.find(Addr);
  if (sectit == SectMap.end()) {
    llvm::errs() << (fmt("warning: no section for address 0x%lx") % Addr).str()
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
}
#endif

}
