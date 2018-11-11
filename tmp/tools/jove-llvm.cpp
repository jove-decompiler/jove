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

//
// Types
//
typedef boost::format fmt;

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

struct binary_state_t {
  std::unordered_map<uintptr_t, function_index_t> FuncMap;
  std::unordered_map<uintptr_t, basic_block_index_t> BBMap;
  boost::icl::split_interval_map<uintptr_t, section_properties_set_t> SectMap;
};

typedef std::tuple<llvm::MCDisassembler &, const llvm::MCSubtargetInfo &,
                   llvm::MCInstPrinter &>
    disas_t;

//
// Globals
//
static decompilation_t Decompilation;
static binary_index_t BinaryIndex = invalid_binary_index;

static std::vector<binary_state_t> BinStateVec;

static llvm::Triple TheTriple;
static llvm::SubtargetFeatures Features;

static const llvm::Target *TheTarget;
static std::unique_ptr<const llvm::MCRegisterInfo> MRI;
static std::unique_ptr<const llvm::MCAsmInfo> AsmInfo;
static std::unique_ptr<const llvm::MCSubtargetInfo> STI;
static std::unique_ptr<const llvm::MCInstrInfo> MII;
static std::unique_ptr<llvm::MCObjectFileInfo> MOFI;
static std::unique_ptr<llvm::MCContext> MCCtx;
static std::unique_ptr<llvm::MCDisassembler> DisAsm;
static std::unique_ptr<llvm::MCInstPrinter> IP;

static std::unique_ptr<tiny_code_generator_t> TCG;

static std::unique_ptr<llvm::LLVMContext> Context;
static std::unique_ptr<llvm::Module> Module;

//
// Stages
//
static int ParseDecompilation(void);
static int FindBinary(void);
static int InitStateForBinaries(void);
static int InitModule(void);
static int ParseBinaryRelocations(void);
static int InitModuleSectionVariables(void);
static int PrepareToTranslateCode(void);
static int WriteModule(void);

int llvm(void) {
  return ParseDecompilation()
      || FindBinary()
      || InitStateForBinaries()
      || InitModule()
      || ParseBinaryRelocations()
      || InitModuleSectionVariables()
      || PrepareToTranslateCode()
      || WriteModule();
}

int ParseDecompilation(void) {
  std::ifstream ifs(
      fs::is_directory(opts::jv) ? (opts::jv + "/decompilation.jv") : opts::jv);

  boost::archive::binary_iarchive ia(ifs);
  ia >> Decompilation;

  return 0;
}

int FindBinary(void) {
  for (unsigned idx = 0; idx < Decompilation.Binaries.size(); ++idx) {
    binary_t &binary = Decompilation.Binaries[idx];

    if (fs::path(binary.Path).filename().string() == opts::Binary) {
      BinaryIndex = idx;
      return 0;
    }
  }

  WithColor::error() << "binary " << opts::Binary
                     << " not found in given decompilation\n";
  return 1;
}

int InitStateForBinaries(void) {
  BinStateVec.resize(Decompilation.Binaries.size());
  for (binary_index_t bin_idx = 0;
       bin_idx < Decompilation.Binaries.size();
       ++bin_idx) {
    const binary_t &binary = Decompilation.Binaries[bin_idx];
    const interprocedural_control_flow_graph_t &ICFG = binary.Analysis.ICFG;

    binary_state_t &st = BinStateVec[bin_idx];

    //
    // FuncMap
    //
    for (function_index_t f_idx = 0;
         f_idx < binary.Analysis.Functions.size();
         ++f_idx) {
      const function_t &f = binary.Analysis.Functions[f_idx];

      st.FuncMap[ICFG[boost::vertex(f.Entry, ICFG)].Addr] = f_idx;
    }

    //
    // BBMap
    //
    for (basic_block_index_t bb_idx = 0;
         bb_idx < boost::num_vertices(ICFG);
         ++bb_idx) {
      basic_block_t bb = boost::vertex(bb_idx, ICFG);

      st.BBMap[ICFG[bb].Addr] = bb_idx;
    }

    //
    // build section map
    //
    llvm::StringRef Buffer(reinterpret_cast<const char *>(&binary.Data[0]),
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

  return 0;
}

int InitModule(void) {
  Context.reset(new llvm::LLVMContext);
  Module.reset(new llvm::Module(opts::Binary, *Context));

  return 0;
}

int ParseBinaryRelocations(void) { return 0; }
int InitModuleSectionVariables(void) { return 0; }

int PrepareToTranslateCode(void) {
  TCG.reset(new tiny_code_generator_t);

  llvm::InitializeAllTargetInfos();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllDisassemblers();

  std::string ArchName;
  std::string Error;

  TheTarget = llvm::TargetRegistry::lookupTarget(ArchName, TheTriple, Error);
  if (!TheTarget) {
    WithColor::error() << "failed to lookup target: " << Error << '\n';
    return 1;
  }

  std::string TripleName = TheTriple.getTriple();

  MRI.reset(TheTarget->createMCRegInfo(TripleName));
  if (!MRI) {
    WithColor::error() << "no register info for target\n";
    return 1;
  }

  AsmInfo.reset(TheTarget->createMCAsmInfo(*MRI, TripleName));
  if (!AsmInfo) {
    WithColor::error() << "no assembly info\n";
    return 1;
  }

  std::string MCPU;

  STI.reset(
      TheTarget->createMCSubtargetInfo(TripleName, MCPU, Features.getString()));
  if (!STI) {
    WithColor::error() << "no subtarget info\n";
    return 1;
  }

  MII.reset(TheTarget->createMCInstrInfo());
  if (!MII) {
    WithColor::error() << "no instruction info\n";
    return 1;
  }

  MOFI.reset(new llvm::MCObjectFileInfo);
  MCCtx.reset(new llvm::MCContext(AsmInfo.get(), MRI.get(), MOFI.get()));

  // FIXME: for now initialize MCObjectFileInfo with default values
  MOFI->InitMCObjectFileInfo(llvm::Triple(TripleName), false, *MCCtx);

  DisAsm.reset(TheTarget->createMCDisassembler(*STI, *MCCtx));
  if (!DisAsm) {
    WithColor::error() << "no disassembler for target\n";
    return 1;
  }

  int AsmPrinterVariant = AsmInfo->getAssemblerDialect(); /* on x86 1=Intel */
  IP.reset(TheTarget->createMCInstPrinter(
      llvm::Triple(TripleName), AsmPrinterVariant, *AsmInfo, *MII, *MRI));
  if (!IP) {
    WithColor::error() << "no instruction printer\n";
    return 1;
  }

  return 0;
}

int WriteModule(void) {
  std::error_code EC;
  llvm::ToolOutputFile Out(opts::Output, EC, llvm::sys::fs::F_None);
  if (EC) {
    WithColor::error() << EC.message() << '\n';
    return 1;
  }

  llvm::WriteBitcodeToFile(*Module, Out.os());

  // Declare success.
  Out.keep();

  return 0;
}

}
