#include "tcgcommon.hpp"

#include <tuple>
#include <memory>
#include <sstream>
#include <fstream>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <llvm/Object/ELF.h>
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
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/Support/FileSystem.h>

#include "jove/jove.h"
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <boost/icl/split_interval_map.hpp>

namespace fs = boost::filesystem;
namespace po = boost::program_options;
namespace obj = llvm::object;

namespace jove {

static int parse_command_line_arguments(int argc, char **argv);
static int initialize_decompilation(void);

}

int main(int argc, char **argv) {
  llvm::StringRef ToolName = argv[0];
  llvm::sys::PrintStackTraceOnErrorSignal(ToolName);
  llvm::PrettyStackTraceProgram X(argc, argv);
  llvm::llvm_shutdown_obj Y;

  return jove::parse_command_line_arguments(argc, argv) ||
         jove::initialize_decompilation();
}

namespace jove {

static bool verify_arch(const obj::ObjectFile &);

static struct {
  fs::path input;
  fs::path output;
  bool verbose;
} cmdline;

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

int initialize_decompilation(void) {
  tiny_code_generator_t tcg;

  // Initialize targets and assembly printers/parsers.
  llvm::InitializeAllTargetInfos();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllDisassemblers();

  llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> FileOrErr =
      llvm::MemoryBuffer::getFileOrSTDIN(cmdline.input.string());

  if (std::error_code EC = FileOrErr.getError()) {
    fprintf(stderr, "failed to open %s\n",
            cmdline.input.string().c_str());
    return 1;
  }

  std::unique_ptr<llvm::MemoryBuffer> &Buffer = FileOrErr.get();

  llvm::Expected<std::unique_ptr<obj::Binary>> BinOrErr =
      obj::createBinary(Buffer->getMemBufferRef());

  if (!BinOrErr) {
    fprintf(stderr, "failed to open %s\n", cmdline.input.string().c_str());
    return 1;
  }

  std::unique_ptr<obj::Binary> &Bin = BinOrErr.get();

  typedef typename obj::ELF64LEObjectFile ELFO;
  typedef typename obj::ELF64LEFile ELFT;

  if (!llvm::isa<ELFO>(Bin.get())) {
    fprintf(stderr, "%s is not ELF64LEObjectFile\n",
            cmdline.input.string().c_str());
    return 1;
  }

  ELFO &O = *llvm::cast<ELFO>(Bin.get());

  if (!verify_arch(O)) {
    fprintf(stderr, "architecture mismatch of input\n");
    return 1;
  }

  std::string ArchName;
  llvm::Triple TheTriple = O.makeTriple();
  std::string Error;

  const llvm::Target *TheTarget =
      llvm::TargetRegistry::lookupTarget(ArchName, TheTriple, Error);
  if (!TheTarget) {
    fprintf(stderr, "failed to lookup target: %s\n", Error.c_str());
    return 1;
  }

  std::string TripleName = TheTriple.getTriple();
  std::string MCPU;
  llvm::SubtargetFeatures Features = O.getFeatures();

  std::unique_ptr<const llvm::MCRegisterInfo> MRI(
      TheTarget->createMCRegInfo(TripleName));
  if (!MRI) {
    fprintf(stderr, "no register info for target\n");
    return 1;
  }

  std::unique_ptr<const llvm::MCAsmInfo> AsmInfo(
      TheTarget->createMCAsmInfo(*MRI, TripleName));
  if (!AsmInfo) {
    fprintf(stderr, "no assembly info\n");
    return 1;
  }

  std::unique_ptr<const llvm::MCSubtargetInfo> STI(
      TheTarget->createMCSubtargetInfo(TripleName, MCPU, Features.getString()));
  if (!STI) {
    fprintf(stderr, "no subtarget info\n");
    return 1;
  }

  std::unique_ptr<const llvm::MCInstrInfo> MII(TheTarget->createMCInstrInfo());
  if (!MII) {
    fprintf(stderr, "no instruction info\n");
    return 1;
  }

  llvm::MCObjectFileInfo MOFI;
  llvm::MCContext Ctx(AsmInfo.get(), MRI.get(), &MOFI);
  // FIXME: for now initialize MCObjectFileInfo with default values
  MOFI.InitMCObjectFileInfo(llvm::Triple(TripleName), false, Ctx);

  std::unique_ptr<llvm::MCDisassembler> DisAsm(
      TheTarget->createMCDisassembler(*STI, Ctx));
  if (!DisAsm) {
    fprintf(stderr, "no disassembler for target\n");
    return 1;
  }

  int AsmPrinterVariant = AsmInfo->getAssemblerDialect();
  std::unique_ptr<llvm::MCInstPrinter> IP(TheTarget->createMCInstPrinter(
      llvm::Triple(TripleName), AsmPrinterVariant, *AsmInfo, *MII, *MRI));
  if (!IP) {
    fprintf(stderr, "no instruction printer\n");
    return 1;
  }

  //
  // initialize the decompilation of the given binary by exploring every defined
  // exported function
  //
  decompilation_t decompilation;
  if (fs::exists(cmdline.output)) {
    std::ifstream ifs(cmdline.output.string());

    boost::archive::binary_iarchive ia(ifs);
    ia >> decompilation;
  }

  decompilation.Binaries.resize(decompilation.Binaries.size() + 1);
  binary_t &binary = decompilation.Binaries.back();

  binary.Path = fs::canonical(cmdline.input).string();
  binary.Data.resize(Buffer->getBufferSize());
  memcpy(&binary.Data[0], Buffer->getBufferStart(), binary.Data.size());

  auto write_decompilation = [&](void) -> void {
    std::ofstream ofs(cmdline.output.string());

    boost::archive::binary_oarchive oa(ofs);
    oa << decompilation;
  };

  const ELFT &E = *O.getELFFile();

  typedef typename ELFT::Elf_Shdr Elf_Shdr;
  typedef typename ELFT::Elf_Sym Elf_Sym;
  typedef typename ELFT::Elf_Sym_Range Elf_Sym_Range;
  typedef typename ELFT::Elf_Shdr_Range Elf_Shdr_Range;

  //
  // build section map
  //
  llvm::Expected<Elf_Shdr_Range> sections = E.sections();
  if (!sections) {
    fprintf(stderr, "error: could not get ELF sections\n");
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

    auto intervl = boost::icl::discrete_interval<uintptr_t>::right_open(
        Sec.sh_addr, Sec.sh_addr + Sec.sh_size);

    section_properties_t sectprop;
    sectprop.name = *name;
    sectprop.contents = *contents;

    section_properties_set_t sectprops = {sectprop};
    sectm.add(std::make_pair(intervl, sectprops));

    printf("%-20s [0x%lx, 0x%lx)\n",
           sectprop.name.data(),
           intervl.lower(),
           intervl.upper());
  }

  //
  // get the dynamic symbols (those are the ones that matter to the dynamic
  // linker)
  //
  struct {
    Elf_Sym_Range Symbols;

    bool Found;
  } Dyn;

  Dyn.Found = false;
  for (const Elf_Shdr &Sec : *sections) {
    if (Sec.sh_type != llvm::ELF::SHT_DYNSYM)
      continue;

    if (Dyn.Found) {
      fprintf(stderr, "malformed ELF: multiple SHT_DYNSYM sections\n");
      return 1;
    }

    Dyn.Symbols = Elf_Sym_Range(
        reinterpret_cast<const Elf_Sym *>(E.base() + Sec.sh_offset),
        reinterpret_cast<const Elf_Sym *>(E.base() + Sec.sh_offset +
                                          Sec.sh_size));

    Dyn.Found = true;
  }

  if (!Dyn.Found) {
    fprintf(stderr, "error: failed to find SHT_DYNSYM section\n");
    return 1;
  }

  if (Dyn.Symbols.empty()) {
    write_decompilation();
    return 0;
  }

  disas_t dis(*DisAsm, std::cref(*STI), *IP);

  //
  // iterate dynamic (!undefined) functions
  //
  for (const Elf_Sym &Sym : Dyn.Symbols) {
    if (Sym.getType() != llvm::ELF::STT_FUNC)
      continue;

    if (Sym.isUndefined())
      continue;

    translate_function(binary, tcg, dis, Sym.st_value);
  }

  putchar('\n');

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

  printf("%lx ", Addr);

  auto sectit = sectm.find(Addr);
  if (sectit == sectm.end()) {
    fprintf(stderr, "error: bad address (0x%lx)\n", Addr);
    abort();
  }
  const section_properties_t &sectprop = *(*sectit).second.begin();
  tcg.set_section((*sectit).first.lower(), sectprop.contents.data());

  unsigned Size;
  jove::terminator_info_t T;
  std::tie(Size, T) = tcg.translate(Addr);

  if (T.Type == TERMINATOR::UNKNOWN) {
    fprintf(stderr, "error: bad terminator @ %#lx\n", Addr);
    abort();
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

    basic_block_t succ = boost::vertex(succidx, binary.Analysis.ICFG);
    boost::add_edge(bb, succ, binary.Analysis.ICFG);
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
    function_index_t f_idx =
        translate_function(binary, tcg, dis, T._call.Target);

    {
      basic_block_properties_t &bbprop = binary.Analysis.ICFG[bb];
      std::vector<function_index_t> &Callees = bbprop.Term.Callees.Local;

      if (!std::binary_search(Callees.begin(), Callees.end(), f_idx)) {
        Callees.push_back(f_idx);
        std::sort(Callees.begin(), Callees.end());
      }
    }

    control_flow(T._call.NextPC);
    break;
  }

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

int parse_command_line_arguments(int argc, char **argv) {
  fs::path &ifp = cmdline.input;
  fs::path &ofp = cmdline.output;
  bool &verbose = cmdline.verbose;

  try {
    po::options_description desc("Allowed options");
    desc.add_options()
      ("help,h", "produce help message")

      ("input,i", po::value<fs::path>(&ifp),
       "input binary")

      ("output,o", po::value<fs::path>(&ofp),
       "output file path")

      ("verbose,v", po::value<bool>(&verbose)->default_value(false),
       "be verbose");

    po::positional_options_description p;
    p.add("input", -1);

    po::variables_map vm;
    po::store(
        po::command_line_parser(argc, argv).options(desc).positional(p).run(),
        vm);
    po::notify(vm);

    if (vm.count("help") || !vm.count("input") || !vm.count("output")) {
      printf("Usage: %s -o decompilation.jv binary\n", argv[0]);
      std::string desc_s;
      {
        std::ostringstream oss(desc_s);
        oss << desc;
      }
      puts(desc_s.c_str());
      return 1;
    }

    if (!fs::exists(ifp)) {
      fprintf(stderr, "given input %s does not exist\n", ifp.string().c_str());
      return 1;
    }
  } catch (std::exception &e) {
    fprintf(stderr, "%s\n", e.what());
    return 1;
  }

  return 0;
}

bool verify_arch(const obj::ObjectFile &Obj) {
#if defined(TARGET_X86_64)
  const llvm::Triple::ArchType archty = llvm::Triple::ArchType::x86_64;
#elif defined(TARGET_AARCH64)
  const llvm::Triple::ArchType archty = llvm::Triple::ArchType::aarch64;
#else
#error "unknown architecture"
#endif

  return Obj.getArch() == archty;
}

}
