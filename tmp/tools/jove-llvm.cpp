#include "tcgcommon.hpp"

#include <memory>
#include <sstream>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
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

namespace fs = boost::filesystem;
namespace po = boost::program_options;
namespace obj = llvm::object;

namespace jove {
static struct {
  fs::path input;
  fs::path output;

  bool noopt;
  bool well_behaved; /* XXX? */
} cmdline;

void parse_command_line_arguments(int argc, char **argv);

static void verify_arch(const obj::ObjectFile &);
static void print_obj_info(const obj::ObjectFile &);
}

int main(int argc, char **argv) {
  llvm::StringRef ToolName = argv[0];
  llvm::sys::PrintStackTraceOnErrorSignal(ToolName);
  llvm::PrettyStackTraceProgram X(argc, argv);
  llvm::llvm_shutdown_obj Y;

  jove::parse_command_line_arguments(argc, argv);

  jove::tiny_code_generator_t tcg;

  // Initialize targets and assembly printers/parsers.
  llvm::InitializeAllTargetInfos();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllDisassemblers();

  llvm::Expected<obj::OwningBinary<obj::Binary>> BinaryOrErr =
      obj::createBinary(jove::cmdline.input.string());

  if (!BinaryOrErr ||
      !llvm::isa<obj::ObjectFile>(BinaryOrErr.get().getBinary())) {
    fprintf(stderr, "failed to open %s\n", argv[1]);
    return 1;
  }

  obj::ObjectFile &O =
      *llvm::cast<obj::ObjectFile>(BinaryOrErr.get().getBinary());

  jove::verify_arch(O);
  jove::print_obj_info(O);

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

  llvm::LLVMContext C;
  llvm::Module M(jove::cmdline.output.stem().string(), C);
  M.setTargetTriple(TheTriple.normalize());

  {
    std::error_code ec;
    llvm::raw_fd_ostream os(jove::cmdline.output.string(), ec,
                            llvm::sys::fs::F_None);

    if (ec)
      return 1;

    llvm::WriteBitcodeToFile(M, os);
  }

  return 0;
}

namespace jove {

void parse_command_line_arguments(int argc, char **argv) {
  fs::path &ifp = cmdline.input;
  fs::path &ofp = cmdline.output;
  bool &noopt = cmdline.noopt;
  bool &well_behaved = cmdline.well_behaved;

  noopt = false;
  well_behaved = false;

  try {
    po::options_description desc("Allowed options");
    desc.add_options()
      ("help,h", "produce help message")

      ("input,i", po::value<fs::path>(&ifp),
       "input binary")

      ("output,o", po::value<fs::path>(&ofp),
       "output bitcode file path")

      ("noopt,s", po::value<bool>(&noopt),
       "produce unoptimized LLVM")

      ("well-behaved,w", po::value<bool>(&well_behaved),
       "the given code conforms to the ABI calling convention");

    po::positional_options_description p;
    p.add("input", -1);

    po::variables_map vm;
    po::store(
        po::command_line_parser(argc, argv).options(desc).positional(p).run(),
        vm);
    po::notify(vm);

    if (vm.count("help") || !vm.count("input") || !vm.count("output")) {
      printf("Usage: %s [-o output] binary\n", argv[0]);
      std::string desc_s;
      {
        std::ostringstream oss(desc_s);
        oss << desc;
      }
      printf("%s", desc_s.c_str());
      exit(1);
    }

    if (!fs::exists(ifp)) {
      fprintf(stderr, "given input %s does not exist\n", ifp.string().c_str());
      exit(1);
    }

    if (!vm.count("output")) {
      ofp = ifp;
      ofp.replace_extension("jv");
      ofp = ofp.filename();
    }
  } catch (std::exception &e) {
    fprintf(stderr, "%s\n", e.what());
    exit(1);
  }
}

void verify_arch(const obj::ObjectFile &Obj) {
#if defined(TARGET_X86_64)
  const llvm::Triple::ArchType archty = llvm::Triple::ArchType::x86_64;
#elif defined(TARGET_AARCH64)
  const llvm::Triple::ArchType archty = llvm::Triple::ArchType::aarch64;
#else
#error "unknown architecture"
#endif

  if (Obj.getArch() != archty) {
    fprintf(stderr, "error: architecture mismatch\n");
    exit(1);
  }
}

void print_obj_info(const obj::ObjectFile &Obj) {
  printf("File: %s\n"
         "Format: %s\n"
         "Arch: %s\n"
         "AddressSize: %ubit\n",
         Obj.getFileName().str().c_str(), Obj.getFileFormatName().str().c_str(),
         llvm::Triple::getArchTypeName(Obj.getArch()).str().c_str(),
         8 * Obj.getBytesInAddress());
}

}
