#include "symbolizer.h"
#include <llvm/DebugInfo/Symbolize/Symbolize.h>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>

namespace fs = boost::filesystem;

namespace jove {

typedef boost::format fmt;

symbolizer_t::symbolizer_t() {
  llvm::symbolize::LLVMSymbolizer::Options Opts;
  Opts.PrintFunctions = llvm::symbolize::FunctionNameKind::None;
  Opts.UseSymbolTable = false;
  Opts.Demangle = false;
  Opts.RelativeAddresses = true;

  Symbolizer = std::make_unique<llvm::symbolize::LLVMSymbolizer>(Opts);
}

symbolizer_t::~symbolizer_t() {}

std::string symbolizer_t::addr2line(const binary_t &binary, tcg_uintptr_t Addr) {
  llvm::symbolize::LLVMSymbolizer::Options Opts;
  Opts.PrintFunctions = llvm::symbolize::FunctionNameKind::None;
  Opts.UseSymbolTable = false;
  Opts.Demangle = false;
  Opts.RelativeAddresses = true;
#if 0
Opts.FallbackDebugPath = ""; // ClFallbackDebugPath
Opts.DebugFileDirectory = ""; // ClDebugFileDirectory;
#endif

  auto ResOrErr = Symbolizer->symbolizeCode(
      binary.Path,
      {Addr, llvm::object::SectionedAddress::UndefSection});
  if (!ResOrErr)
    return std::string();

  llvm::DILineInfo &LnInfo = ResOrErr.get();

  if (LnInfo.FileName == llvm::DILineInfo::BadString)
    return std::string();

  fs::path sourcePath = LnInfo.FileName;

  if (fs::path(sourcePath).is_relative())
    sourcePath = fs::path("/usr/src/debug") /
                 fs::path(binary.Path).stem() /
                 LnInfo.FileName;

  if (fs::exists(sourcePath))
    sourcePath = fs::canonical(sourcePath);

  return sourcePath.string() +
         ":" + std::to_string(LnInfo.Line) +
	 ":" + std::to_string(LnInfo.Column);
}

std::string symbolizer_t::addr2desc(const binary_t &binary, tcg_uintptr_t Addr) {
  if (Addr == 0 || ~Addr == 0)
    return "??";

  std::string desc =
    (fmt("%s+0x%08x")
     % fs::path(binary.Path).filename().string()
     % Addr).str();

  std::string src_desc(addr2line(binary, Addr));

  if (!src_desc.empty())
    return desc + " [" + src_desc + "]";
  else
    return desc;
}

}
