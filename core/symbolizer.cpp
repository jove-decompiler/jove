#include "symbolizer.h"
#include "process.h"

#include <llvm/DebugInfo/Symbolize/Symbolize.h>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>

namespace fs = boost::filesystem;

namespace jove {

typedef boost::format fmt;

symbolizer_t::symbolizer_t(locator_t &locator, bool Addr2Line)
  : locator(locator), Addr2Line(Addr2Line) {
  llvm::symbolize::LLVMSymbolizer::Options Opts;
  Opts.PrintFunctions = llvm::symbolize::FunctionNameKind::None;
  Opts.UseSymbolTable = false;
  Opts.Demangle = false;
  Opts.RelativeAddresses = true;

  Symbolizer = std::make_unique<llvm::symbolize::LLVMSymbolizer>(Opts);
}

symbolizer_t::~symbolizer_t() {}

template <bool MT, bool MinSize>
std::string symbolizer_t::addr2line(const binary_base_t<MT, MinSize> &binary,
                                    uint64_t Addr) {
  if (Addr2Line) {
    std::string path_to_stdout = "/tmp/stdout";
    std::string path_to_stderr = "/tmp/stderr";

    RunExecutableToExit(locator.mingw_addr2line(IsTarget32),
                        [&](auto Arg) {
                          Arg(locator.mingw_addr2line(IsTarget32));
                          Arg("-e");
                          Arg(binary.Name.c_str());
                          Arg((fmt("0x%" PRIx64) % Addr).str());
                        },
                        path_to_stdout ,
                        path_to_stderr);
    return read_file_into_string(path_to_stdout.c_str());
  }

  if (!binary.is_file())
    return std::string();

  llvm::DILineInfo LnInfo;
  {
  // LLVMSymbolizer is *not* thread-safe. It caches binaries.
  std::unique_lock<std::mutex> lck(mtx);

  auto ResOrErr = Symbolizer->symbolizeCode(
      binary.path_str(),
      {Addr, llvm::object::SectionedAddress::UndefSection});
  if (!ResOrErr) {
    std::string Buf;
    {
      llvm::raw_string_ostream OS(Buf);
      llvm::logAllUnhandledErrors(ResOrErr.takeError(), OS, "");
    }
    return std::string();
  }
  LnInfo = ResOrErr.get();
  }

  if (LnInfo.FileName == llvm::DILineInfo::BadString)
    return std::string();

  fs::path sourcePath = LnInfo.FileName;

#if 0
  if (fs::path(sourcePath).is_relative())
    sourcePath = /* fs::path("/usr/src/debug") / */
                 fs::path(binary.path_str()).stem() /
                 LnInfo.FileName;
  else
    sourcePath = fs::path(LnInfo.FileName).filename();
#endif

  if (fs::exists(sourcePath))
    sourcePath = fs::canonical(sourcePath);
  else
    sourcePath = sourcePath.lexically_normal();

  return sourcePath.string() +
         ":" + std::to_string(LnInfo.Line) +
	 ":" + std::to_string(LnInfo.Column);
}

template <bool MT, bool MinSize>
std::string symbolizer_t::addr2desc(const binary_base_t<MT, MinSize> &binary,
                                    uint64_t Addr) {
  if (Addr == 0 || ~Addr == 0)
    return "??";

  std::string desc =
    (fmt("%s:0x%08x")
     % fs::path(binary.path_str()).filename().string()
     % Addr).str();

  std::string src_desc(addr2line<MT>(binary, Addr));

  if (!src_desc.empty())
    return desc + " [" + src_desc + "]";
  else
    return desc;
}

#define VALUES_TO_INSTANTIATE_WITH1                                            \
    ((true))                                                                   \
    ((false))
#define VALUES_TO_INSTANTIATE_WITH2                                            \
    ((true))                                                                   \
    ((false))
#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)

#define DO_INSTANTIATE(r, product)                                             \
  template std::string                                                         \
  symbolizer_t::addr2desc<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),            \
                          GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))>(           \
      const binary_base_t<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),            \
                          GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))> &,         \
      uint64_t Addr);                                                          \
  template std::string                                                         \
  symbolizer_t::addr2line<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),            \
                          GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))>(           \
      const binary_base_t<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),            \
                          GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))> &,         \
      uint64_t Addr);
BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_INSTANTIATE, (VALUES_TO_INSTANTIATE_WITH1)(VALUES_TO_INSTANTIATE_WITH2))

}
