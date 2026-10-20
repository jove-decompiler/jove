#include "symbolizer.h"
#include "process.h"
#include "pipe.h"

#include <llvm/DebugInfo/Symbolize/Symbolize.h>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/algorithm/string.hpp>

namespace fs = boost::filesystem;

namespace jove {

typedef boost::format fmt;

template <bool MT, bool MinSize>
symbolizer_base_t<MT, MinSize>::symbolizer_base_t(const jv_t &jv, locator_t &locator, bool Addr2Line)
  : locator(locator), Addr2Line(Addr2Line), state(jv) {
  llvm::symbolize::LLVMSymbolizer::Options Opts;
  Opts.PrintFunctions = llvm::symbolize::FunctionNameKind::None;
  Opts.UseSymbolTable = false;
  Opts.Demangle = false;
  Opts.RelativeAddresses = true;

  Symbolizer = std::make_unique<llvm::symbolize::LLVMSymbolizer>(Opts);
}

template <bool MT, bool MinSize>
symbolizer_base_t<MT, MinSize>::~symbolizer_base_t() {}

template <bool MT, bool MinSize>
std::string
symbolizer_base_t<MT, MinSize>::addr2line(const binary_base_t<MT, MinSize> &binary,
                                     uint64_t Addr) {
  if (!binary.is_file())
    return std::string();

  auto do_addr2line = [&](void) -> std::pair<bool, std::string> {
    std::string A2LOutput;
    bool IsA2LOutputValid = ({
      int pipefd[2];
      if (::pipe(pipefd) < 0)
        throw std::runtime_error("pipe failed: " +
                                 std::string(strerror(errno)));

      scoped_fd rfd(pipefd[0]);
      scoped_fd wfd(pipefd[1]);

      const std::string path_to_addr2line =
          B::is_coff(state.for_binary(binary).Bin.get())
              ? locator.mingw_addr2line(IsTarget32)
              : locator.addr2line();

      pid_t child = RunExecutable(
          path_to_addr2line,
          [&](auto Arg) {
            Arg(path_to_addr2line);
            Arg("-e");
            Arg(binary.Name.c_str());
            Arg((fmt("0x%" PRIx64) % Addr).str());
          },
          "", "",
          [&](const char **argv, const char **envp) {
            rfd.close();
            (void)robust::dup2(wfd.get(), STDOUT_FILENO);
            (void)robust::dup2(wfd.get(), STDERR_FILENO);
            wfd.close();
          });

      BOOST_SCOPE_DEFER[&] { WaitForProcessToExit(child); };

      wfd.close();

      pipe_reader pipe(rfd.get());
      A2LOutput = pipe.get();

      boost::algorithm::trim_if(A2LOutput, [](char ch) -> bool {
        return ch == ' ' || ch == '\n' || ch == '\t';
      });

      A2LOutput != "??:?" && A2LOutput != "??:0" && A2LOutput != ":?" &&
          A2LOutput != "fake:" && A2LOutput != "fake:?";
    });


    return std::make_pair(IsA2LOutputValid, A2LOutput);
  };

  if (this->Addr2Line) {
    bool IsA2LOutputValid;
    std::string A2LOutput;
    std::tie(IsA2LOutputValid, A2LOutput) = do_addr2line();

    if (IsA2LOutputValid)
      return A2LOutput;
  }

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

  if (LnInfo.FileName == llvm::DILineInfo::BadString) {
    bool IsA2LOutputValid;
    std::string A2LOutput;
    std::tie(IsA2LOutputValid, A2LOutput) = do_addr2line();

    if (IsA2LOutputValid)
      return A2LOutput;

    return std::string();
  }

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

  std::string line_desc = std::to_string(LnInfo.Line);
  std::string col_desc = std::to_string(LnInfo.Column);

  boost::trim(line_desc);
  boost::trim(col_desc);

  return sourcePath.string() + ":" + line_desc + ":" + col_desc;
}

template <bool MT, bool MinSize>
std::string
symbolizer_base_t<MT, MinSize>::addr2desc(const binary_base_t<MT, MinSize> &binary,
                                     uint64_t Addr) {
  if (Addr == 0 || ~Addr == 0)
    return "??";

  std::string desc =
    (fmt("%s:0x%08x")
     % fs::path(binary.path_str()).filename().string()
     % Addr).str();

  std::string src_desc(addr2line(binary, Addr));

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
  template class symbolizer_base_t<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),   \
                                   GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))>;
BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_INSTANTIATE, (VALUES_TO_INSTANTIATE_WITH1)(VALUES_TO_INSTANTIATE_WITH2))

}
