#include "symbolizer.h"
#include "process.h"
#include "pipe.h"

#include <llvm/DebugInfo/Symbolize/Symbolize.h>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/algorithm/string.hpp>

namespace fs = boost::filesystem;
namespace obj = llvm::object;

namespace jove {

typedef boost::format fmt;

template <bool MT, bool MinSize>
symbolizer_base_t<MT, MinSize>::symbolizer_base_t(const jv_t &jv, locator_t &locator, bool Addr2Line)
  : locator(locator), Addr2Line(Addr2Line), state(jv) {
  llvm::symbolize::LLVMSymbolizer::Options Opts;
  Opts.PrintFunctions = llvm::symbolize::FunctionNameKind::ShortName;
  Opts.UseSymbolTable = true;
  Opts.Demangle = false;
  Opts.RelativeAddresses = true;

  Symbolizer = std::make_unique<llvm::symbolize::LLVMSymbolizer>(Opts);
}

template <bool MT, bool MinSize>
symbolizer_base_t<MT, MinSize>::~symbolizer_base_t() {}

template <bool MT, bool MinSize>
std::string symbolizer_base_t<MT, MinSize>::addr2line(
    const binary_base_t<MT, MinSize> &b, uint64_t Addr) {
  if (!b.is_file())
    return std::string();
  auto &x = state.for_binary(b);

  const auto &omap = x.cb.second.omap;
  const auto &amap = x.cb.second.omap;
  auto ait = intvl_map_find(amap, Addr);

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
          B::is_coff(x.cb.first.get())
              ? locator.mingw_addr2line(IsTarget32)
              : locator.addr2line();

      pid_t child = RunExecutable(
          path_to_addr2line,
          [&](auto Arg) {
            Arg(path_to_addr2line);
            Arg("-e");
            Arg(b.Name.c_str());
            Arg("-f");

            const auto off = B::cached::offset_of_va(x.cb, Addr);
            auto oit = intvl_map_find(omap, off);
            if (oit == omap.end()) {
              Arg((fmt("0x%" PRIx64) % Addr).str());
            } else {
              const unsigned idx = (*oit).second;
              auto &section = x.cb.second.svec[idx];
              Arg("--section=" + section.Name.str());
              Arg((fmt("0x%" PRIx64) % (off - section.off())).str());
            }
          },
          "", "",
          [&](const char **argv, const char **envp) {

#if 0
  for (const char **argp = argv; *argp; ++argp) {
  llvm::errs() << *argp;

    if (*(argp + 1))
      llvm::errs() << ' ';
  }

  llvm::errs() << '\n';
#endif

            rfd.close();
            (void)robust::dup2(wfd.get(), STDOUT_FILENO);
            (void)robust::dup2(wfd.get(), STDERR_FILENO);
            wfd.close();
          });

      wfd.close();

      pipe_reader pipe(rfd.get());
      A2LOutput = pipe.get();

      WaitForProcessToExit(child);

      boost::algorithm::trim_if(A2LOutput, [](char ch) -> bool {
        return ch == ' ' || ch == '\n' || ch == '\t';
      });

      std::string fnnm;
      const auto nl_pos = A2LOutput.find('\n');
      if (nl_pos != std::string::npos) {
        const auto nl_it = std::next(A2LOutput.begin(), nl_pos);
        aassert(std::distance(nl_it, A2LOutput.end()) > 0);

        fnnm = A2LOutput.substr(0, nl_pos);
        A2LOutput = A2LOutput.substr(nl_pos+1);

#if 0
      if (boost::algorithm::starts_with(A2LOutput, "??\n"))
        A2LOutput = A2LOutput.substr(3);
#endif
      }

      const bool res = !boost::algorithm::ends_with(A2LOutput, ":?") &&
          A2LOutput != "??:?" &&
          A2LOutput != "??:0" &&
          A2LOutput != ":?" &&
          A2LOutput != "fake:" &&
          A2LOutput != "fake:?";

      if (res && !fnnm.empty())
        A2LOutput.append(" <" + fnnm + '>');
      res;
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

  obj::SectionedAddress TheSectionedAddress;
  if (ait == amap.end()) {
    TheSectionedAddress = {Addr, llvm::object::SectionedAddress::UndefSection};
  } else {
    const unsigned idx = (*ait).second;
    auto &section = x.cb.second.svec[idx];
    TheSectionedAddress = {Addr - section.addr(), idx};
  }

  llvm::Expected<llvm::DILineInfo> LineInfoOrErr = ({
    /* NOTE: LLVMSymbolizer is not thread-safe (it caches binaries). */
    std::unique_lock<std::mutex> lck(mtx);
    Symbolizer->symbolizeCode(b.path_str(), TheSectionedAddress);
  });

  if (LineInfoOrErr) {
    llvm::DILineInfo LnInfo = *LineInfoOrErr;

    if (LnInfo.FileName == llvm::DILineInfo::BadString) {
      if (!this->Addr2Line) {
        bool IsA2LOutputValid;
        std::string A2LOutput;
        std::tie(IsA2LOutputValid, A2LOutput) = do_addr2line();

        if (IsA2LOutputValid)
          return A2LOutput;
      }
    } else {
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

      std::string res = sourcePath.string() + ":" + line_desc + ":" + col_desc;
      if (LnInfo.FunctionName != llvm::DILineInfo::BadString)
        res.append(" <" + LnInfo.FunctionName + '>');
      return res;
    }
  } else {
    std::string Buf;
    {
      llvm::raw_string_ostream OS(Buf);
      llvm::logAllUnhandledErrors(LineInfoOrErr.takeError(), OS, "");
    }
#if 0
    return std::string();
#endif
  }

  if (ait != amap.end()) {
    const char *nm = b.Name.c_str();

    if (b.is_file()) {
      auto &shortnm = x.shortnm;
      if (shortnm.empty())
        shortnm = fs::path(b.Name.c_str()).filename().string();
      nm = shortnm.c_str();
    }

    const unsigned idx = (*ait).second;
    auto &section = x.cb.second.svec[idx];
    return nm +
         ('[' + std::string(section.Name) + '+')
         + taddr2str(Addr - section.addr(), false) + ']';
  }

  return {};
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
