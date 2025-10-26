#include "tool.h"
#include "jove.constants.h"
#include "mmap.h"
#include "B.h"

#include <boost/filesystem.hpp>

#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

#include <regex>

namespace cl = llvm::cl;
namespace fs = boost::filesystem;

using llvm::WithColor;

namespace jove {

namespace {

struct binary_state_t {
  B::unique_ptr Bin;
  binary_state_t(const auto &b) { Bin = B::Create(b.data()); }
};

}

class CallStackTool
    : public StatefulJVTool<ToolKind::CopyOnWrite, binary_state_t, void, void> {
  struct Cmdline {
    cl::opt<bool> Offsets;
    cl::alias OffsetsAlias;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Offsets("offsets",
                  cl::desc("Print in offsets rather than virtual addresses"),
                  cl::cat(JoveCategory)),

          OffsetsAlias("o", cl::desc("Alias for --offsets."),
                       cl::aliasopt(Offsets), cl::cat(JoveCategory)) {}

  } opts;

public:
  CallStackTool() : opts(JoveCategory) {}

  int Run(void) override;

  void FindCallStackFiles(const fs::path &dir, const char *env,
                          std::vector<unsigned> &tidvec);

  taddr_t AddrOrOff(const binary_t &binary, taddr_t);
};

JOVE_REGISTER_TOOL("callstack", CallStackTool);

int CallStackTool::Run(void) {
  char *env = getenv("JOVECALLS");
  if (!env || strlen(env) == 0) {
    WithColor::error() << "$JOVECALLS is empty\n";
    return 1;
  }

  //
  // we need to look for any files of the form ${JOVECALLS}.*
  //
  fs::path dir = fs::path(env).parent_path();
  if (!fs::exists(dir) || !fs::is_directory(dir)) {
    WithColor::error() << "invalid $JOVECALLS\n";
    return 1;
  }

  std::vector<unsigned> tidvec;
  FindCallStackFiles(dir, env, tidvec);

  if (tidvec.empty()) {
    if (IsVerbose())
      HumanOut() << "no callstack files found\n";
    return 0;
  }

  std::for_each(
      maybe_par_unseq, /* CoW map ASAP */
      tidvec.begin(),
      tidvec.end(),
      [&](unsigned tid) {
        std::string filepath = std::string(env) + "." + std::to_string(tid);
        assert(fs::exists(filepath) && fs::is_regular_file(filepath));

        scoped_fd fd(::open(filepath.c_str(), O_RDONLY));
        if (!fd) {
          int err = errno;
          WithColor::error() << llvm::formatv(
              "failed to open callstack file: {0}\n", strerror(err));
          return;
        }

        scoped_mmap mapping(NULL, JOVE_CALLSTACK_SIZE, PROT_READ, MAP_PRIVATE,
                            fd.get(), 0);
        if (!mapping) {
          int err = errno;
          WithColor::error() << llvm::formatv(
              "failed to open callstack file: {0}\n", strerror(err));
          return;
        }

        const uint64_t *ptr = reinterpret_cast<const uint64_t *>(mapping.get());
        ptr += (JOVE_PAGE_SIZE / sizeof(uint64_t));

        if (!ptr[0])
          return;

        static std::mutex mtx;
        {
          std::unique_lock<std::mutex> lck(mtx);

          HumanOut() << llvm::formatv("==== thread {0} ====\n", tid);

          for (; *ptr; ++ptr) {
            uint64_t X = *ptr;

            binary_index_t      BIdx  = X >> 32;
            basic_block_index_t BBIdx = X & 0xffffffff;

#if 0
            if (IsVerbose())
              HumanOut() << llvm::formatv("JV_{0}_{1}\n", BIdx, BBIdx);
#endif

            if (is_binary_index_valid(BIdx) &&
                is_basic_block_index_valid(BBIdx)) {
              auto &b = jv.Binaries.at(BIdx);
              auto &ICFG = b.Analysis.ICFG;
              bb_t bb = basic_block_of_index(BBIdx, ICFG);
              taddr_t x = ICFG[bb].Addr;

              llvm::outs() << llvm::formatv(
                  "{0}:{1:x}\n",
                  b.is_file() ? fs::path(b.path_str()).filename().c_str()
                              : b.Name.c_str(),
                  AddrOrOff(b, x));
            } else {
              llvm::outs() << "...\n";
            }
          }
        }
      });

  return 0;
}

void CallStackTool::FindCallStackFiles(const fs::path &dir,
                                       const char *env,
                                       std::vector<unsigned> &tidvec) {
  std::regex pattern("^" + std::regex_replace(env, std::regex("\\."), "\\.") +
                     "\\.(\\d+)$");

  for (auto &entry : fs::directory_iterator(dir)) {
    std::smatch match;
    std::string filename = entry.path().string();
    if (std::regex_match(filename, match, pattern)) {
      if (match.size() == 2) {
        tidvec.push_back(std::stoul(match[1].str()));
        if (IsVeryVerbose())
          HumanOut() << llvm::formatv("Found: {0}\n", entry.path().string());
      }
    }
  }
}

taddr_t CallStackTool::AddrOrOff(const binary_t &b, taddr_t Addr) {
  if (opts.Offsets)
    return B::offset_of_va(state.for_binary(b).Bin.get(), Addr);

  return Addr;
}

}
