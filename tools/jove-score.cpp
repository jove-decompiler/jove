#include "tool.h"
#include "score.h"
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <thread>

namespace cl = llvm::cl;
namespace fs = boost::filesystem;

//using llvm::WithColor;

namespace jove {

class ScoreTool : public Tool {
  struct Cmdline {
    cl::opt<std::string> jv;
    cl::alias jvAlias;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
     :    jv("Decompilation", cl::desc("Jove Decompilation"), cl::Required,
             cl::value_desc("filename"), cl::cat(JoveCategory)),

          jvAlias("d", cl::desc("Alias for -Decompilation."), cl::aliasopt(jv),
                  cl::cat(JoveCategory)) {}
  } opts;

  decompilation_t decompilation;

public:
  ScoreTool() : opts(JoveCategory) {}

  int Run(void);
};

JOVE_REGISTER_TOOL("score", ScoreTool);

typedef boost::format fmt;

int ScoreTool::Run(void) {
  bool git = fs::is_directory(opts.jv);
  std::string jvfp = git ? (opts.jv + "/decompilation.jv") : opts.jv;

  ReadDecompilationFromFile(jvfp, decompilation);

  for_each_binary(decompilation, [&](binary_t &binary) {
    if (binary.IsVDSO)
      return;

    binary_index_t BIdx = index_of_binary(binary, decompilation);
    HumanOut() << (fmt("%5f %s\n")
                   % compute_score(decompilation, BIdx)
                   % binary.Path).str();
  });

  return 0;
}

}

