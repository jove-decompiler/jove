#include <jove/jove.h>

#include <llvm/Support/CommandLine.h>
#include <llvm/Support/DataTypes.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/WithColor.h>

#include <fstream>
#include <algorithm>
#include <boost/filesystem.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <boost/serialization/bitset.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/format.hpp>
#include <sys/wait.h>

namespace fs = boost::filesystem;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace opts {
static cl::OptionCategory JoveCategory("Specific Options");

static cl::list<std::string>
    InputFilenames(cl::Positional, cl::desc("<input jove decompilations>"),
                   cl::OneOrMore, cl::cat(JoveCategory));

} // namespace opts

namespace jove {

static int await_process_completion(pid_t);

typedef boost::format fmt;

static void invalidateInput(const std::string &Path) {
  bool git = fs::is_directory(Path);

  decompilation_t Decompilation;
  {
    std::ifstream ifs(git ? Path + "/decompilation.jv" : Path);

    boost::archive::binary_iarchive ia(ifs);
    ia >> Decompilation;
  }

  // invalidate all function analyses
  for (binary_t &binary : Decompilation.Binaries)
    for (function_t &f : binary.Analysis.Functions)
      f.InvalidateAnalysis();

  //
  // write decompilation
  //
  {
    std::ofstream ofs(git ? Path + "/decompilation.jv" : Path);

    boost::archive::binary_oarchive oa(ofs);
    oa << Decompilation;
  }

  //
  // git commit
  //
  if (git) {
    pid_t pid = fork();
    if (!pid) { /* child */
      chdir(Path.c_str());

      const char *argv[] = {
	"/usr/bin/git",
	"commit", ".",
	"-m", "[jove-invalidate]",
	nullptr
      };

      execve(argv[0], const_cast<char **>(&argv[0]), ::environ);

      int err = errno;
      WithColor::error() << llvm::formatv("execve failed ({0})\n",
                                          strerror(err));
      abort();
    }

    (void)await_process_completion(pid);
  }
}

int await_process_completion(pid_t pid) {
  int wstatus;
  do {
    if (waitpid(pid, &wstatus, WUNTRACED | WCONTINUED) < 0)
      abort();

    if (WIFEXITED(wstatus)) {
      printf("exited, status=%d\n", WEXITSTATUS(wstatus));
      return WEXITSTATUS(wstatus);
    } else if (WIFSIGNALED(wstatus)) {
      printf("killed by signal %d\n", WTERMSIG(wstatus));
      return 1;
    } else if (WIFSTOPPED(wstatus)) {
      printf("stopped by signal %d\n", WSTOPSIG(wstatus));
      return 1;
    } else if (WIFCONTINUED(wstatus)) {
      printf("continued\n");
    }
  } while (!WIFEXITED(wstatus) && !WIFSIGNALED(wstatus));

  abort();
}

}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::HideUnrelatedOptions({&opts::JoveCategory, &llvm::ColorCategory});
  cl::ParseCommandLineOptions(argc, argv, "Jove Invalidate\n");

  for (const std::string &Path : opts::InputFilenames) {
    if (!fs::exists(Path)) {
      WithColor::error() << Path << " does not exist\n";
      return 1;
    }
  }

  llvm::for_each(opts::InputFilenames, jove::invalidateInput);

  return 0;
}
