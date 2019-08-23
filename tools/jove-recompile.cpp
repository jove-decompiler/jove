#include <unistd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sched.h>
#include <tuple>
#include <thread>
#include <chrono>
#include <memory>
#include <mutex>
#include <queue>
#include <sstream>
#include <fstream>
#include <boost/filesystem.hpp>
#include <boost/dll/runtime_symbol_info.hpp>
#include <llvm/ADT/StringRef.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/WithColor.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "jove/jove.h"
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/serialization/bitset.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/set.hpp>
#include <boost/graph/adj_list_serialize.hpp>

namespace fs = boost::filesystem;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {
static unsigned num_cpus(void);
}

namespace opts {
static cl::OptionCategory JoveCategory("Specific Options");

static cl::opt<std::string> jv("decompilation", cl::desc("Jove decompilation"),
                               cl::Required, cl::cat(JoveCategory));

static cl::alias jvAlias("d", cl::desc("Alias for -decompilation."),
                         cl::aliasopt(jv), cl::cat(JoveCategory));

static cl::opt<std::string> Output("output", cl::desc("Output directory"),
                                   cl::Required, cl::cat(JoveCategory));

static cl::alias OutputAlias("o", cl::desc("Alias for -output."),
                             cl::aliasopt(Output), cl::cat(JoveCategory));

static cl::opt<unsigned> Threads("num-threads",
                                 cl::desc("Number of CPU threads to use (hack)"),
                                 cl::init(1 /* jove::num_cpus() */),
                                 cl::cat(JoveCategory));

static cl::opt<bool>
    Trace("trace",
          cl::desc("Instrument code to output basic block execution trace"),
          cl::cat(JoveCategory));

static cl::opt<bool>
    NoOpt("no-opt",
          cl::desc("Don't optimize bitcode any further"),
          cl::cat(JoveCategory));

static cl::opt<bool>
    Verbose("verbose",
            cl::desc("Print extra information for debugging purposes"),
            cl::cat(JoveCategory));

static cl::alias VerboseAlias("v", cl::desc("Alias for -verbose."),
                              cl::aliasopt(Verbose), cl::cat(JoveCategory));
} // namespace opts

namespace jove {
static int recompile(void);
}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::HideUnrelatedOptions({&opts::JoveCategory, &llvm::ColorCategory});
  cl::ParseCommandLineOptions(argc, argv, "Jove Recompile\n");

  return jove::recompile();
}

namespace jove {

static decompilation_t Decompilation;

static void spawn_workers(void);

static std::queue<unsigned> Q;
static char tmpdir[] = {'/', 't', 'm', 'p', '/', 'X',
                        'X', 'X', 'X', 'X', 'X', '\0'};
static const char *compiler_runtime_afp =
    "/usr/lib/clang/10.0.0/lib/linux/libclang_rt.builtins-x86_64.a";

static int await_process_completion(pid_t);

static void print_command(const char **argv);

static std::string jove_llvm_path, llc_path, lld_path, opt_path;
static std::string dyn_linker_path;

static std::atomic<bool> Cancel(false);

static void handle_sigint(int);

int recompile(void) {
  if (!fs::exists(compiler_runtime_afp) ||
      !fs::is_regular_file(compiler_runtime_afp)) {
    WithColor::error() << "compiler runtime does not exist at path '"
                       << compiler_runtime_afp
                       << "' (or is not regular file)\n";
    return 0;
  }

  //
  // sanity checks for output path
  //
  if (fs::exists(opts::Output))
    fs::remove_all(opts::Output);

  if (!fs::create_directory(opts::Output)) {
    WithColor::error() << "failed to create directory at \"" << opts::Output
                       << "\"\n";
    return 1;
  }

  //
  // get paths to stuff
  //
  jove_llvm_path =
      (boost::dll::program_location().parent_path() / std::string("jove-llvm"))
          .string();
  if (!fs::exists(jove_llvm_path)) {
    WithColor::error() << "could not find jove-llvm at " << jove_llvm_path
                       << '\n';
    return 1;
  }

  llc_path = "/usr/bin/llc";
  if (!fs::exists(llc_path)) {
    WithColor::error() << "could not find /usr/bin/llc\n";
    return 1;
  }

  lld_path = "/usr/bin/ld.lld";
  if (!fs::exists(lld_path)) {
    WithColor::error() << "could not find /usr/bin/ld.lld\n";
    return 1;
  }

  opt_path = "/usr/bin/opt";
  if (!fs::exists(opt_path)) {
    WithColor::error() << "could not find /usr/bin/opt\n";
    return 1;
  }

  //
  // prepare to process the binaries by creating a unique temporary directory
  //
  if (!mkdtemp(tmpdir)) {
    WithColor::error() << "mkdtemp failed : " << strerror(errno) << '\n';
    return 1;
  }

  llvm::outs() << "tmpdir: " << tmpdir << '\n';

  fs::path jvpath(opts::jv);
  if (fs::is_directory(jvpath))
    jvpath /= "decompilation.jv";
  if (!fs::exists(jvpath) || fs::is_directory(jvpath))
    return 1;

  //
  // parse the existing decompilation file
  //
  {
    std::ifstream ifs(jvpath.string());

    boost::archive::binary_iarchive ia(ifs);
    ia >> Decompilation;
  }

  //
  // get path to dynamic linker
  //
  for (binary_t &b : Decompilation.Binaries) {
    if (!b.IsDynamicLinker)
      continue;

    dyn_linker_path = b.Path;
    break;
  }

  assert(!dyn_linker_path.empty());
  assert(fs::exists(dyn_linker_path));

  //
  // fill queue to process
  //
  for (unsigned BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    binary_t &b = Decompilation.Binaries[BIdx];
    if (b.IsDynamicLinker)
      continue;
    if (b.IsVDSO)
      continue;

    Q.push(BIdx);
  }

  // install signal handler for Ctrl-C to gracefully cancel
  {
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = handle_sigint;

    sigaction(SIGINT, &sa, nullptr);
  }

  spawn_workers();

  if (Cancel) {
    WithColor::note() << "Canceled.\n";
    return 1;
  }

  std::vector<fs::path> sofp_vec;
  for (binary_t &b : Decompilation.Binaries) {
    if (b.IsExecutable)
      continue;
    if (b.IsDynamicLinker)
      continue;
    if (b.IsVDSO)
      continue;

    sofp_vec.push_back(opts::Output + b.Path);
  }

  std::string exe_fp;
  std::string exe_objfp;
  for (binary_t &b : Decompilation.Binaries) {
    if (!b.IsExecutable)
      continue;

    exe_fp = opts::Output + b.Path;

    fs::path chrooted_path(opts::Output + b.Path);
    exe_objfp = chrooted_path.string() + ".o";

    break;
  }
  assert(!exe_objfp.empty());
  assert(!exe_fp.empty());

  pid_t pid = fork();
  if (!pid) {
    {
      struct sigaction sa;

      sigemptyset(&sa.sa_mask);
      sa.sa_flags = 0;
      sa.sa_handler = SIG_IGN;

      sigaction(SIGINT, &sa, nullptr);
    }

    std::vector<const char *> arg_vec = {
      lld_path.c_str(),
      "-o", exe_fp.c_str(),
      "-m", "elf_" ___JOVE_ARCH_NAME,
      "-dynamic-linker", dyn_linker_path.c_str(),
      "-pie",
      "-e", "__jove_start",
      "-nostdlib",
      "-z", "nodefaultlib",
      "-z", "origin",

      exe_objfp.c_str(),
      "--push-state",
      "--as-needed",
      compiler_runtime_afp,
      "--pop-state",
      dyn_linker_path.c_str()
    };

    for (const fs::path &sofp : sofp_vec) {
      // /path/to/libfoo.so -> "-lfoo"
      std::string &Ldir = *new std::string(sofp.parent_path().string());

      arg_vec.push_back("-L");
      arg_vec.push_back(Ldir.c_str());

      std::string &lStr = *new std::string(':' + sofp.filename().string());

      arg_vec.push_back("-l");
      arg_vec.push_back(lStr.c_str());

      std::string &rpathStr =
          *new std::string(std::string("-rpath=$ORIGIN/") +
                           fs::relative(sofp, fs::path(exe_fp).parent_path())
                               .parent_path()
                               .string());

      arg_vec.push_back(rpathStr.c_str());
    }

    arg_vec.push_back(nullptr);

    print_command(&arg_vec[0]);

    close(STDIN_FILENO);
    execve(arg_vec[0], const_cast<char **>(&arg_vec[0]), ::environ);
    return 0;
  }

  //
  // check exit code
  //
  if (int ret = await_process_completion(pid)) {
    WithColor::error() << "failed to link executable\n";
    return 1;
  }

  //
  // copy dynamic linker
  //
  for (binary_t &b : Decompilation.Binaries) {
    if (!b.IsDynamicLinker)
      continue;

    assert(fs::exists(b.Path) && fs::is_regular_file(b.Path));

    fs::path chrooted_path(opts::Output + b.Path);
    fs::create_directories(chrooted_path.parent_path());
    fs::copy(b.Path, chrooted_path);
    break;
  }

  return 0;
}

void handle_sigint(int no) {
  Cancel = true;
}

static std::mutex mtx;

static void worker(void) {
  auto pop_binary_index = [](unsigned &out) -> bool {
    std::lock_guard<std::mutex> lck(mtx);

    if (Q.empty()) {
      return false;
    } else {
      out = Q.front();
      Q.pop();
      return true;
    }
  };

  unsigned BIdx;
  while (!Cancel && pop_binary_index(BIdx)) {
    pid_t pid;

    binary_t &b = Decompilation.Binaries[BIdx];

    // make sure the path is absolute
    assert(b.Path.at(0) == '/');

    const fs::path chrooted_path(opts::Output + b.Path);

    fs::create_directories(chrooted_path.parent_path());
    fs::create_directories(chrooted_path.parent_path());

    std::string bcfp(chrooted_path.string() + ".bc");

    std::string binary_filename = fs::path(b.Path).filename().string();

    pid = fork();
    if (!pid) {
      {
        struct sigaction sa;

        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sa.sa_handler = SIG_IGN;

        sigaction(SIGINT, &sa, nullptr);
      }

      std::vector<const char *> arg_vec = {
        jove_llvm_path.c_str(),
        "-decompilation", opts::jv.c_str(),
        "-binary", binary_filename.c_str(),
        "-output", bcfp.c_str()
      };

      if (opts::Trace)
        arg_vec.push_back("-trace");
      arg_vec.push_back(nullptr);

      print_command(&arg_vec[0]);

      std::string stdoutfp = bcfp + ".txt";
      int stdoutfd = open(stdoutfp.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0666);
      dup2(stdoutfd, STDOUT_FILENO);

      close(STDIN_FILENO);
      execve(arg_vec[0], const_cast<char **>(&arg_vec[0]), ::environ);
      return;
    }

    //
    // check exit code
    //
    if (int ret = await_process_completion(pid)) {
      WithColor::error() << "jove-llvm failed for " << binary_filename << '\n';
      continue;
    }

    if (Cancel)
      return;

    //
    // optimize bitcode
    //
    std::string optbcfp(chrooted_path.string() + ".opt.bc");
    if (opts::NoOpt) {
      optbcfp = bcfp;
      goto skip_opt;
    }

    pid = fork();
    if (!pid) {
      {
        struct sigaction sa;

        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sa.sa_handler = SIG_IGN;

        sigaction(SIGINT, &sa, nullptr);
      }

      const char *arg_vec[] = {
        opt_path.c_str(),
        "-o", optbcfp.c_str(),
        "-Os", bcfp.c_str(),
        nullptr
      };

      print_command(&arg_vec[0]);

      close(STDIN_FILENO);
      execve(arg_vec[0], const_cast<char **>(&arg_vec[0]), ::environ);
      return;
    }

    //
    // check exit code
    //
    if (int ret = await_process_completion(pid)) {
      WithColor::error() << "llvm failed for " << binary_filename << '\n';
      continue;
    }

    if (Cancel)
      return;

skip_opt:
    //
    // compile bitcode
    //
    std::string objfp(chrooted_path.string() + ".o");

    pid = fork();
    if (!pid) {
      {
        struct sigaction sa;

        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sa.sa_handler = SIG_IGN;

        sigaction(SIGINT, &sa, nullptr);
      }

      const char *arg_vec[] = {
        llc_path.c_str(),
        "-o", objfp.c_str(),
        "-filetype=obj",
        "-relocation-model=pic",
        "-frame-pointer=all",
        optbcfp.c_str(),
        nullptr
      };

      print_command(&arg_vec[0]);

      close(STDIN_FILENO);
      execve(arg_vec[0], const_cast<char **>(&arg_vec[0]), ::environ);
      return;
    }

    //
    // check exit code
    //
    if (int ret = await_process_completion(pid)) {
      WithColor::error() << "llc failed for " << binary_filename << '\n';
      continue;
    }

    if (Cancel)
      return;

    if (b.IsExecutable)
      continue;

    //
    // link object file to create shared library
    //
    std::string sofp(chrooted_path.string());

    pid = fork();
    if (!pid) {
      {
        struct sigaction sa;

        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sa.sa_handler = SIG_IGN;

        sigaction(SIGINT, &sa, nullptr);
      }

      const char *arg_vec[] = {
        lld_path.c_str(),
        "-o", sofp.c_str(),
        "-m", "elf_" ___JOVE_ARCH_NAME,
        "-dynamic-linker", dyn_linker_path.c_str(),
        "-nostdlib",
        "-z", "nodefaultlib",
        "-z", "origin",
        "-shared",
        objfp.c_str(),
        "--push-state",
        "--as-needed",
        compiler_runtime_afp,
        "--pop-state",
        dyn_linker_path.c_str(),
        nullptr
      };

      print_command(arg_vec);

      close(STDIN_FILENO);
      execve(arg_vec[0], const_cast<char **>(&arg_vec[0]), ::environ);
      return;
    }

    //
    // check exit code
    //
    if (int ret = await_process_completion(pid)) {
      WithColor::error() << "ld failed for " << binary_filename << '\n';
      continue;
    }

    if (Cancel)
      return;
  }
}

void spawn_workers(void) {
  std::vector<std::thread> workers;

  unsigned N = opts::Threads;

  workers.reserve(N);
  for (unsigned i = 0; i < N; ++i)
    workers.push_back(std::thread(worker));

  for (std::thread &t : workers)
    t.join();
}

int await_process_completion(pid_t pid) {
  int wstatus;
  do {
    if (waitpid(pid, &wstatus, WUNTRACED | WCONTINUED) < 0)
      abort();

    if (WIFEXITED(wstatus)) {
      //printf("exited, status=%d\n", WEXITSTATUS(wstatus));
      return WEXITSTATUS(wstatus);
    } else if (WIFSIGNALED(wstatus)) {
      //printf("killed by signal %d\n", WTERMSIG(wstatus));
      return 1;
    } else if (WIFSTOPPED(wstatus)) {
      //printf("stopped by signal %d\n", WSTOPSIG(wstatus));
      return 1;
    } else if (WIFCONTINUED(wstatus)) {
      //printf("continued\n");
    }
  } while (!WIFEXITED(wstatus) && !WIFSIGNALED(wstatus));

  abort();
}

unsigned num_cpus(void) {
  cpu_set_t cpu_mask;
  if (sched_getaffinity(0, sizeof(cpu_mask), &cpu_mask) < 0) {
    WithColor::error() << "sched_getaffinity failed : " << strerror(errno)
                       << '\n';
    abort();
  }

  return CPU_COUNT(&cpu_mask);
}

void print_command(const char **argv) {
  for (const char **s = argv; *s; ++s)
    llvm::outs() << *s << ' ';

  llvm::outs() << '\n';
}

}
