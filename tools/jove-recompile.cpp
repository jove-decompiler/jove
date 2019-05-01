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

static cl::opt<std::string> Output("output", cl::desc("Output directory"),
                                   cl::Required, cl::cat(JoveCategory));

static cl::opt<unsigned> Threads("num-threads",
                                 cl::desc("Number of CPU threads to use"),
                                 cl::init(jove::num_cpus()),
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
    "/usr/lib/clang/8.0.0/lib/linux/libclang_rt.builtins-x86_64.a";

static int await_process_completion(pid_t);

static void print_command(std::vector<char *> &arg_vec);

static std::string jove_llvm_path, llc_path, lld_path, opt_path;
static std::string dyn_linker_path;

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

    Q.push(BIdx);
  }

  spawn_workers();

  std::vector<fs::path> sofp_vec;
  for (binary_t &b : Decompilation.Binaries) {
    if (b.IsExecutable)
      continue;
    if (b.IsDynamicLinker)
      continue;

    sofp_vec.push_back(opts::Output + b.Path);
  }

  std::string exe_fp;
  std::string exe_objfp;
  for (binary_t &b : Decompilation.Binaries) {
    if (!b.IsExecutable)
      continue;

    exe_fp = opts::Output + b.Path;

    fs::path tmpdir_path(std::string(tmpdir) + b.Path);
    exe_objfp = tmpdir_path.replace_extension("o").string();

    break;
  }
  assert(!exe_objfp.empty());
  assert(!exe_fp.empty());

  pid_t pid = fork();
  if (!pid) {
    std::vector<char *> arg_vec;

    arg_vec.push_back(const_cast<char *>(lld_path.c_str()));

    arg_vec.push_back(const_cast<char *>("-o"));
    arg_vec.push_back(const_cast<char *>(exe_fp.c_str()));

    arg_vec.push_back(const_cast<char *>("-m"));
    arg_vec.push_back(const_cast<char *>("elf_" ___JOVE_ARCH_NAME));

    arg_vec.push_back(const_cast<char *>("-dynamic-linker"));
    arg_vec.push_back(const_cast<char *>(dyn_linker_path.c_str()));

    arg_vec.push_back(const_cast<char *>("-pie"));

    arg_vec.push_back(const_cast<char *>("-e"));
    arg_vec.push_back(const_cast<char *>("__jove_start"));

    arg_vec.push_back(const_cast<char *>("-nostdlib"));

#if 0
    arg_vec.push_back(const_cast<char *>("-z"));
    arg_vec.push_back(const_cast<char *>("nodefaultlib"));
#endif

    arg_vec.push_back(const_cast<char *>("-z"));
    arg_vec.push_back(const_cast<char *>("origin"));

    arg_vec.push_back(const_cast<char *>(exe_objfp.c_str()));

    for (const fs::path &sofp : sofp_vec) {
      // /path/to/libfoo.so -> "-lfoo"
      std::string &Ldir = *new std::string(sofp.parent_path().string());

      arg_vec.push_back(const_cast<char *>("-L"));
      arg_vec.push_back(const_cast<char *>(Ldir.c_str()));

      std::string &lStr = *new std::string(':' + sofp.filename().string());

      arg_vec.push_back(const_cast<char *>("-l"));
      arg_vec.push_back(const_cast<char *>(lStr.c_str()));

      std::string &rpathStr =
          *new std::string(std::string("-rpath=$ORIGIN/") +
                           fs::relative(sofp, fs::path(exe_fp).parent_path())
                               .parent_path()
                               .string());

      arg_vec.push_back(const_cast<char *>(rpathStr.c_str()));
    }

    arg_vec.push_back(const_cast<char *>("--push-state"));
    arg_vec.push_back(const_cast<char *>("--as-needed"));
    arg_vec.push_back(const_cast<char *>(compiler_runtime_afp));
    arg_vec.push_back(const_cast<char *>("--pop-state"));

    arg_vec.push_back(const_cast<char *>(dyn_linker_path.c_str()));

    arg_vec.push_back(nullptr);

    print_command(arg_vec);
    execve(arg_vec.front(), arg_vec.data(), ::environ);
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

  //
  // copy compiler runtime
  //
  {
    fs::path chrooted_path(opts::Output + compiler_runtime_afp);
    fs::create_directories(chrooted_path.parent_path());
    fs::copy(compiler_runtime_afp, chrooted_path);
  }

  return 0;
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
  while (pop_binary_index(BIdx)) {
    pid_t pid;

    binary_t &b = Decompilation.Binaries[BIdx];

    // make sure the path is absolute
    assert(b.Path.at(0) == '/');

    const fs::path tmpdir_path(std::string(tmpdir) + b.Path);
    const fs::path chrooted_path(opts::Output + b.Path);

    fs::create_directories(tmpdir_path.parent_path());
    fs::create_directories(chrooted_path.parent_path());

    std::string bcfp;
    {
      fs::path path(tmpdir_path);
      bcfp = path.replace_extension("bc").string();
    }

    std::string binary_filename = fs::path(b.Path).filename().string();

    pid = fork();
    if (!pid) {
      std::vector<char *> arg_vec;
      arg_vec.push_back(const_cast<char *>(jove_llvm_path.c_str()));
      arg_vec.push_back(const_cast<char *>("-decompilation"));
      arg_vec.push_back(const_cast<char *>(opts::jv.c_str()));
      arg_vec.push_back(const_cast<char *>("-binary"));
      arg_vec.push_back(const_cast<char *>(binary_filename.c_str()));
      arg_vec.push_back(const_cast<char *>("-output"));
      arg_vec.push_back(const_cast<char *>(bcfp.c_str()));
      arg_vec.push_back(nullptr);

      print_command(arg_vec);

      std::string stdoutfp = bcfp + ".txt";
      int stdoutfd = open(stdoutfp.c_str(), O_CREAT | O_WRONLY);
      dup2(stdoutfd, STDOUT_FILENO);
      dup2(stdoutfd, STDERR_FILENO);

      execve(arg_vec.front(), arg_vec.data(), ::environ);
      return;
    }

    //
    // check exit code
    //
    if (int ret = await_process_completion(pid)) {
      WithColor::error() << "jove-llvm failed for " << binary_filename << '\n';
      continue;
    }

    //
    // optimize bitcode
    //
    std::string optbcfp;
    {
      fs::path path(tmpdir_path);
      optbcfp = path.replace_extension("opt.bc").string();
    }

    pid = fork();
    if (!pid) {
      std::vector<char *> arg_vec;
      arg_vec.push_back(const_cast<char *>(opt_path.c_str()));
      arg_vec.push_back(const_cast<char *>("-o"));
      arg_vec.push_back(const_cast<char *>(optbcfp.c_str()));
      arg_vec.push_back(const_cast<char *>("-Os"));
      arg_vec.push_back(const_cast<char *>(bcfp.c_str()));
      arg_vec.push_back(nullptr);

      print_command(arg_vec);

      execve(arg_vec.front(), arg_vec.data(), ::environ);
      return;
    }

    //
    // check exit code
    //
    if (int ret = await_process_completion(pid)) {
      WithColor::error() << "llvm failed for " << binary_filename << '\n';
      continue;
    }

    //
    // compile bitcode
    //
    std::string objfp;
    {
      fs::path path(tmpdir_path);
      objfp = path.replace_extension("o").string();
    }

    pid = fork();
    if (!pid) {
      std::vector<char *> arg_vec;
      arg_vec.push_back(const_cast<char *>(llc_path.c_str()));
      arg_vec.push_back(const_cast<char *>("-o"));
      arg_vec.push_back(const_cast<char *>(objfp.c_str()));
      arg_vec.push_back(const_cast<char *>("-filetype=obj"));
      arg_vec.push_back(const_cast<char *>("-relocation-model=pic"));
      arg_vec.push_back(const_cast<char *>("-frame-pointer=all"));
      arg_vec.push_back(const_cast<char *>(optbcfp.c_str()));
      arg_vec.push_back(nullptr);

      print_command(arg_vec);
      execve(arg_vec.front(), arg_vec.data(), ::environ);
      return;
    }

    //
    // check exit code
    //
    if (int ret = await_process_completion(pid)) {
      WithColor::error() << "llc failed for " << binary_filename << '\n';
      continue;
    }

    if (b.IsExecutable)
      continue;

    //
    // link object file to create shared library
    //
    std::string sofp;
    {
      fs::path path(chrooted_path);
      sofp = path.replace_extension("so").string();
    }

    pid = fork();
    if (!pid) {
      std::vector<char *> arg_vec;

      arg_vec.push_back(const_cast<char *>(lld_path.c_str()));

      arg_vec.push_back(const_cast<char *>("-o"));
      arg_vec.push_back(const_cast<char *>(sofp.c_str()));

      arg_vec.push_back(const_cast<char *>("-m"));
      arg_vec.push_back(const_cast<char *>("elf_" ___JOVE_ARCH_NAME));

      arg_vec.push_back(const_cast<char *>("-dynamic-linker"));
      arg_vec.push_back(const_cast<char *>(dyn_linker_path.c_str()));

      arg_vec.push_back(const_cast<char *>("-e"));
      arg_vec.push_back(const_cast<char *>("__jove_start"));

      arg_vec.push_back(const_cast<char *>("-nostdlib"));

#if 0
      arg_vec.push_back(const_cast<char *>("-z"));
      arg_vec.push_back(const_cast<char *>("nodefaultlib"));
#endif

      arg_vec.push_back(const_cast<char *>("-z"));
      arg_vec.push_back(const_cast<char *>("origin"));

      arg_vec.push_back(const_cast<char *>("-shared"));

      arg_vec.push_back(const_cast<char *>(objfp.c_str()));

      arg_vec.push_back(const_cast<char *>("--push-state"));
      arg_vec.push_back(const_cast<char *>("--as-needed"));
      arg_vec.push_back(const_cast<char *>(compiler_runtime_afp));
      arg_vec.push_back(const_cast<char *>("--pop-state"));

      arg_vec.push_back(const_cast<char *>(dyn_linker_path.c_str()));

      arg_vec.push_back(nullptr);

      print_command(arg_vec);
      execve(arg_vec.front(), arg_vec.data(), ::environ);
      return;
    }

    //
    // check exit code
    //
    if (int ret = await_process_completion(pid)) {
      WithColor::error() << "ld failed for " << binary_filename << '\n';
      continue;
    }
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
    if (waitpid(pid, &wstatus, WUNTRACED | WCONTINUED) < 0) {
      if (errno != EINTR) {
        WithColor::error() << "waitpid failed : " << strerror(errno) << '\n';
        abort();
      }
    }
  } while (!WIFEXITED(wstatus));

  return WEXITSTATUS(wstatus);
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

void print_command(std::vector<char *> &arg_vec) {
  for (char *s : arg_vec)
    llvm::outs() << s << ' ';

  llvm::outs() << '\n';
}

}
