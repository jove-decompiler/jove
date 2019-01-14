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
  static cl::opt<std::string> jv("decompilation",
    cl::desc("Jove decompilation"),
    cl::Required);

  static cl::opt<std::string> Output("output",
    cl::desc("Output directory"),
    cl::Required);

  static cl::opt<unsigned> Threads("num-threads",
    cl::desc("Number of CPU threads to use"),
    cl::init(jove::num_cpus()));

  static cl::opt<bool> Verbose("verbose",
    cl::desc("Print extra information for debugging purposes"));
}

namespace jove {
static int recompile(void);
}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::ParseCommandLineOptions(argc, argv, "Jove Recompile\n");

  return jove::recompile();
}

namespace jove {

static decompilation_t Decompilation;

static void spawn_workers(void);

static std::queue<std::string> Q;
static char tmpdir[] = {'/', 't', 'm', 'p', '/', 'X',
                        'X', 'X', 'X', 'X', 'X', '\0'};

static int await_process_completion(pid_t);

static std::string jove_llvm_path;

int recompile(void) {
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

  jove_llvm_path =
      (boost::dll::program_location().parent_path() / std::string("jove-llvm"))
          .string();
  if (!fs::exists(jove_llvm_path)) {
    WithColor::error() << "could not find jove-llvm at " << jove_llvm_path
                       << '\n';
    return 1;
  }

  //
  // prepare to process the binaries by creating a unique temporary directory
  //
  if (!mkdtemp(tmpdir)) {
    WithColor::error() << "mkdtemp failed : " << strerror(errno) << '\n';
    return 1;
  }

  llvm::outs() << tmpdir << '\n';

  //
  // process the binaries, concurrently
  //
  for (binary_t &b : Decompilation.Binaries) {
    if (b.IsDynamicLinker)
      continue;

    Q.push(fs::path(b.Path).filename().string());
  }

  spawn_workers();

#if 0
  if (opts::Git) {
    pid_t pid;

    //
    // git init
    //
    pid = fork();
    if (!pid) {
      chdir(opts::Output.c_str());

      std::vector<char *> arg_vec;
      arg_vec.push_back(const_cast<char *>("/usr/bin/git"));
      arg_vec.push_back(const_cast<char *>("init"));
      arg_vec.push_back(nullptr);

      return execve("/usr/bin/git", arg_vec.data(), ::environ);
    }

    if (int ret = await_process_completion(pid))
      return ret;

    //
    // Append '[diff "jv"]\n        textconv = jove-dump-x86_64' to .git/config
    //
    assert(fs::exists(opts::Output + "/.git/config"));
    {
      std::ofstream ofs(opts::Output + "/.git/config",
                        std::ios_base::out | std::ios_base::app);
      ofs << "\n[diff \"jv\"]\n        textconv = jove-dump";
    }

    //
    // Write '*.jv diff=jv' to .git/info/attributes
    //
    assert(!fs::exists(opts::Output + "/.git/info/attributes"));
    {
      std::ofstream ofs(opts::Output + "/.git/info/attributes");
      ofs << "*.jv diff=jv";
    }

    //
    // git add
    //
    pid = fork();
    if (!pid) {
      chdir(opts::Output.c_str());

      std::vector<char *> arg_vec;
      arg_vec.push_back(const_cast<char *>("/usr/bin/git"));
      arg_vec.push_back(const_cast<char *>("add"));
      arg_vec.push_back(const_cast<char *>("decompilation.jv"));
      arg_vec.push_back(nullptr);

      return execve("/usr/bin/git", arg_vec.data(), ::environ);
    }

    if (int ret = await_process_completion(pid))
      return ret;

    //
    // git commit
    //
    pid = fork();
    if (!pid) {
      chdir(opts::Output.c_str());

      std::vector<char *> arg_vec;
      arg_vec.push_back(const_cast<char *>("/usr/bin/git"));
      arg_vec.push_back(const_cast<char *>("commit"));
      arg_vec.push_back(const_cast<char *>("."));
      arg_vec.push_back(const_cast<char *>("-m"));
      arg_vec.push_back(const_cast<char *>("initial commit"));
      arg_vec.push_back(nullptr);

      return execve("/usr/bin/git", arg_vec.data(), ::environ);
    }

    if (int ret = await_process_completion(pid))
      return ret;
  }
#endif

  return 0;
}

static std::mutex mtx;

static void worker(void) {
  auto pop_path = [](std::string &out) -> bool {
    std::lock_guard<std::mutex> lck(mtx);

    if (Q.empty()) {
      return false;
    } else {
      out = Q.front();
      Q.pop();
      return true;
    }
  };

  std::string binary_filename;
  while (pop_path(binary_filename)) {
    llvm::outs() << binary_filename << '\n';

    std::string bcfp =
        (fs::path(tmpdir) / binary_filename).replace_extension("bc").string();

    int pipefd[2];
    if (pipe(pipefd) < 0)
      WithColor::error() << "pipe failed : " << strerror(errno) << '\n';

    pid_t pid = fork();
    if (!pid) {
      close(pipefd[0]); /* close unused read end */
      dup2(pipefd[1], STDOUT_FILENO);
      dup2(pipefd[1], STDERR_FILENO);

      std::vector<char *> arg_vec;
      arg_vec.push_back(const_cast<char *>(jove_llvm_path.c_str()));
      arg_vec.push_back(const_cast<char *>("-decompilation"));
      arg_vec.push_back(const_cast<char *>(opts::jv.c_str()));
      arg_vec.push_back(const_cast<char *>("-binary"));
      arg_vec.push_back(const_cast<char *>(binary_filename.c_str()));
      arg_vec.push_back(const_cast<char *>("-output"));
      arg_vec.push_back(const_cast<char *>(bcfp.c_str()));
      arg_vec.push_back(nullptr);

      execve(jove_llvm_path.c_str(), arg_vec.data(), ::environ);
      return;
    }

    close(pipefd[1]); /* close unused write end */

    std::string stdout_s;
    {
      char buf;
      while (read(pipefd[0], &buf, 1) > 0)
        stdout_s += buf;
    }

    close(pipefd[0]); /* close read end */

    //
    // check exit code
    //
    if (int ret = await_process_completion(pid))
      WithColor::error() << "jove-llvm failed for " << binary_filename << '\n';

    llvm::outs() << stdout_s;
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

}
