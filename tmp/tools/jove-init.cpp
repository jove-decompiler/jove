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

#include "jove/jove.h"
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/set.hpp>
#include <boost/graph/adj_list_serialize.hpp>

namespace fs = boost::filesystem;
namespace cl = llvm::cl;

namespace jove {
static unsigned num_cpus(void);
}

namespace opts {
  static cl::opt<std::string> Input(cl::Positional,
    cl::desc("<program>"),
    cl::Required);

  static cl::opt<std::string> Output("output",
    cl::desc("Output decompilation"),
    cl::Required);

  static cl::opt<unsigned> Threads("num-threads",
    cl::desc("Number of CPU threads to use"),
    cl::init(jove::num_cpus()));

  static cl::opt<bool> Git("git",
    cl::desc("Create git repository for decompilation"));

  static cl::opt<bool> Verbose("verbose",
    cl::desc("Print extra information for debugging purposes"));
}

namespace jove {
static int initialize_decompilation(void);
}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::ParseCommandLineOptions(argc, argv, "Jove Init\n");

  return jove::initialize_decompilation();
}

namespace jove {

static void spawn_workers(void);

static std::queue<std::string> Q;
static char tmpdir[] = {'/', 't', 'm', 'p', '/', 'X',
                        'X', 'X', 'X', 'X', 'X', '\0'};

static int await_process_completion(pid_t);

static std::string jove_add_path;

int initialize_decompilation(void) {
  jove_add_path = (boost::dll::program_location().parent_path() /
                   std::string("jove-add-" ___JOVE_ARCH_NAME))
                      .string();
  if (!fs::exists(jove_add_path)) {
    llvm::errs() << "could not find jove-add at " << jove_add_path << '\n';
    return 1;
  }

  //
  // run program with LD_TRACE_LOADED_OBJECTS=1 and no arguments. capture the
  // standard output, which will tell us what binaries are needed by prog.
  //
  int pipefd[2];
  if (pipe(pipefd) < 0) {
    llvm::errs() << "pipe failed : " << strerror(errno) << '\n';
    return 1;
  }

  const pid_t pid = fork();

  //
  // are we the child?
  //
  if (!pid) {
    close(pipefd[0]); /* close unused read end */

    /* make stdout be the write end of the pipe */
    if (dup2(pipefd[1], STDOUT_FILENO) < 0) {
      llvm::errs() << "dup2 failed : " << strerror(errno) << '\n';
      exit(1);
    }

    std::vector<char *> arg_vec;
    arg_vec.push_back(const_cast<char *>(opts::Input.c_str()));
    arg_vec.push_back(nullptr);

    std::vector<char *> env_vec;
    for (char **env = ::environ; *env; ++env)
      env_vec.push_back(*env);
    env_vec.push_back(const_cast<char *>("LD_TRACE_LOADED_OBJECTS=1"));
    env_vec.push_back(nullptr);

    return execve(opts::Input.c_str(), arg_vec.data(), env_vec.data());
  }

  close(pipefd[1]); /* close unused write end */

  //
  // check exit code
  //
  if (int ret = await_process_completion(pid)) {
    llvm::errs() << "LD_TRACE_LOADED_OBJECTS=1 " << opts::Input
                 << " returned nonzero exit code " << ret << '\n';
    return 1;
  }

  //
  // slurp up the result of executing the binary
  //
  std::string dynlink_stdout;
  {
    char buf;
    while (read(pipefd[0], &buf, 1) > 0)
      dynlink_stdout += buf;
  }

  close(pipefd[0]); /* close read end */

  //
  // parse the standard output from the dynamic linker
  //
  std::unordered_set<std::string> binary_paths;
  binary_paths.insert(fs::canonical(opts::Input).string());

  std::string::size_type pos = 0;
  for (;;) {
    std::string::size_type arrow_pos = dynlink_stdout.find(" => /", pos);

    if (arrow_pos == std::string::npos)
      break;

    pos = arrow_pos + strlen(" => /") - 1;

    std::string::size_type space_pos = dynlink_stdout.find(" (0x", pos);

    if (space_pos == std::string::npos)
      break;

    std::string path = dynlink_stdout.substr(pos, space_pos - pos);
    if (!fs::exists(path)) {
      llvm::errs() << "error: path from dynamic linker '" << path
                   << "' is bogus\n";
      return 1;
    }

    binary_paths.insert(fs::canonical(path).string());
  }

  //
  // prepare to process the binaries by creating a unique temporary directory
  //
  if (!mkdtemp(tmpdir)) {
    llvm::errs() << "mkdtemp failed : " << strerror(errno) << '\n';
    return 1;
  }

  //
  // process the binaries, concurrently
  //
  for (const std::string& path : binary_paths)
    Q.push(path);

  spawn_workers();

  //
  // merge the intermediate decompilation files
  //
  decompilation_t final_decompilation;
  final_decompilation.Binaries.reserve(binary_paths.size());

  for (const std::string &path : binary_paths) {
    std::string jvfp = tmpdir + path + ".jv";
    if (!fs::exists(jvfp)) {
      llvm::errs() << "intermediate result " << jvfp << " not found" << '\n';
      return 1;
    }

    decompilation_t decompilation;
    {
      std::ifstream ifs(jvfp);

      boost::archive::binary_iarchive ia(ifs);
      ia >> decompilation;
    }

    if (decompilation.Binaries.size() != 1) {
      llvm::errs() << "invalid intermediate result " << jvfp << '\n';
      return 1;
    }

    //
    // trivially combine decompilations
    //
    final_decompilation.Binaries.push_back(decompilation.Binaries.front());
  }

  if (fs::exists(opts::Output)) {
    if (opts::Verbose)
      llvm::outs() << "output already exists, overwriting " << opts::Output
                   << '\n';

    if (fs::is_directory(opts::Output)) {
      fs::remove_all(opts::Output);
    } else {
      fs::remove(opts::Output);
    }
  }

  std::string final_output_path = opts::Output;
  if (opts::Git) {
    fs::create_directory(opts::Output);
    final_output_path += "/decompilation.jv";
  }

  {
    std::ofstream ofs(final_output_path);

    boost::archive::binary_oarchive oa(ofs);
    oa << final_decompilation;
  }

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
      ofs << "\n[diff \"jv\"]\n        textconv = jove-dump-x86_64";
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

  std::string path;
  while (pop_path(path)) {
    llvm::outs() << path << '\n';

    std::string jvfp = tmpdir + path + ".jv";
    fs::create_directories(fs::path(jvfp).parent_path());

    pid_t pid = fork();

    //
    // are we the child?
    //
    if (!pid) {
      std::vector<char *> arg_vec;
      arg_vec.push_back(const_cast<char *>(jove_add_path.c_str()));
      arg_vec.push_back(const_cast<char *>("-output"));
      arg_vec.push_back(const_cast<char *>(jvfp.c_str()));
      arg_vec.push_back(const_cast<char *>("-input"));
      arg_vec.push_back(const_cast<char *>(path.c_str()));
      arg_vec.push_back(nullptr);

      execve(jove_add_path.c_str(), arg_vec.data(), ::environ);
      return;
    }

    //
    // check exit code
    //
    if (int ret = await_process_completion(pid))
      llvm::errs() << "jove-add failed for " << path << '\n';
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
        llvm::errs() << "waitpid failed : " << strerror(errno) << '\n';
        abort();
      }
    }
  } while (!WIFEXITED(wstatus));

  return WEXITSTATUS(wstatus);
}

unsigned num_cpus(void) {
  cpu_set_t cpu_mask;
  if (sched_getaffinity(0, sizeof(cpu_mask), &cpu_mask) < 0) {
    fprintf(stderr, "sched_getaffinity failed : %s\n", strerror(errno));
    exit(1);
  }

  return CPU_COUNT(&cpu_mask);
}

}
