#include "tcgcommon.hpp"

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
#include <boost/program_options.hpp>
#include <boost/dll/runtime_symbol_info.hpp>
#include <llvm/ADT/StringRef.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/ManagedStatic.h>

#include "jove/jove.h"
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/graph/adj_list_serialize.hpp>

#if defined(TARGET_X86_64)
#define ___JOVE_ARCH_NAME "x86_64"
#elif defined(TARGET_AARCH64)
#define ___JOVE_ARCH_NAME "aarch64"
#endif

namespace fs = boost::filesystem;
namespace po = boost::program_options;

namespace jove {

static int parse_command_line_arguments(int argc, char **argv);
static int initialize_decompilation(void);

}

int main(int argc, char **argv) {
  llvm::StringRef ToolName = argv[0];
  llvm::sys::PrintStackTraceOnErrorSignal(ToolName);
  llvm::PrettyStackTraceProgram X(argc, argv);
  llvm::llvm_shutdown_obj Y;

  return jove::parse_command_line_arguments(argc, argv) ||
         jove::initialize_decompilation();
}

namespace jove {

static struct {
  fs::path jove_add_path, git_path;
  fs::path input;
  fs::path output;
  fs::path tmpdir;
  bool verbose;
  bool git;
  unsigned threads;
} cmdline;

static unsigned num_cpus(void);
static void spawn_workers(const std::vector<std::string> &binary_paths);

static std::queue<std::string> Q;

int initialize_decompilation(void) {
  //
  // run program with LD_TRACE_LOADED_OBJECTS=1 and no arguments. capture the
  // standard output, which will tell us what binaries are needed by prog.
  //
  int pipefd[2];
  if (pipe(pipefd) < 0) {
    fprintf(stderr, "pipe failed : %s\n", strerror(errno));
    return 1;
  }

  const pid_t pid = fork();
  if (pid < 0) {
    fprintf(stderr, "fork failed : %s\n", strerror(errno));
    return 1;
  }

  //
  // are we the child?
  //
  if (pid == 0) {
    close(pipefd[0]); /* close unused read end */

    /* make stdout be the write end of the pipe */
    if (dup2(pipefd[1], STDOUT_FILENO) < 0) {
      fprintf(stderr, "dup2 failed : %s\n", strerror(errno));
      exit(1);
    }

    char extra_env[] = {'L', 'D', '_', 'T', 'R', 'A', 'C', 'E', '_',
                        'L', 'O', 'A', 'D', 'E', 'D', '_', 'O', 'B',
                        'J', 'E', 'C', 'T', 'S', '=', '1', '\0'};

    char null_ch = '\0';
    char *_argv[2] = {&null_ch, nullptr};

    unsigned env_len = 0;
    for (char **_envp = ::environ; *_envp; ++_envp)
      ++env_len;

    std::vector<std::vector<char>> _env_vec;
    _env_vec.resize(env_len);
    for (unsigned i = 0; i < env_len; ++i) {
      _env_vec[i].resize(strlen(environ[i]) + 1);
      strncpy(&_env_vec[i][0], environ[i], _env_vec[i].size());
    }

    std::vector<char *> _env;
    _env.reserve(env_len + 2);
    for (std::vector<char> &_vec : _env_vec)
      _env.push_back(&_vec[0]);
    _env.push_back(extra_env);
    _env.push_back(nullptr);

    return execve(cmdline.input.string().c_str(), _argv, _env.data());
  }

  close(pipefd[1]); /* close unused write end */

  //
  // as the parent, we'll wait for the child to exit
  //
  int wstatus;
  do {
    if (waitpid(pid, &wstatus, WUNTRACED | WCONTINUED) < 0) {
      fprintf(stderr, "waitpid failed : %s\n", strerror(errno));
      return 1;
    }
  } while (!WIFEXITED(wstatus));

  //
  // check exit code
  //
  if (WEXITSTATUS(wstatus) != 0) {
    fprintf(stderr, "LD_TRACE_LOADED_OBJECTS=1 prog : returned %d\n",
            WEXITSTATUS(wstatus));
    return 1;
  }

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
  std::vector<std::string> binary_paths;
  binary_paths.push_back(fs::canonical(cmdline.input).string());

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
      fprintf(stderr, "error: invalid binary path '%s'\n", path.c_str());
      return 1;
    }

    binary_paths.push_back(fs::canonical(path).string());
  }

  for (const std::string& path : binary_paths)
    Q.push(path);

  spawn_workers(binary_paths);

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
  }
}

void spawn_workers(const std::vector<std::string> &binary_paths) {
  std::vector<std::thread> workers;

  unsigned N = cmdline.threads;
  if (!N)
    N = num_cpus();

  workers.reserve(N);
  for (unsigned i = 0; i < N; ++i)
    workers.push_back(std::thread(worker));

  for (std::thread &t : workers)
    t.join();
}

unsigned num_cpus(void) {
  cpu_set_t cpu_mask;
  if (sched_getaffinity(0, sizeof(cpu_mask), &cpu_mask) < 0) {
    fprintf(stderr, "sched_getaffinity failed : %s\n", strerror(errno));
    exit(1);
  }

  return CPU_COUNT(&cpu_mask);
}

int parse_command_line_arguments(int argc, char **argv) {
  fs::path &jove_add_path = cmdline.jove_add_path;
  fs::path &git_path = cmdline.git_path;
  fs::path &ifp = cmdline.input;
  fs::path &ofp = cmdline.output;
  bool &verbose = cmdline.verbose;
  bool &git = cmdline.git;
  unsigned &threads = cmdline.threads;
  fs::path &tmpdir = cmdline.tmpdir;

  try {
    po::options_description desc("Allowed options");
    desc.add_options()
      ("help,h", "produce help message")

      ("git,g", "initialize output in git repository")

      ("verbose,v", "be verbose")

      ("tmp-dir,d", po::value<fs::path>(&tmpdir)
         ->default_value("/tmp/jove-init-" ___JOVE_ARCH_NAME),
       "Directory for temporary files")

      ("path-to-jove-add", po::value<fs::path>(&jove_add_path)
         ->default_value(boost::dll::program_location().parent_path() /
			 (std::string("jove-add-" ___JOVE_ARCH_NAME))),
       "Path to jove-add")

      ("path-to-git",
       po::value<fs::path>(&git_path)->default_value("/usr/bin/git"),
       "Path to git")

      ("input,i", po::value<fs::path>(&ifp),
       "input binary")

      ("output,o", po::value<fs::path>(&ofp),
       "output file (or directory, if --git was specified) path")

      ("threads,t", po::value<unsigned>(&threads)->default_value(0u),
       "Specify the number of worker threads to use. Setting threads to a "
       "special value 0 makes jove-init use as many threads as there are CPU "
       "cores on the system.");

    po::positional_options_description p;
    p.add("input", -1);

    po::variables_map vm;
    po::store(
        po::command_line_parser(argc, argv).options(desc).positional(p).run(),
        vm);
    po::notify(vm);

    if (vm.count("help") || !vm.count("input") || !vm.count("output")) {
      printf("Usage: %s -o DECOMPILATION.jv <PROG>\n", argv[0]);
      std::ostringstream oss;
      oss << desc;
      puts(oss.str().c_str());
      return 1;
    }

    if (!fs::exists(ifp)) {
      fprintf(stderr, "given program %s does not exist\n",
              ifp.string().c_str());
      return 1;
    }

    ifp = fs::canonical(ifp);

    if (!fs::exists(jove_add_path)) {
      fprintf(stderr, "path for jove-add %s does not exist\n",
              jove_add_path.string().c_str());
      return 1;
    }

    if (!fs::exists(git_path)) {
      fprintf(stderr, "path for git %s does not exist\n",
              git_path.string().c_str());
      return 1;
    }

    verbose = vm.count("verbose") != 0;
    git = vm.count("git") != 0;
  } catch (std::exception &e) {
    fprintf(stderr, "%s\n", e.what());
    return 1;
  }

  fs::create_directories(tmpdir);

  char buff[0x2000];
  snprintf(buff, sizeof(buff), "%s/XXXXXX", tmpdir.string().c_str());
  mkdtemp(buff);

  assert(fs::exists(buff));
  tmpdir = buff;

  return 0;
}

}
