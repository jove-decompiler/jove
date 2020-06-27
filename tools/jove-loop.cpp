#include <unistd.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <thread>
#include <cinttypes>
#include <boost/filesystem.hpp>
#include <boost/dll/runtime_symbol_info.hpp>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <pthread.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/WithColor.h>
#include <llvm/Support/FormatVariadic.h>

namespace fs = boost::filesystem;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace opts {
static cl::OptionCategory JoveCategory("Specific Options");

static cl::opt<std::string> Prog(cl::Positional, cl::desc("prog"), cl::Required,
                                 cl::value_desc("filename"),
                                 cl::cat(JoveCategory));

static cl::list<std::string> Args("args", cl::CommaSeparated,
                                  cl::value_desc("arg_1,arg_2,...,arg_n"),
                                  cl::desc("Program arguments"),
                                  cl::cat(JoveCategory));

static cl::opt<std::string> jv("decompilation", cl::desc("Jove decompilation"),
                               cl::Required, cl::value_desc("filename"),
                               cl::cat(JoveCategory));

static cl::alias jvAlias("d", cl::desc("Alias for -decompilation."),
                         cl::aliasopt(jv), cl::cat(JoveCategory));

static cl::opt<std::string> sysroot("sysroot", cl::desc("Output directory"),
                                    cl::Required, cl::cat(JoveCategory));

static cl::opt<bool> DFSan("dfsan", cl::desc("Run dfsan on bitcode"),
                           cl::cat(JoveCategory));

} // namespace opts

namespace jove {

static int loop(void);

} // namespace jove

int main(int argc, char **argv) {
  int _argc = argc;
  char **_argv = argv;

  // argc/argv replacement to handle '--'
  struct {
    std::vector<std::string> s;
    std::vector<const char *> a;
  } arg_vec;

  {
    int prog_args_idx = -1;

    for (int i = 0; i < argc; ++i) {
      if (strcmp(argv[i], "--") == 0) {
        prog_args_idx = i;
        break;
      }
    }

    if (prog_args_idx != -1) {
      for (int i = 0; i < prog_args_idx; ++i)
        arg_vec.s.push_back(argv[i]);

      for (std::string &s : arg_vec.s)
        arg_vec.a.push_back(s.c_str());
      arg_vec.a.push_back(nullptr);

      _argc = prog_args_idx;
      _argv = const_cast<char **>(&arg_vec.a[0]);

      for (int i = prog_args_idx + 1; i < argc; ++i) {
        //llvm::outs() << llvm::formatv("argv[{0}] = {1}\n", i, argv[i]);

        opts::Args.push_back(argv[i]);
      }
    }
  }

  llvm::InitLLVM X(_argc, _argv);

  cl::HideUnrelatedOptions({&opts::JoveCategory, &llvm::ColorCategory});
  cl::ParseCommandLineOptions(_argc, _argv, "Jove Loop\n");

  return jove::loop();
}

namespace jove {

static fs::path jove_recompile_path, jove_run_path, jove_analyze_path;

static int await_process_completion(pid_t);

static void IgnoreCtrlC(void);

static void print_command(const char **argv);

static std::atomic<bool> Cancelled(false);

static void handle_sigint(int no) {
  Cancelled = true;
}

int loop(void) {
  //
  // install signal handler for Ctrl-C to gracefully cancel
  //
  {
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = handle_sigint;

    if (sigaction(SIGINT, &sa, nullptr) < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv("{0}: sigaction failed ({1})\n",
                                          __func__, strerror(err));
    }
  }

  if (!fs::exists(opts::sysroot) || !fs::is_directory(opts::sysroot)) {
    WithColor::error() << llvm::formatv(
        "provided sysroot {0} is not directory\n", opts::sysroot);
    return 1;
  }

  jove_recompile_path = (boost::dll::program_location().parent_path() /
                         std::string("jove-recompile"))
                            .string();
  if (!fs::exists(jove_recompile_path)) {
    WithColor::error() << llvm::formatv(
        "could not find jove-recompile at {0}\n", jove_recompile_path.c_str());

    return 1;
  }

  jove_run_path =
      (boost::dll::program_location().parent_path() / std::string("jove-run"))
          .string();
  if (!fs::exists(jove_run_path)) {
    WithColor::error() << llvm::formatv(
        "could not find jove-run at {0}\n", jove_run_path.c_str());

    return 1;
  }

  jove_analyze_path = (boost::dll::program_location().parent_path() /
                       std::string("jove-analyze"))
                          .string();
  if (!fs::exists(jove_analyze_path)) {
    WithColor::error() << llvm::formatv(
        "could not find jove-analyze at {0}\n", jove_analyze_path.c_str());

    return 1;
  }

  while (!Cancelled) {
    pid_t pid;

    {
      fs::path chrooted_path(opts::sysroot);
      chrooted_path /= opts::Prog;

      if (!fs::exists(chrooted_path))
        goto skip_run;
    }

    //
    // run
    //
    pid = fork();
    if (!pid) {
      std::vector<const char *> arg_vec = {
          jove_run_path.c_str(),
          opts::sysroot.c_str(),
          opts::Prog.c_str(),
      };

      for (std::string &s : opts::Args)
        arg_vec.push_back(s.c_str());

      arg_vec.push_back(nullptr);

      print_command(&arg_vec[0]);
      execve(arg_vec[0], const_cast<char **>(&arg_vec[0]), ::environ);

      int err = errno;
      WithColor::error() << llvm::formatv("execve failed: {0}\n",
                                          strerror(err));
      return 1;
    }

    {
      int ret = await_process_completion(pid);

      //
      // XXX currently the only way to know that jove-recover was run is by
      // looking at the exit status ('b' or 'f')
      //
      if (ret != 'b' &&
          ret != 'f')
        break;
    }

skip_run:
    //
    // analyze
    //
    pid = fork();
    if (!pid) {
      const char *arg_arr[] = {
          jove_analyze_path.c_str(),

          "-d", opts::jv.c_str(),

          nullptr
      };

      execve(arg_arr[0], const_cast<char **>(&arg_arr[0]), ::environ);

      int err = errno;
      WithColor::error() << llvm::formatv("execve failed: {0}\n",
                                          strerror(err));
      return 1;
    }

    if (int ret = await_process_completion(pid)) {
      WithColor::error() << llvm::formatv("jove-analyze failed [{0}]\n", ret);
      return ret;
    }

    //
    // recompile
    //
    pid = fork();
    if (!pid) {
      std::vector<const char *> arg_vec = {
          jove_recompile_path.c_str(),

          "-d", opts::jv.c_str(),
          "-o", opts::sysroot.c_str(),
      };

      if (opts::DFSan)
        arg_vec.push_back("--dfsan");

      arg_vec.push_back(nullptr);

      print_command(&arg_vec[0]);
      execve(arg_vec[0], const_cast<char **>(&arg_vec[0]), ::environ);

      int err = errno;
      WithColor::error() << llvm::formatv("execve failed: {0}\n",
                                          strerror(err));
      return 1;
    }

    if (int ret = await_process_completion(pid)) {
      WithColor::error() << llvm::formatv("jove-recompile failed [{0}]\n", ret);
      return ret;
    }
  }

  return 0;
}

void print_command(const char **argv) {
  for (const char **s = argv; *s; ++s)
    llvm::outs() << *s << ' ';

  llvm::outs() << '\n';
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

void IgnoreCtrlC(void) {
  struct sigaction sa;

  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = SIG_IGN;

  sigaction(SIGINT, &sa, nullptr);
}

}
