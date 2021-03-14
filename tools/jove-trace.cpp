#include "jove/jove.h"

#include <cstdlib>
#include <sys/wait.h>
#include <sys/vfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <boost/filesystem.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/serialization/bitset.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/WithColor.h>
#include <llvm/Support/InitLLVM.h>
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

static cl::list<std::string>
    Envs("env", cl::CommaSeparated,
         cl::value_desc("KEY_1=VALUE_1,KEY_2=VALUE_2,...,KEY_n=VALUE_n"),
         cl::desc("Extra environment variables"), cl::cat(JoveCategory));

static cl::opt<std::string> ExistingSysroot("existing-sysroot",
                                            cl::desc("path to directory"),
                                            cl::value_desc("filename"),
                                            cl::cat(JoveCategory));

static cl::opt<std::string> jv("decompilation", cl::desc("Jove decompilation"),
                               cl::Required, cl::value_desc("filename"),
                               cl::cat(JoveCategory));

static cl::alias jvAlias("d", cl::desc("Alias for -decompilation."),
                         cl::aliasopt(jv), cl::cat(JoveCategory));

static cl::opt<std::string> Output("output", cl::desc("Output trace txt file"),
                                   cl::Required, cl::value_desc("filename"),
                                   cl::cat(JoveCategory));

static cl::alias OutputAlias("o", cl::desc("Alias for -output."),
                             cl::aliasopt(Output), cl::cat(JoveCategory));

static cl::opt<bool> SkipUProbe("skip-uprobe",
                                cl::desc("Skip adding userspace tracepoints"),
                                cl::cat(JoveCategory));

static cl::opt<bool> SkipExec("skip-exec",
                              cl::desc("Skip executing prog"),
                              cl::cat(JoveCategory));

static cl::list<std::string>
    Excludes("exclude-binaries", cl::CommaSeparated,
             cl::value_desc("binary_1,binary_2,...,binary_n"),
             cl::desc("Binaries to exclude from trace"), cl::cat(JoveCategory));

static cl::list<std::string>
    Only("only-binaries", cl::CommaSeparated,
         cl::value_desc("binary_1,binary_2,...,binary_n"),
         cl::desc("Binaries to include in trace"), cl::cat(JoveCategory));

} // namespace opts

namespace jove {
static int trace(void);
}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::HideUnrelatedOptions({&opts::JoveCategory, &llvm::ColorCategory});
  cl::AddExtraVersionPrinter([](llvm::raw_ostream &OS) -> void {
    OS << "jove version " JOVE_VERSION "\n";
  });
  cl::ParseCommandLineOptions(argc, argv, "Jove Trace\n");

  if (!fs::exists(opts::Prog)) {
    WithColor::error() << "program does not exist\n";
    return 1;
  }

  if (!fs::exists(opts::jv)) {
    WithColor::error() << "decompilation does not exist\n";
    return 1;
  }

  return jove::trace();
}

namespace jove {

static decompilation_t Decompilation;

static char tmpdir[] = {'/', 't', 'm', 'p', '/', 'X',
                        'X', 'X', 'X', 'X', 'X', '\0'};

static int await_process_completion(pid_t);

int trace(void) {
  bool git = fs::is_directory(opts::jv);

  //
  // parse the existing decompilation file
  //
  {
    std::ifstream ifs(git ? (opts::jv + "/decompilation.jv") : opts::jv);

    boost::archive::binary_iarchive ia(ifs);
    ia >> Decompilation;
  }

#if 0
  //
  // run program with LD_TRACE_LOADED_OBJECTS=1 and no arguments. capture the
  // standard output, which will tell us what binaries are needed by prog.
  //
  int pipefd[2];
  if (pipe(pipefd) < 0) {
    WithColor::error() << llvm::formatv("pipe failed: {0}\n", strerror(errno));
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
      WithColor::error() << llvm::formatv("dup2 failed: {0}\n",
                                          strerror(errno));
      exit(1);
    }

    const char *argv[] = {opts::Prog.c_str(), nullptr};

    std::vector<const char *> envv;
    for (char **env = ::environ; *env; ++env)
      envv.push_back(*env);
    envv.push_back("LD_TRACE_LOADED_OBJECTS=1");
    envv.push_back(nullptr);

    return execve(argv[0],
                  const_cast<char **>(&argv[0]),
                  const_cast<char **>(&envv[0]));
  }

  close(pipefd[1]); /* close unused write end */

  //
  // slurp up the result of executing the binary
  //
  std::string dynlink_stdout;
  {
    char ch;
    while (read(pipefd[0], &ch, 1) > 0)
      dynlink_stdout += ch;
  }

  close(pipefd[0]); /* close read end */

  //
  // check exit code
  //
  if (int ret = await_process_completion(pid)) {
    WithColor::error() << llvm::formatv("LD_TRACE_LOADED_OBJECTS=1 {0}\n",
                                        opts::Prog);
    return 1;
  }

  std::vector<fs::path> binary_paths = {opts::Prog};

  //
  // get the path to the dynamic linker
  //
  {
    std::string::size_type pos = dynlink_stdout.find("\t/");
    if (pos == std::string::npos) {
      WithColor::error()
          << "could not find interpreter path in output from dynamic linker\n";
      return 1;
    }

    ++pos; /* skip '\t' */

    std::string::size_type space_pos = dynlink_stdout.find(" (0x", pos);
    std::string dynl_path = dynlink_stdout.substr(pos, space_pos - pos);

    // (don't canonicalize)
    binary_paths.push_back(dynl_path);
  }

  //
  // consider everything else, except vdso
  //
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

    assert(std::find(binary_paths.begin(), binary_paths.end(), path) ==
           binary_paths.end());

    // (don't canonicalize)
    binary_paths.push_back(path);
  }
#endif

  fs::path sysroot;
  if (!opts::ExistingSysroot.empty()) {
    sysroot = opts::ExistingSysroot;
    if (!fs::exists(sysroot)) {
      WithColor::error() << llvm::formatv(
          "provided sysroot '{0}' does not exist\n", sysroot.c_str());
    }
  } else {
    //
    // creating a unique temporary directory that will serve as a sysroot
    //
    if (!mkdtemp(tmpdir)) {
      WithColor::error() << llvm::formatv("mkdtemp failed: {0}\n",
                                          strerror(errno));
      return 1;
    }

    sysroot = tmpdir;

    WithColor::note() << llvm::formatv("sysroot: {0}\n", sysroot.c_str());

#if 0
  //
  // copy the binaries to the sysroot, making symbolic links as necessary
  //
  for (const fs::path &p : binary_paths) {
    if (!fs::exists(p)) {
      WithColor::error() << llvm::formatv(
          "path from dynamic linker '{0}' is bogus\n", p.c_str());
      return 1;
    }

    //llvm::outs() << llvm::formatv("binary path: {0}\n", p.c_str());

    fs::path chrooted(sysroot / p);

    //llvm::outs() << llvm::formatv("chrooted: {0}\n", chrooted.c_str());

    fs::create_directories(chrooted.parent_path());

    if (fs::is_symlink(p)) {
      fs::copy_symlink(p, chrooted);

      fs::path _p = p.parent_path() / fs::read_symlink(p);
      fs::path _chrooted(sysroot / _p);

      fs::create_directories(_chrooted.parent_path());
      fs::copy_file(_p, _chrooted);
    } else {
      assert(fs::is_regular_file(p));
      fs::copy_file(p, chrooted);
    }
  }
#endif

    //
    // build sysroot
    //
    for (const binary_t &binary : Decompilation.Binaries) {
      fs::path p(binary.Path);
      if (!fs::exists(p)) {
        WithColor::error() << llvm::formatv("binary '{0}' doesn't exist\n",
                                            binary.Path);
        return 1;
      }

      fs::path chrooted(sysroot / binary.Path);

      // llvm::outs() << llvm::formatv("chrooted: {0}\n", chrooted.c_str());

      fs::create_directories(chrooted.parent_path());

      if (fs::is_symlink(p)) {
        fs::copy_symlink(p, chrooted);

        fs::path _p = p.parent_path() / fs::read_symlink(p);
        fs::path _chrooted(sysroot / _p);

        fs::create_directories(_chrooted.parent_path());
        fs::copy_file(_p, _chrooted);
      } else {
        assert(fs::is_regular_file(p));
        fs::copy_file(p, chrooted);
      }
    }
  }

  //
  // check for tracefs filesystem
  //
#define PATH_TO_TRACEFS "/sys/kernel/debug/tracing"
  {
    struct statfs buf;
    if (statfs(PATH_TO_TRACEFS "/README", &buf) < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv("statfs failed: {0}\n",
                                          strerror(err));
      return 1;
    }

    if (buf.f_type != TRACEFS_MAGIC) {
      WithColor::error() << "no tracefs found at " PATH_TO_TRACEFS "\n";
      return 1;
    }
  }

  if (opts::SkipUProbe)
    goto skip_uprobe;

  //
  // open with O_TRUNC to clear any uprobe_events already registered
  //
  {
clear_events:
    int fd = open(PATH_TO_TRACEFS "/uprobe_events", O_TRUNC | O_WRONLY);
    if (fd < 0) {
      int err = errno;
      if (err == EBUSY) {
        //
        // try disabling any existing uprobe tracepoints
        //
        fd = open(PATH_TO_TRACEFS "/events/jove/enable", O_WRONLY);
        if (!(fd < 0)) {
          bool succeeded = write(fd, "0\n", sizeof("0\n")) == sizeof("0\n");
          close(fd);
          if (succeeded) {
            goto clear_events; // if all that succeeded, try again
          }
        }
      }

      WithColor::error() << llvm::formatv("failed to open uprobe_events: {0}\n",
                                          strerror(err));
      return 1;
    }

    //
    // create a uprobe_event for every basic block in every DSO except the
    // dynamic linker
    //
    for (unsigned BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
      const binary_t &binary = Decompilation.Binaries[BIdx];

      if (binary.IsDynamicLinker)
        continue;
      if (binary.IsVDSO)
        continue;

      std::string binaryName = fs::path(binary.Path).filename().string();
      if (!opts::Only.empty()) {
        if (std::find(opts::Only.begin(),
                      opts::Only.end(), binaryName) == opts::Only.end())
          continue;
      } else {
        if (std::find(opts::Excludes.begin(),
                      opts::Excludes.end(), binaryName) != opts::Excludes.end())
          continue;
      }

      fs::path chrooted(sysroot / binary.Path);
      if (!fs::exists(chrooted)) {
        WithColor::error() << llvm::formatv("binary does not exist at {0}\n",
                                            chrooted.c_str());
        return 1;
      }

      const auto &ICFG = binary.Analysis.ICFG;

      for (unsigned BBIdx = 0; BBIdx < boost::num_vertices(ICFG); ++BBIdx) {
        basic_block_t bb = boost::vertex(BBIdx, ICFG);

        //
        // e.g.
        //
        // $ cat /sys/kernel/debug/tracing/uprobe_events
        //
        // p:jove/JV_0_0 /tmp/XdoHpm/usr/bin/ls:0x0000000000005ac0
        // p:jove/JV_0_1 /tmp/XdoHpm/usr/bin/ls:0x0000000000005aee
        //

        char buff[0x100];
        snprintf(buff, sizeof(buff),
                 "p:jove/JV_%u_%u %s:0x%" PRIx64 "\n",
                 BIdx,
                 BBIdx,
                 chrooted.c_str(),
                 static_cast<uint64_t>(ICFG[bb].Addr));

        if (write(fd, buff, strlen(buff)) < 0) {
          int err = errno;

          if (err == ENODEV) {
            WithColor::warning()
                << "failed to write to uprobe_events: No such device\n";

            if (close(fd) < 0) {
              int err = errno;
              WithColor::error() << llvm::formatv(
                  "failed to close uprobe_events: {0}\n", strerror(err));

              return 1;
            }

            // we hit the ceiling
            goto enable_uprobe;
          }

          WithColor::error() << llvm::formatv(
              "failed to write to uprobe_events: {0}\n", strerror(err));
          return 1;
        }
      }
    }

    if (close(fd) < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv("failed to close uprobe_events: {0}\n",
                                          strerror(err));
      return 1;
    }
  }

enable_uprobe:
  //
  // enable the uprobe_events we just added
  //
  {
    int fd = open(PATH_TO_TRACEFS "/events/jove/enable", O_WRONLY);
    if (fd < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv(
          "failed to open uprobe_events enable: {0}\n", strerror(err));
      return 1;
    }

    if (write(fd, "1\n", 2) < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv(
          "failed to write to uprobe_events enable: {0}\n", strerror(err));
      return 1;
    }

    if (close(fd) < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv(
          "failed to close uprobe_events enable: {0}\n", strerror(err));
      return 1;
    }
  }

skip_uprobe:
  //
  // clear /sys/kernel/debug/tracing/trace
  //
  {
    int fd = open(PATH_TO_TRACEFS "/trace", O_TRUNC | O_WRONLY);
    if (!(fd < 0))
      close(fd);
  }

  if (opts::SkipExec)
    goto skip_exec;

  //
  // fork, chroot, exec
  //
  {
    pid_t child = fork();
    if (!child) {
      if (chroot(sysroot.c_str()) < 0) {
        int err = errno;
        WithColor::error() << llvm::formatv("failed to chroot: {0}\n",
                                            strerror(err));
        return 1;
      }

      if (chdir("/") < 0) {
        int err = errno;
        WithColor::error() << llvm::formatv("chdir failed : {0}\n",
                                            strerror(err));
        return 1;
      }

      //
      // arguments
      //
      std::vector<const char *> argv;
      argv.push_back(opts::Prog.c_str());

      for (const std::string &arg : opts::Args)
        argv.push_back(arg.c_str());

      argv.push_back(nullptr);

      //
      // environment
      //
      std::vector<const char *> envv;
      for (char **env = ::environ; *env; ++env)
        envv.push_back(*env);

#if defined(__x86_64__)
      // <3 glibc
      envv.push_back("GLIBC_TUNABLES=glibc.cpu.hwcaps="
                     "-AVX_Usable,"
                     "-AVX2_Usable,"
                     "-AVX512F_Usable,"
                     "-SSE4_1,"
                     "-SSE4_2,"
                     "-SSSE3,"
                     "-Fast_Unaligned_Load,"
                     "-ERMS,"
                     "-AVX_Fast_Unaligned_Load");
#elif defined(__i386__)
      // <3 glibc
      envv.push_back("GLIBC_TUNABLES=glibc.cpu.hwcaps="
                     "-SSE4_1,"
                     "-SSE4_2,"
                     "-SSSE3,"
                     "-Fast_Rep_String,"
                     "-Fast_Unaligned_Load,"
                     "-SSE2");
#endif

      //envv.push_back("LD_BIND_NOW=1");

      for (const std::string &env : opts::Envs)
        envv.push_back(env.c_str());

      envv.push_back(nullptr);

      execve(argv[0],
             const_cast<char **>(&argv[0]),
             const_cast<char **>(&envv[0]));

      {
        int err = errno;
        WithColor::error() << llvm::formatv("execve failed : {0}\n",
                                            strerror(err));
        return 1;
      }
    }

    int ret = await_process_completion(child);

    {
      //
      // parse /sys/kernel/debug/tracing/trace
      //
      // e.g.
      //
      // # tracer: nop
      // #
      // # entries-in-buffer/entries-written: 67/67   #P:8
      // #
      // #                              _-----=> irqs-off
      // #                             / _----=> need-resched
      // #                            | / _---=> hardirq/softirq
      // #                            || / _--=> preempt-depth
      // #                            ||| /     delay
      // #           TASK-PID   CPU#  ||||    TIMESTAMP  FUNCTION
      // #              | |       |   ||||       |         |
      //      returns_u64-24099 [003] d... 1045487.565114: JV_0_0: (0x40f0e0)
      //

      std::ofstream ofs(opts::Output);
      std::ifstream trace_ifs(PATH_TO_TRACEFS "/trace");

      std::string line;
      while (std::getline(trace_ifs, line)) {
        if (line.empty())
          continue;

        if (line.front() == '#')
          continue;

        std::string::size_type jv_pos = line.find("JV_");
        if (jv_pos == std::string::npos)
          continue;

        std::string s = line.substr(jv_pos);
        std::string::size_type pos = s.find(':');

        if (pos == std::string::npos)
          continue;

        ofs << s.substr(0, pos) << '\n';
      }
    }

    return ret;
  }

skip_exec:
  return 0;
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

}
