#include "tool.h"
#include "elf.h"

#include <boost/filesystem.hpp>

#include <llvm/Support/CommandLine.h>
#include <llvm/Support/DataExtractor.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

#include <cstdlib>

#include <fcntl.h>
#include <linux/magic.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

namespace {

struct binary_state_t {
  std::unique_ptr<llvm::object::Binary> ObjectFile;
};

}

class TraceTool : public TransformerTool<binary_state_t> {
  struct Cmdline {
    cl::opt<std::string> Prog;
    cl::list<std::string> Args;
    cl::list<std::string> Envs;
    cl::opt<std::string> ExistingSysroot;
    cl::opt<std::string> jv;
    cl::alias jvAlias;
    cl::opt<std::string> Output;
    cl::alias OutputAlias;
    cl::opt<bool> SkipUProbe;
    cl::opt<bool> SkipExec;
    cl::opt<unsigned> Sleep;
    cl::list<std::string> Excludes;
    cl::list<std::string> Only;
    cl::opt<bool> OutsideChroot;
    cl::alias OutsideChrootAlias;
    cl::opt<std::string> PathToTracefs;
    cl::opt<bool> NoParseTrace;
    cl::opt<bool> Verbose;
    cl::alias VerboseAlias;

    bool OnlyExecutable;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Prog(cl::Positional, cl::desc("prog"), cl::Required,
               cl::value_desc("filename"), cl::cat(JoveCategory)),

          Args("args", cl::CommaSeparated,
               cl::value_desc("arg_1,arg_2,...,arg_n"),
               cl::desc("Program arguments"), cl::cat(JoveCategory)),

          Envs("env", cl::CommaSeparated,
               cl::value_desc("KEY_1=VALUE_1,KEY_2=VALUE_2,...,KEY_n=VALUE_n"),
               cl::desc("Extra environment variables"), cl::cat(JoveCategory)),

          ExistingSysroot("existing-sysroot", cl::desc("path to directory"),
                          cl::value_desc("filename"), cl::cat(JoveCategory)),

          jv("jv", cl::desc("Jove jv"), cl::Required,
             cl::value_desc("filename"), cl::cat(JoveCategory)),

          jvAlias("d", cl::desc("Alias for -jv."), cl::aliasopt(jv),
                  cl::cat(JoveCategory)),

          Output("output", cl::desc("Output trace txt file"), cl::Required,
                 cl::value_desc("filename"), cl::cat(JoveCategory)),

          OutputAlias("o", cl::desc("Alias for -output."), cl::aliasopt(Output),
                      cl::cat(JoveCategory)),

          SkipUProbe("skip-uprobe",
                     cl::desc("Skip adding userspace tracepoints"),
                     cl::cat(JoveCategory)),

          SkipExec("skip-exec", cl::desc("Skip executing prog"),
                   cl::cat(JoveCategory)),

          Sleep("sleep", cl::value_desc("seconds"),
                cl::desc("Time in seconds to sleep for after finishing waiting "
                         "on child; "
                         "can be useful if the program being recompiled forks"),
                cl::cat(JoveCategory)),

          Excludes("exclude-binaries", cl::CommaSeparated,
                   cl::value_desc("binary_1,binary_2,...,binary_n"),
                   cl::desc("Binaries to exclude from trace"),
                   cl::cat(JoveCategory)),

          Only("only-binaries", cl::CommaSeparated,
               cl::value_desc("binary_1,binary_2,...,binary_n"),
               cl::desc("Binaries to include in trace"), cl::cat(JoveCategory)),

          OutsideChroot("outside-chroot", cl::desc("Do not chroot(2)."),
                        cl::cat(JoveCategory)),

          OutsideChrootAlias(
              "x", cl::desc("Exe only. Alias for --outside-chroot."),
              cl::aliasopt(OutsideChroot), cl::cat(JoveCategory)),

          PathToTracefs("tracefs",
                        cl::desc("Provide path to mounted tracefs filesystem"),
                        cl::init("/sys/kernel/debug/tracing"),
                        cl::value_desc("directory"), cl::cat(JoveCategory)),

          NoParseTrace("no-parse-trace",
                       cl::desc("Do not parse /sys/kernel/debug/tracing/trace "
                                "at the very end."),
                       cl::cat(JoveCategory)),

          Verbose("verbose",
                  cl::desc("Print extra information for debugging purposes"),
                  cl::cat(JoveCategory)),

          VerboseAlias("v", cl::desc("Alias for -verbose."),
                       cl::aliasopt(Verbose), cl::cat(JoveCategory)) {}
  } opts;

public:
  TraceTool() : opts(JoveCategory) {}

  int Run(void);

  void InitStateForBinaries(jv_t &);
};

JOVE_REGISTER_TOOL("trace", TraceTool);

static char tmpdir[] = {'/', 't', 'm', 'p', '/', 'X',
                        'X', 'X', 'X', 'X', 'X', '\0'};

int TraceTool::Run(void) {
  for (char *dashdash_arg : dashdash_args)
    opts.Args.push_back(dashdash_arg);

  if (!fs::exists(opts.Prog)) {
    WithColor::error() << "program does not exist\n";
    return 1;
  }

  if (!fs::exists(opts.jv)) {
    WithColor::error() << "jv does not exist\n";
    return 1;
  }

  opts.OnlyExecutable = opts.OutsideChroot;

  //
  // establish that a mounted tracefs filesystem exists
  //
  {
    struct statfs buf;
    if (statfs(opts.PathToTracefs.c_str(), &buf) < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv(
          "failed to access tracefs at {0}: {1}\n", opts.PathToTracefs.c_str(),
          strerror(err));
      return 1;
    }

    if (buf.f_type != TRACEFS_MAGIC) {
      WithColor::error() << llvm::formatv(
          "tracefs at {0} has unknown filesystem type\n",
          opts.PathToTracefs);
      return 1;
    }
  }

  ReadJvFromFile(opts.jv, jv);
  InitStateForBinaries(jv);

  //
  // establish temporary directory that may or may not be used as a sysroot
  //
  fs::path SysrootPath;
  if (!opts.ExistingSysroot.empty()) {
    if (!fs::exists(opts.ExistingSysroot)) {
      WithColor::error() << llvm::formatv(
          "provided directory for sysroot '{0}' does not exist\n",
          opts.ExistingSysroot.c_str());
      return 1;
    }

    SysrootPath = opts.ExistingSysroot;
  } else {
    //
    // create a unique temporary directory
    //
    if (!mkdtemp(tmpdir)) {
      int err = errno;
      WithColor::error() << llvm::formatv("mkdtemp failed: {0}\n", strerror(err));
      return 1;
    }

    SysrootPath = tmpdir;
  }

  if (opts.Verbose)
    WithColor::note() << llvm::formatv("sysroot: {0}\n", SysrootPath.c_str());

  //
  // recreate sysroot as best we can TODO refactor
  //
  for (const binary_t &binary : jv.Binaries) {
    fs::path chrooted_path(SysrootPath / binary.Path);
    fs::create_directories(chrooted_path.parent_path());

    {
      std::ofstream ofs(chrooted_path.c_str());
      ofs.write(&binary.Data[0], binary.Data.size());
    }

    fs::permissions(chrooted_path, fs::others_read
                                 | fs::others_exe
                                 | fs::group_read
                                 | fs::group_exe
                                 | fs::owner_read
                                 | fs::owner_write
                                 | fs::owner_exe);
  }

  if (opts.SkipUProbe)
    goto skip_uprobe;

  {
open_events:
    int events_fd;

    {
      std::string s(opts.PathToTracefs);
      s.append("/uprobe_events");

      //
      // open with O_TRUNC to clear any uprobe_events already registered
      //
      events_fd = ::open(s.c_str(), O_TRUNC | O_WRONLY);
    }

    if (events_fd < 0) {
      int err = errno;
      if (err == EBUSY) {
        //
        // try disabling any existing uprobe tracepoints
        //
        int fd;
        {
          std::string s(opts.PathToTracefs);
          s.append("/events/jove/enable");

          fd = ::open(s.c_str(), O_WRONLY);
        }

        if (fd < 0) {
          ;
        } else {
          ssize_t ret = ::write(fd, "0\n", sizeof("0\n"));

          (void)::close(fd);

          if (ret == sizeof("0\n")) {
            //
            // if all that succeeded, start over again
            //
            goto open_events;
          }
        }
      }

      WithColor::error() << llvm::formatv("failed to open uprobe_events: {0}\n",
                                          strerror(err));
      return 1;
    }

    //
    // register uprobes
    //
    for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
      const binary_t &binary = jv.Binaries[BIdx];

      if (binary.IsDynamicLinker)
        continue;
      if (binary.IsVDSO)
        continue;
      if (opts.OnlyExecutable && !binary.IsExecutable)
        continue;

      std::string binaryName = fs::path(binary.Path).filename().string();
      if (!opts.Only.empty()) {
        if (std::find(opts.Only.begin(),
                      opts.Only.end(), binaryName) == opts.Only.end())
          continue;
      } else {
        if (std::find(opts.Excludes.begin(),
                      opts.Excludes.end(), binaryName) != opts.Excludes.end())
          continue;
      }

      fs::path chrooted_path(SysrootPath / binary.Path);
      if (!fs::exists(chrooted_path)) {
        WithColor::warning() << llvm::formatv(
            "{0} does not exist; not placing uprobe tracepoints\n",
            chrooted_path.c_str());
        continue;
      }

      assert(state.for_binary(binary).ObjectFile.get() != nullptr);
      assert(llvm::isa<ELFO>(state.for_binary(binary).ObjectFile.get()));
      ELFO &O = *llvm::cast<ELFO>(state.for_binary(binary).ObjectFile.get());
      const ELFF &E = *O.getELFFile();

      const auto &ICFG = binary.Analysis.ICFG;

      for (basic_block_index_t BBIdx = 0; BBIdx < boost::num_vertices(ICFG); ++BBIdx) {
        basic_block_t bb = boost::vertex(BBIdx, ICFG);

        //
        // e.g.
        //
        // $ cat /sys/kernel/debug/tracing/uprobe_events
        //
        // p:jove/JV_0_0 /tmp/XdoHpm/usr/bin/ls:0x0000000000005ac0
        // p:jove/JV_0_1 /tmp/XdoHpm/usr/bin/ls:0x0000000000005aee
        //

        uintptr_t Off;
        if (binary.IsPIC) {
          Off = ICFG[bb].Addr;
        } else {
          assert(binary.IsExecutable);

          //
          // instead of a virtual address, we need to provide an offset from the
          // start of the file.
          //
          llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(ICFG[bb].Addr);
          if (!ExpectedPtr) {
            //WARN();
            continue;
          }

          const uint8_t *Ptr = *ExpectedPtr;

          Off = (uintptr_t)Ptr - (uintptr_t)E.base();
        }

        char buff[0x100];
        unsigned N = snprintf(buff, sizeof(buff),
                 "p:jove/JV_%" PRIu32 "_%" PRIu32 " %s:0x%" PRIx64 "\n",
                 BIdx,
                 BBIdx,
                 chrooted_path.c_str(),
                 static_cast<uint64_t>(Off));

        ssize_t ret = ::write(events_fd, buff, N);
        if (ret < 0) {
          int err = errno;

          (void)::close(events_fd);

          if (err == ENODEV) {
            WithColor::warning()
                << "failed to write to uprobe_events: No such device\n";

            goto enable_uprobe; /* did we hit the ceiling? */
          }

          WithColor::error() << llvm::formatv(
              "failed to write to uprobe_events: {0}\n", strerror(err));
          return 1;
        }

        if (ret != N) {
          (void)::close(events_fd);

          WithColor::error()
              << llvm::formatv("only wrote {0} bytes to uprobe_events\n", ret);
          return 1;
        }
      }
    }

enable_uprobe:
    (void)::close(events_fd);
  }

  //
  // enable the uprobe_events we just added
  //
  {
    std::string s(opts.PathToTracefs);
    s.append("/events/jove/enable");

    int fd = ::open(s.c_str(), O_WRONLY);

    if (fd < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv("failed to open {0}: {1}\n",
                                          s.c_str(), strerror(err));
      return 1;
    }

  constexpr unsigned MAX_RETRIES = 10;
  unsigned c = 0;

do_enable_uprobe:
    ssize_t ret = ::write(fd, "1\n", sizeof("1\n"));
    if (ret < 0) {
      int err = errno;
      if (err == EINVAL && ++c < MAX_RETRIES) {
        WithColor::error() << llvm::formatv(
            "failed to write to {0}, trying again...\n", s.c_str());
        usleep(1000);
        goto do_enable_uprobe;
      }

      (void)::close(fd);

      WithColor::error() << llvm::formatv(
          "failed to write to {0}: {1}\n", s.c_str(), strerror(err));
      return 1;
    }

    (void)::close(fd);

    if (ret != sizeof("1\n")) {
      WithColor::error() << llvm::formatv(
          "only wrote {0} bytes to uprobe_events enable\n", ret);

      return 1;
    }
  }

skip_uprobe:
  //
  // clear /sys/kernel/debug/tracing/trace
  //
  {
    std::string s(opts.PathToTracefs);
    s.append("/trace");

    (void)::close(::open(s.c_str(), O_TRUNC | O_WRONLY));
  }

  if (opts.SkipExec)
    return 0;

  //
  // fork, (optionally) chroot, exec
  //
  {
    pid_t child = ::fork();
    if (!child) {
      if (!opts.OutsideChroot) {
        if (::chroot(SysrootPath.c_str()) < 0) {
          int err = errno;
          WithColor::error() << llvm::formatv("failed to chroot: {0}\n",
                                              strerror(err));
          return 1;
        }

        if (::chdir("/") < 0) {
          int err = errno;
          WithColor::error() << llvm::formatv("chdir failed : {0}\n",
                                              strerror(err));
          return 1;
        }
      }

      //
      // arguments
      //
      std::vector<const char *> arg_vec;

      fs::path exe_path = opts.OutsideChroot
                              ? SysrootPath / jv.Binaries[0].Path
                              : jv.Binaries[0].Path;

      arg_vec.push_back(exe_path.c_str());

      for (const std::string &arg : opts.Args)
        arg_vec.push_back(arg.c_str());

      arg_vec.push_back(nullptr);

      //
      // environment
      //
      std::vector<const char *> env_vec;
      for (char **env = ::environ; *env; ++env)
        env_vec.push_back(*env);

#if defined(__x86_64__)
      // <3 glibc
      env_vec.push_back("GLIBC_TUNABLES=glibc.cpu.hwcaps="
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
      env_vec.push_back("GLIBC_TUNABLES=glibc.cpu.hwcaps="
                        "-SSE4_1,"
                        "-SSE4_2,"
                        "-SSSE3,"
                        "-Fast_Rep_String,"
                        "-Fast_Unaligned_Load,"
                        "-SSE2");
#endif

      env_vec.push_back("LD_BIND_NOW=1");

      if (fs::exists("/firmadyne/libnvram.so"))
        env_vec.push_back("LD_PRELOAD=/firmadyne/libnvram.so");

      for (const std::string &env : opts.Envs)
        env_vec.push_back(env.c_str());

      env_vec.push_back(nullptr);

      ::execve(arg_vec[0],
               const_cast<char **>(&arg_vec[0]),
               const_cast<char **>(&env_vec[0]));

      int err = errno;
      WithColor::error() << llvm::formatv("execve failed: {0}\n",
                                          strerror(err));
      return 1;
    }

    int ret = WaitForProcessToExit(child);

    if (unsigned sec = opts.Sleep) {
      llvm::errs() << llvm::formatv("sleeping for {0} seconds...\n", sec);

      for (unsigned t = 0; t < sec; ++t) {
        sleep(1);

        llvm::errs() << '.';
      }
    }

    if (!opts.NoParseTrace) {
      llvm::errs() << "parsing trace...\n";

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

      std::ofstream ofs(opts.Output);
      fs::path the_trace_path = fs::path(opts.PathToTracefs) / "trace";
      std::ifstream trace_ifs(the_trace_path.c_str());

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

  return 0;
}

void TraceTool::InitStateForBinaries(jv_t &jv) {
  for_each_binary(jv, [&](binary_t &binary) {
    ignore_exception([&]() {
      state.for_binary(binary).ObjectFile = CreateBinary(binary.Data);
    });
  });
}
}
