#include "tool.h"
#include "recovery.h"
#include "elf.h"
#include "crypto.h"

#include <boost/dll/runtime_symbol_info.hpp>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>

#include <llvm/Support/FormatVariadic.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/WithColor.h>

#include <atomic>
#include <cinttypes>
#include <string>
#include <thread>

#include <fcntl.h>
#include <pthread.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "jove_macros.h"

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

struct RunTool : public Tool {
  struct Cmdline {
    cl::opt<std::string> jv;
    cl::alias jvAlias;
    cl::opt<std::string> Prog;
    cl::list<std::string> Args;
    cl::list<std::string> Envs;
    cl::opt<std::string> EnvFromFile;
    cl::opt<std::string> ArgsFromFile;
    cl::list<std::string> BindMountDirs;
    cl::opt<std::string> sysroot;
    cl::opt<unsigned> Sleep;
    cl::opt<unsigned> DangerousSleep1;
    cl::opt<unsigned> DangerousSleep2;
    cl::opt<bool> NoChroot;
    cl::opt<std::string> ChangeDirectory;
    cl::opt<bool> ForeignLibs;
    cl::alias ForeignLibsAlias;
    cl::opt<std::string> HumanOutput;
    cl::opt<bool> Silent;
    cl::opt<std::string> Group;
    cl::alias GroupAlias;
    cl::opt<std::string> User;
    cl::alias UserAlias;
    cl::opt<std::string> PIDFifo;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : jv("jv", cl::desc("Jove jv"),
             cl::value_desc("filename"), cl::cat(JoveCategory)),

          jvAlias("d", cl::desc("Alias for -jv."), cl::aliasopt(jv),
                  cl::cat(JoveCategory)),

          Prog(cl::Positional, cl::desc("prog"), cl::Required,
               cl::value_desc("filename"), cl::cat(JoveCategory)),

          Args("args", cl::CommaSeparated, cl::ConsumeAfter,
               cl::desc("<program arguments>..."), cl::cat(JoveCategory)),

          Envs("env", cl::CommaSeparated,
               cl::value_desc("KEY_1=VALUE_1,KEY_2=VALUE_2,...,KEY_n=VALUE_n"),
               cl::desc("Extra environment variables"), cl::cat(JoveCategory)),

          EnvFromFile("env-from-file",
                      cl::desc("use output from `cat /proc/<pid>/environ`"),
                      cl::cat(JoveCategory)),

          ArgsFromFile("args-from-file",
                       cl::desc("use output from `cat /proc/<pid>/cmdline`"),
                       cl::cat(JoveCategory)),

          BindMountDirs("bind", cl::CommaSeparated,
                        cl::value_desc(
                            "/path/to/dir_1,/path/to/dir_2,...,/path/to/dir_n"),
                        cl::desc("List of directories to bind mount"),
                        cl::cat(JoveCategory)),

          sysroot("sysroot", cl::desc("Output directory"), cl::Required,
                  cl::cat(JoveCategory)),

          Sleep("sleep", cl::value_desc("seconds"),
                cl::desc("Time in seconds to sleep for after finishing waiting "
                         "on child; "
                         "can be useful if the program being recompiled forks"),
                cl::cat(JoveCategory)),

          DangerousSleep1("dangerous-sleep1", cl::value_desc("useconds"),
                          cl::desc("Time in useconds to wait for the dynamic "
                                   "linker to do its thing (1)"),
                          cl::init(30000), cl::cat(JoveCategory)),

          DangerousSleep2("dangerous-sleep2", cl::value_desc("useconds"),
                          cl::desc("Time in useconds to wait for the dynamic "
                                   "linker to do its thing (2)"),
                          cl::init(40000), cl::cat(JoveCategory)),

          NoChroot("no-chroot",
                   cl::desc("run program under real sysroot (useful when "
                            "combined with --foreign-libs)"),
                   cl::cat(JoveCategory)),

          ChangeDirectory("cd",
                          cl::desc("change directory after chroot(2)'ing"),
                          cl::cat(JoveCategory)),

          ForeignLibs(
              "foreign-libs",
              cl::desc("only recompile the executable itself; "
                       "treat all other binaries as \"foreign\". Implies "
                       "--no-chroot"),
              cl::cat(JoveCategory)),

          ForeignLibsAlias("x", cl::desc("Exe only. Alias for --foreign-libs."),
                           cl::aliasopt(ForeignLibs), cl::cat(JoveCategory)),

          HumanOutput("human-output",
                      cl::desc("Print messages to the given file path"),
                      cl::cat(JoveCategory)),

          Silent("silent",
                 cl::desc(
                     "Leave the stdout/stderr of the application undisturbed"),
                 cl::cat(JoveCategory)),

          Group("group", cl::desc("Run the given command as the superuser"),
                cl::cat(JoveCategory)),

          GroupAlias("g", cl::desc("Alias for --group"), cl::aliasopt(Group),
                     cl::cat(JoveCategory)),

          User("user", cl::desc("Run the given command as the superuser"),
               cl::cat(JoveCategory)),

          UserAlias("u", cl::desc("Alias for --user"), cl::aliasopt(User),
                    cl::cat(JoveCategory)),

          PIDFifo("pid-fifo",
                  cl::desc("Path to FIFO which will receive child PID"),
                  cl::cat(JoveCategory)) {}
  } opts;

  bool has_jv;
  std::string jvfp;

  std::unique_ptr<disas_t> disas;
  std::unique_ptr<tiny_code_generator_t> tcg;
  std::unique_ptr<symbolizer_t> symbolizer;
  std::unique_ptr<CodeRecovery> Recovery;

public:
  RunTool() : opts(JoveCategory) {}

  int Run(void);

  template <bool WillChroot>
  int DoRun(void);

  std::atomic<bool> WasDecompilationModified = false;
};

JOVE_REGISTER_TOOL("run", RunTool);

typedef boost::format fmt;

static RunTool *pTool;

static bool LivingDangerously;

static void CrashHandler(int no) {
  switch (no) {
  case SIGBUS:
  case SIGABRT:
  case SIGSEGV: {
    const char *msg = "jove-run crashed! attach with a debugger..";
    ::write(STDERR_FILENO, msg, strlen(msg));

    for (;;)
      sleep(1);

    __builtin_unreachable();
  }

  default:
    abort();
  }
}

int RunTool::Run(void) {
  pTool = this;

  for (char *dashdash_arg : dashdash_args)
    opts.Args.push_back(dashdash_arg);

  if (!opts.HumanOutput.empty())
    HumanOutToFile(opts.HumanOutput);

  jvfp = opts.jv;
  if (jvfp.empty())
    jvfp = path_to_jv(opts.Prog.c_str());

  has_jv = fs::exists(jvfp);

  //
  // signal handlers
  //
  {
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = CrashHandler;

    if (::sigaction(SIGSEGV, &sa, nullptr) < 0 ||
/*      ::sigaction(SIGABRT, &sa, nullptr) < 0 || */
        ::sigaction(SIGBUS, &sa, nullptr) < 0) {
      int err = errno;
      HumanOut() << llvm::formatv("sigaction failed: {0}\n", strerror(err));
      return 1;
    }
  }

  const bool WillChroot = !(opts.NoChroot || opts.ForeignLibs);
  LivingDangerously = !WillChroot && !opts.ForeignLibs;

  return WillChroot ? DoRun<true>() :
                      DoRun<false>();
}

//
// set when jove-recover has been run (if nonzero then either 'f', 'b', 'F', 'r')
//
static std::atomic<char> recovered_ch;
static std::atomic<bool> FileSystemRestored(false);

static void *recover_proc(const char *fifo_path);

static std::atomic<bool> interrupt_sleep;

static constexpr unsigned MAX_UMOUNT_RETRIES = 10;

template <bool IsEnabled>
struct ScopedMount {
  RunTool &tool;

  const char *const source;
  const char *const target;
  const char *const filesystemtype;
  const unsigned long mountflags;
  const void *const data;

  bool mounted;

  ScopedMount() = delete;

  ScopedMount(RunTool &tool,
              const char *source,
              const char *target,
              const char *filesystemtype,
              unsigned long mountflags,
              const void *data)
      : tool(tool),
        source(source),
        target(target),
        filesystemtype(filesystemtype),
        mountflags(mountflags),
        data(data),
        mounted(false) {
    if (!IsEnabled)
      return;

    if (source && *source == '\0')
      return;

    for (;;) {
      int ret = ::mount(this->source,
                        this->target,
                        this->filesystemtype,
                        this->mountflags,
                        this->data);
      if (ret < 0) {
        int err = errno;
        switch (err) {
        case EINTR:
          continue;

        default:
          if (tool.IsVerbose())
            tool.HumanOut() << llvm::formatv("mount(\"{0}\", \"{1}\", \"{2}\", {3:x}, {4}) failed: {5}\n",
                    this->source,
                    this->target,
                    this->filesystemtype,
                    (unsigned)this->mountflags,
                    (void *)this->data,
                    strerror(err));
          return;
        }
      } else {
        /* mount suceeded */
        this->mounted = true;
        break;
      }
    }
  }

  ~ScopedMount () {
    if (!IsEnabled)
      return;

    if (!this->mounted)
      return;

    unsigned retries = 0;

    for (;;) {
      int ret = ::umount2(this->target, 0);

      if (ret < 0) {
        int err = errno;

        switch (err) {
        case EBUSY:
          if (retries++ < MAX_UMOUNT_RETRIES) {
            if (tool.IsVerbose())
              tool.HumanOut() << llvm::formatv("retrying umount of {0} shortly...\n", this->target);

            usleep(10000 /* 0.01 s */);
          } else {
            tool.HumanOut() << llvm::formatv("unmounting {0} failed: EBUSY...\n", this->target);
            return;
          }
          /* fallthrough */
        case EINTR:
          continue;

        default:
          tool.HumanOut() << llvm::formatv("umount(\"{0}\") failed: {1}\n",
                                           this->target,
                                           strerror(err));
          return;
        }
      } else {
        if (tool.IsVerbose())
          tool.HumanOut() << llvm::formatv("unmounted {0}.\n", this->target);

        /* unmount suceeded */
        break;
      }
    }
  }
};

static void touch(const fs::path &);

#define __BEGIN_MOUNTS__ {
#define __END_MOUNTS__ }

template <bool WillChroot>
int RunTool::DoRun(void) {
  int pid_fd = -1;

  //
  // if we were given a pipefd, then communicate the app child's PID
  //
  if (!opts.PIDFifo.empty()) {
    pid_fd = ::open(opts.PIDFifo.c_str(), O_WRONLY);
    if (pid_fd < 0) {
      int err = errno;
      HumanOut() << llvm::formatv("failed to open pid fifo: {0}\n",
                                  strerror(err));
    }
  }

  if (WillChroot || LivingDangerously) {
    if (::getuid() > 0) {
      HumanOut() << "must be root\n";
      return 1;
    }
  }

  auto drop_privileges = [&](void) -> void {
    if (!opts.Group.empty()) {
      unsigned gid = atoi(opts.Group.c_str());

      if (::setgid(gid) < 0) {
        int err = errno;
        HumanOut() << llvm::formatv("setgid failed: {0}", strerror(err));
      }
    }

    if (!opts.User.empty()) {
      unsigned uid = atoi(opts.User.c_str());

      if (::setuid(uid) < 0) {
        int err = errno;
        HumanOut() << llvm::formatv("setuid failed: {0}", strerror(err));
      }
    }
  };

  int ret_val = -1;

#if 0 /* is this necessary? */
  if (::mount(opts.sysroot, opts.sysroot, "", MS_BIND, nullptr) < 0)
    fprintf(stderr, "bind mounting %s failed : %s\n", opts.sysroot,
            strerror(errno));
#endif

  __BEGIN_MOUNTS__

  fs::path proc_path = fs::path(opts.sysroot) / "proc";
  ScopedMount<WillChroot> proc_mnt(*this,
                                   "proc",
                                   proc_path.c_str(),
                                   "proc",
                                   MS_NOSUID | MS_NODEV | MS_NOEXEC,
                                   nullptr);

  fs::path sys_path = fs::path(opts.sysroot) / "sys";
  ScopedMount<WillChroot> sys_mnt(*this,
                                  "sys",
                                  sys_path.c_str(),
                                  "sysfs",
                                  MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
                                  nullptr);

  //
  // command-line bind mounts
  //
  std::list<fs::path>                CmdLineBindMountChrootedDirs;
  std::list<ScopedMount<WillChroot>> CmdLineBindMounts;

  for (const std::string &Dir : opts.BindMountDirs) {
    fs::path &chrooted_dir =
        CmdLineBindMountChrootedDirs.emplace_back(fs::path(opts.sysroot) / Dir);
    fs::create_directories(chrooted_dir);

    CmdLineBindMounts.emplace_back(*this,
                                   Dir.c_str(),
                                   chrooted_dir.c_str(),
                                   "",
                                   MS_BIND,
                                   nullptr);
  }

#if 0
  //
  // common bind mounts
  //
  fs::path dev_path = fs::path(opts.sysroot) / "dev";
  ScopedMount<WillChroot> dev_mnt(*this,
                                  "udev",
                                  dev_path.c_str(),
                                  "devtmpfs",
                                  MS_NOSUID,
                                  "mode=0755");

  fs::path dev_pts_path = fs::path(opts.sysroot) / "dev" / "pts";
  ScopedMount<WillChroot> dev_pts_mnt(*this,
                                      "devpts",
                                      dev_pts_path.c_str(),
                                      "devpts",
                                      MS_NOSUID | MS_NOEXEC,
                                      "mode=0620,gid=5");

  fs::path dev_shm_path = fs::path(opts.sysroot) / "dev" / "shm";
  ScopedMount<WillChroot> dev_shm_mnt(*this,
                                      "shm",
                                      dev_shm_path.c_str(),
                                      "tmpfs",
                                      MS_NOSUID | MS_NODEV,
                                      "mode=1777");

  fs::path tmp_path = fs::path(opts.sysroot) / "tmp";
  ScopedMount<WillChroot> tmp_mnt(*this,
                                  "tmp",
                                  tmp_path.c_str(),
                                  "tmpfs",
                                  MS_NOSUID | MS_NODEV | MS_STRICTATIME,
                                  "mode=1777");
#endif

#define __BIND_MOUNT_DIR(name, dir)                                            \
  fs::path _##name##_path;                                                     \
  try {                                                                        \
    _##name##_path = fs::canonical(dir);                                       \
  } catch (...) {                                                              \
    ;                                                                          \
  }                                                                            \
                                                                               \
  fs::path _##chrooted_##name = fs::path(opts.sysroot) / dir;                 \
                                                                               \
  if (!_##name##_path.empty())                                                 \
    fs::create_directories(_##chrooted_##name);                                \
                                                                               \
  ScopedMount<WillChroot> name##_mnt(*this,                                    \
                                     _##name##_path.c_str(),                   \
                                     _##chrooted_##name.c_str(),               \
                                     "",                                       \
                                     MS_BIND,                                  \
                                     nullptr);

  __BIND_MOUNT_DIR(dev, "/dev")
  __BIND_MOUNT_DIR(run, "/run")
  __BIND_MOUNT_DIR(var, "/var")
  __BIND_MOUNT_DIR(tmp, "/tmp")
  __BIND_MOUNT_DIR(etc, "/etc")
  __BIND_MOUNT_DIR(libnvram, "/firmadyne/libnvram")

#undef __BIND_MOUNT_DIR

#define __BIND_MOUNT_FILE(name, filepath)                                      \
  fs::path _##name##_path;                                                     \
  try {                                                                        \
    _##name##_path = fs::canonical(filepath);                                  \
  } catch (...) {                                                              \
    ;                                                                          \
  }                                                                            \
                                                                               \
  fs::path _##chrooted_##name = fs::path(opts.sysroot) / filepath;             \
                                                                               \
  if (!_##name##_path.empty())                                                 \
    touch(_##chrooted_##name.c_str());                                         \
                                                                               \
  ScopedMount<WillChroot> name##_mnt(*this,                                    \
                                     _##name##_path.c_str(),                   \
                                     _##chrooted_##name.c_str(), "", MS_BIND,  \
                                     nullptr);


#if 0 /* already bind mounted /etc */
  __BIND_MOUNT_FILE(resolv_conf,  "/etc/resolv.conf")
  __BIND_MOUNT_FILE(etc_passwd,   "/etc/passwd")
  __BIND_MOUNT_FILE(etc_group,    "/etc/group")
  __BIND_MOUNT_FILE(etc_shadow,   "/etc/shadow")
  __BIND_MOUNT_FILE(etc_nsswitch, "/etc/nsswitch.conf")
  __BIND_MOUNT_FILE(etc_hosts,    "/etc/hosts")
#endif

#undef __BIND_MOUNT_FILE

  //
  // code recovery fifo. why don't we use an anonymous pipe? because the
  // program being recompiled may decide to close all the open file descriptors
  //
  std::string fifo_dir;
  if (WillChroot)
    fifo_dir = opts.sysroot;
  fifo_dir.append("/tmp/jove.XXXXXX");

  if (!mkdtemp(&fifo_dir[0])) {
    int err = errno;
    throw std::runtime_error("failed to make temporary directory: " +
                             std::string(strerror(err)));
  }

  if (::chmod(fifo_dir.c_str(), 0777) < 0) {
    int err = errno;
    throw std::runtime_error("failed to change permissions of temporary directory: " +
                             std::string(strerror(err)));
  }

  std::string fifo_path = fifo_dir + "/jove.fifo";
  if (mkfifo(fifo_path.c_str(), 0666) < 0) {
    int err = errno;
    HumanOut() << llvm::formatv("mkfifo failed : %s\n", strerror(err));
    return 1;
  }

  if (::chmod(fifo_path.c_str(), 0666) < 0) {
    int err = errno;
    throw std::runtime_error("failed to change permissions of temporary fifo: " +
                             std::string(strerror(err)));
  }

  fs::path fifo_file_path = fs::canonical(fifo_path);

  std::string fifo_path_under_sysroot;
  if (WillChroot)
    fifo_path_under_sysroot = "/" + fs::relative(fifo_file_path, fs::canonical(opts.sysroot)).string();

  //
  // create thread reading from fifo
  //
  pthread_t recover_thd;
  if (pthread_create(&recover_thd, nullptr, (void *(*)(void *))recover_proc,
                     (void *)fifo_file_path.c_str()) != 0) {
    HumanOut() << "failed to create recover_proc thread\n";
    return 1;
  }

  //
  // parse jv
  //
  if (has_jv) {
    ReadJvFromFile(jvfp, jv);

    disas = std::make_unique<disas_t>();
    tcg = std::make_unique<tiny_code_generator_t>();
    symbolizer = std::make_unique<symbolizer_t>();
    Recovery = std::make_unique<CodeRecovery>(jv, *disas, *tcg, *symbolizer);
  }

  int rfd = -1;
  int wfd = -1;

  if (LivingDangerously) {
    //
    // this pipe will be used to make sure we don't proceed further unless the
    // execve(2) has already happened (close-on-exec)
    //
    {
      int pipefd[2] = {-1, -1};
      if (::pipe(pipefd) < 0) {
        HumanOut() << "pipe(2) failed. bug?\n";
        return 1;
      }

      rfd = pipefd[0];
      wfd = pipefd[1];
    }

    //
    // danger zone: this is where we modify the root file system
    //

    //
    // (1) create hard links to pre-existing binaries with .jove.sav suffix
    //
    for (const binary_t &binary : jv.Binaries) {
      if (binary.IsExecutable)
        continue;
      if (binary.IsVDSO)
        continue;
      if (binary.IsDynamicLinker)
        continue;

      std::string sav_path = binary.Path + ".jove.sav";
      if (::link(binary.Path.c_str(), sav_path.c_str()) < 0) {
        int err = errno;
        HumanOut() << llvm::formatv("failed to create hard link for {0}: {1}\n",
                                    binary.Path, strerror(err));
        return 1;
      }
    }

    //
    // (2) copy recompiled binaries to root filesystem
    //
    for (const binary_t &binary : jv.Binaries) {
      if (binary.IsExecutable)
        continue;
      if (binary.IsVDSO)
        continue;
      if (binary.IsDynamicLinker)
        continue;

      fs::path chrooted_path = fs::path(opts.sysroot) / binary.Path;
      std::string new_path = binary.Path + ".jove.new";

      if (::link(chrooted_path.c_str(), new_path.c_str()) < 0) {
        if (IsVerbose()) {
          int err = errno;
          HumanOut() << llvm::formatv("failed to create hard link {0} -> {1}: {2}\n",
                                      chrooted_path.c_str(), new_path, strerror(err));
        }

        //
        // link may fail if src and dst are in different file systems. fallback
        // to regular copy file
        //
        try {
          fs::copy_file(chrooted_path, new_path);
        } catch (...) {
          HumanOut() << llvm::formatv(
              "failed to copy {0} to {1}\n",
              chrooted_path.c_str(), new_path.c_str());
          return 1;
        }
      }
    }
  }

  //
  // now actually exec the given executable
  //
  fs::path prog_path =
      WillChroot ? opts.Prog : fs::path(opts.sysroot) / opts.Prog;

  pid_t pid = -1;
  try {
    pid = jove::RunExecutable(
        prog_path.c_str(),
        [&](auto Arg) {
          if (!opts.ArgsFromFile.empty()) {
            std::ifstream ifs(opts.ArgsFromFile);

            while (ifs) {
              std::string arg_entry;
              char ch;
              while (ifs.read(&ch, sizeof(ch))) {
                if (ch == '\0')
                  break;

                arg_entry.push_back(ch);
              }

              if (!arg_entry.empty())
                Arg(arg_entry);
            }
          } else {
            Arg(prog_path.string());

            for (const std::string &s : opts.Args)
              Arg(s);
          }
        },
        [&](auto Env) {
          if (!opts.EnvFromFile.empty()) {
            std::ifstream ifs(opts.EnvFromFile);

            while (ifs) {
              std::string env_entry;
              char ch;
              while (ifs.read(&ch, sizeof(ch))) {
                if (ch == '\0')
                  break;

                env_entry.push_back(ch);
              }

              if (!env_entry.empty())
                Env(env_entry);
            }
          } else {
            InitWithEnviron(Env);
          }

          std::string fifo_env("JOVE_RECOVER_FIFO=");
          fifo_env.append(WillChroot ? fifo_path_under_sysroot.c_str()
                                     : fifo_file_path.c_str());

          Env(fifo_env);

          if (IsVerbose())
            HumanOut() << fifo_env << '\n';

          //
          // XXX DISABLE GLIBC IFUNCS
          //
#if defined(TARGET_X86_64)
          Env("GLIBC_TUNABLES=glibc.cpu.hwcaps="
              "-AVX,"
              "-AVX2,"
              "-AVX_Usable,"
              "-AVX2_Usable,"
              "-AVX512F_Usable,"
              "-SSE4_1,"
              "-SSE4_2,"
              "-SSSE3,"
              "-Fast_Unaligned_Load,"
              "-ERMS,"
              "-AVX_Fast_Unaligned_Load");
#elif defined(TARGET_I386)
          Env("GLIBC_TUNABLES=glibc.cpu.hwcaps="
              "-SSE4_1,"
              "-SSE4_2,"
              "-SSSE3,"
              "-Fast_Rep_String,"
              "-Fast_Unaligned_Load,"
              "-SSE2");
#endif

          Env("LD_BIND_NOW=1"); /* disable lazy linking (please) */

          if (fs::exists("/firmadyne/libnvram.so")) /* XXX firmadyne */
            Env("LD_PRELOAD=/firmadyne/libnvram.so");

          for (const std::string &s : opts.Envs)
            Env(s);
        },
        std::string(),
        std::string(),
        [&](const char **, const char **) {
          if (LivingDangerously) {
            //
            // close unused read end of pipe
            //
            ::close(rfd);

            //
            // make the write end of the pipe be close-on-exec
            //
            if (::fcntl(wfd, F_SETFD, FD_CLOEXEC) < 0) {
              int err = errno;
              HumanOut() << llvm::formatv(
                  "failed to set pipe write end close-on-exec: {0}\n",
                  strerror(err));
            }
          }

          if (WillChroot) {
            if (::chroot(opts.sysroot.c_str()) < 0) {
              int err = errno;

              throw std::runtime_error(std::string("chroot failed: ") +
                                       strerror(err));
            }

            const char *working_dir = !opts.ChangeDirectory.empty()
                                          ? opts.ChangeDirectory.c_str()
                                          : "/";

            if (::chdir(working_dir) < 0) {
              int err = errno;

              throw std::runtime_error(std::string("chdir failed: ") +
                                       strerror(err));
            }
          }

          if (LivingDangerously) {
            //
            // (3) perform the renames!!! do this as close as possible before
            // execve
            //
            if (IsVerbose())
              HumanOut() << (__ANSI_CYAN
                             "*** modifying root file system ***" __ANSI_NORMAL_COLOR
                             "\n");

            for (const binary_t &binary : jv.Binaries) {
              if (binary.IsExecutable)
                continue;
              if (binary.IsVDSO)
                continue;
              if (binary.IsDynamicLinker)
                continue;

              std::string new_path = binary.Path + ".jove.new";

              if (::rename(new_path.c_str(), binary.Path.c_str()) < 0) {
                int err = errno;

                HumanOut() << llvm::formatv(__ANSI_BOLD_RED
                    "rename of {0} to {1} failed: {2}\n" __ANSI_NORMAL_COLOR,
                    new_path.c_str(),
                    binary.Path.c_str(),
                    strerror(err));
              }
            }

            if (IsVerbose())
              HumanOut()
                  << (__ANSI_CYAN
                      "*** modified root file system ***" __ANSI_NORMAL_COLOR
                      "\n");
          }

          drop_privileges();
        });
  } catch (const std::exception &e) {
#if 0
    if (LivingDangerously)
      ::close(wfd); /* close-on-exec didn't happen */
#endif

    HumanOut() << e.what() << '\n';

    exit(1); /* exception must have been thrown in (forked) child process XXX */
  }

  IgnoreCtrlC();

  //
  // if we were given a pipefd, then communicate the app child's PID
  //
  if (!(pid_fd < 0)) {
    uint64_t u64 = pid;
    ssize_t ret = robust_write(pid_fd, &u64, sizeof(uint64_t));

    if (ret != sizeof(uint64_t))
      HumanOut() << llvm::formatv("failed to write to pid_fd: {0}\n", ret);

    if (::close(pid_fd) < 0) {
      int err = errno;
      HumanOut() << llvm::formatv("failed to close pid_fd: {0}\n",
                                  strerror(err));
    }
  }

  if (LivingDangerously) {
    ::close(wfd);

    ssize_t ret;
    do {
      uint8_t byte;
      ret = ::read(rfd, &byte, 1);
    } while (!(ret <= 0));

    /* if we got here, the other end of the pipe must have been closed,
     * most likely by close-on-exec */

    if (usleep(opts.DangerousSleep1) < 0) { /* wait for the dynamic linker to load the program */
      int err = errno;
      HumanOut() << llvm::formatv("usleep failed: {0}\n", strerror(err));
    }

    if (IsVerbose())
      HumanOut() << (__ANSI_MAGENTA
                     "*** restoring root file system ***" __ANSI_NORMAL_COLOR
                     "\n");

    //
    // (4) perform the renames to undo the changes we made to the root
    // filesystem all DSO's except those dynamically loaded (we do that after the second sleep)
    //
    bool HaveDynamicallyLoaded = false;
    for (const binary_t &binary : jv.Binaries) {
      if (binary.IsExecutable)
        continue;
      if (binary.IsVDSO)
        continue;
      if (binary.IsDynamicLinker)
        continue;
      if (binary.IsDynamicallyLoaded) {
        HaveDynamicallyLoaded = true;
        continue;
      }

      std::string sav_path = binary.Path + ".jove.sav";

      if (::rename(sav_path.c_str(), binary.Path.c_str()) < 0) {
        int err = errno;
        HumanOut() << llvm::formatv(__ANSI_BOLD_RED "rename of {0} to {1} failed: {2}\n"
                                    __ANSI_NORMAL_COLOR,
                                    sav_path.c_str(),
                                    binary.Path.c_str(),
                                    strerror(err));
      }
    }

    if (HaveDynamicallyLoaded) {
      usleep(opts.DangerousSleep2); /* wait for the dynamic linker to load the rest */

      //
      // (5) perform the renames to undo the changes we made to the root filesystem
      // for all the dynamically loaded DSOs
      //
      for (const binary_t &binary : jv.Binaries) {
        if (binary.IsExecutable)
          continue;
        if (binary.IsVDSO)
          continue;
        if (binary.IsDynamicLinker)
          continue;
        if (!binary.IsDynamicallyLoaded)
          continue;

        std::string sav_path = binary.Path + ".jove.sav";

        if (::rename(sav_path.c_str(), binary.Path.c_str()) < 0) {
          int err = errno;
          HumanOut() << llvm::formatv(
              "rename of {0} to {1} failed: {2}\n",
              sav_path.c_str(), binary.Path.c_str(), strerror(err));
        }
      }
    }

    FileSystemRestored.store(true);

    if (IsVerbose())
      HumanOut() << (__ANSI_MAGENTA
                     "*** restored root file system ***" __ANSI_NORMAL_COLOR
                     "\n");

    ::close(rfd);
  }

  //
  // wait for process to exit
  //
  ret_val = WaitForProcessToExit(pid);

  //
  // optionally sleep
  //
  if (unsigned sec = opts.Sleep) {
    HumanOut() << llvm::formatv("sleeping for {0} seconds...\n", sec);
    for (unsigned t = 0; t < sec; ++t) {
      sleep(1);

      if (interrupt_sleep.load()) {
        if (IsVerbose())
          HumanOut() << "sleep interrupted\n";
        break;
      }

      if (recovered_ch.load()) {
        if (IsVerbose())
          HumanOut() << "sleep interrupted by jove-recover\n";
        sleep(std::min<unsigned>(sec - t, 3));
        break;
      }

      HumanOut() << ".";
    }
  }

  //
  // cancel the thread reading the fifo
  //
  if (pthread_cancel(recover_thd) != 0) {
    HumanOut() << "error: failed to cancel recover_proc thread\n";

    void *retval;
    if (pthread_join(recover_thd, &retval) != 0)
      HumanOut() << "error: pthread_join failed\n";
  } else {
    void *recover_retval;
    if (pthread_join(recover_thd, &recover_retval) != 0)
      HumanOut() << "error: pthread_join failed\n";
    else if (recover_retval != PTHREAD_CANCELED)
      HumanOut() << llvm::formatv(
              "warning: expected retval to equal PTHREAD_CANCELED, but is {0}\n",
              recover_retval);
  }

  fs::remove_all(fifo_dir);

#if 0 /* is this necessary? */
  if (::umount2(opts.sysroot, 0) < 0)
    fprintf(stderr, "unmounting %s failed : %s\n", opts.sysroot, strerror(errno));
#endif

  __END_MOUNTS__

  drop_privileges();

  if (has_jv && WasDecompilationModified.load()) {
    jv.InvalidateFunctionAnalyses();

    WriteJvToFile(jvfp, jv);
  }

  {
    //
    // robust means of determining whether jove-recover has run
    //
    char ch = recovered_ch.load();
    if (ch)
      return ch; /* return char jove-loop will recognize */
  }

  return ret_val;
}

void touch(const fs::path &p) {
  fs::create_directories(p.parent_path());
  if (!fs::exists(p))
    ::close(::open(p.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666));
}

void *recover_proc(const char *fifo_path) {
  assert(pTool);
  RunTool &tool = *pTool;

  //
  // ATTENTION: this thread has to be cancel-able.
  //

  int recover_fd;
  do
    recover_fd = ::open(fifo_path, O_RDONLY);
  while (recover_fd < 0 && errno == EINTR);

  if (recover_fd < 0) {
    int err = errno;
    tool.HumanOut() << llvm::formatv("recover: failed to open fifo at {0} ({1})\n",
                                     fifo_path, strerror(err));
    return nullptr;
  }

  void (*cleanup_handler)(void *) = [](void *arg) -> void {
    int fd = reinterpret_cast<long>(arg);
    if (::close(fd) < 0) {
      int err = errno;
      throw std::runtime_error(
          std::string("recover_proc: cleanup_handler: close failed: ") +
          strerror(err));
    }
  };

  pthread_cleanup_push(cleanup_handler, reinterpret_cast<void *>(recover_fd));

  for (;;) {
    char ch;

    {
      // NOTE: read is a cancellation point
      ssize_t ret = ::read(recover_fd, &ch, 1);
      if (ret != 1) {
        if (ret < 0) {
          int err = errno;

          if (err == EINTR)
            continue;

          tool.HumanOut() << llvm::formatv("recover: read failed ({0})\n",
                                           strerror(err));
        } else if (ret == 0) {
          // NOTE: open is a cancellation point
          int new_recover_fd = ::open(fifo_path, O_RDONLY);
          if (new_recover_fd < 0) {
            int err = errno;
            tool.HumanOut() << llvm::formatv(
                "recover: failed to open fifo at {0} ({1})\n", fifo_path,
                strerror(err));
            return nullptr;
          }

          if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, nullptr) != 0) {
            tool.HumanOut() << "pthread_setcancelstate failed\n";
          }

          assert(new_recover_fd != recover_fd);

          if (::dup2(new_recover_fd, recover_fd) < 0) {
            int err = errno;
            tool.HumanOut() << llvm::formatv(
                "recover: failed to dup2({0}, {1})) ({2})\n", new_recover_fd,
                recover_fd, strerror(err));
          }

          if (::close(new_recover_fd) < 0) {
            int err = errno;
            tool.HumanOut() << llvm::formatv("recover_proc: close failed ({0})\n",
                                        strerror(err));
          }

          if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, nullptr) != 0)
            tool.HumanOut() << "pthread_setcancelstate failed\n";

          continue;
        } else {
          tool.HumanOut() << llvm::formatv("recover: read gave {0}\n", ret);
        }

        break;
      }
    }

    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, nullptr) != 0)
      tool.HumanOut() << "pthread_setcancelstate failed\n";

    {
      static bool FirstTime = true;

      if (unlikely(FirstTime)) {
        FirstTime = false;

        if (LivingDangerously)
          while (!FileSystemRestored.load())
            usleep(10000 /* 0.01 s */);
      }
    }

    //
    // we assume ch is loaded with a byte from the fifo. it's got to be either
    // 'f', 'F', 'b', 'a', or 'r'.
    //
    assert(tool.Recovery);

    recovered_ch.store(ch);

    auto do_recover = [&](void) -> std::string {
      if (ch == 'f') {
        struct {
          uint32_t BIdx;
          uint32_t BBIdx;
        } Caller;

        struct {
          uint32_t BIdx;
          uint32_t FIdx;
        } Callee;

        {
          ssize_t ret;

          ret = robust_read(recover_fd, &Caller.BIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));

          ret = robust_read(recover_fd, &Caller.BBIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));

          ret = robust_read(recover_fd, &Callee.BIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));

          ret = robust_read(recover_fd, &Callee.FIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));
        }

        return tool.Recovery->RecoverDynamicTarget(Caller.BIdx,
                                                   Caller.BBIdx,
                                                   Callee.BIdx,
                                                   Callee.FIdx);
      } else if (ch == 'b') {
        struct {
          uint32_t BIdx;
          uint32_t BBIdx;
        } IndBr;

        uintptr_t Addr;

        {
          ssize_t ret;

          ret = robust_read(recover_fd, &IndBr.BIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));

          ret = robust_read(recover_fd, &IndBr.BBIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));

          ret = robust_read(recover_fd, &Addr, sizeof(uintptr_t));
          assert(ret == sizeof(uintptr_t));
        }

        return tool.Recovery->RecoverBasicBlock(IndBr.BIdx,
                                                IndBr.BBIdx,
                                                Addr);
      } else if (ch == 'F') {
        struct {
          uint32_t BIdx;
          uint32_t BBIdx;
        } IndCall;

        struct {
          uint32_t BIdx;
          uintptr_t Addr;
        } Callee;

        {
          ssize_t ret;

          ret = robust_read(recover_fd, &IndCall.BIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));

          ret = robust_read(recover_fd, &IndCall.BBIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));

          ret = robust_read(recover_fd, &Callee.BIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));

          ret = robust_read(recover_fd, &Callee.Addr, sizeof(uintptr_t));
          assert(ret == sizeof(uintptr_t));
        }

        return tool.Recovery->RecoverFunction(IndCall.BIdx,
                                              IndCall.BBIdx,
                                              Callee.BIdx,
                                              Callee.Addr);
      } else if (ch == 'a') {
        struct {
          uint32_t BIdx;
          uint32_t FIdx;
        } NewABI;

        {
          ssize_t ret;

          ret = robust_read(recover_fd, &NewABI.BIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));

          ret = robust_read(recover_fd, &NewABI.FIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));
        }

        return tool.Recovery->RecoverABI(NewABI.BIdx,
                                         NewABI.FIdx);
      } else if (ch == 'r') {
        struct {
          uint32_t BIdx;
          uint32_t BBIdx;
        } Call;

        {
          ssize_t ret;

          ret = robust_read(recover_fd, &Call.BIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));

          ret = robust_read(recover_fd, &Call.BBIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));
        }

        return tool.Recovery->Returns(Call.BIdx,
                                      Call.BBIdx);
      } else {
        std::string ch_s;
        ch_s.push_back(ch);
        throw std::runtime_error("unknown character \"" + ch_s + "\"");
      }
    };

    try {
      std::string msg = do_recover();

      if (!msg.empty()) {
        tool.WasDecompilationModified.store(true);

        tool.HumanOut() << msg << '\n';
      }
    } catch (const std::exception &e) {
      tool.HumanOut() << llvm::formatv(
          __ANSI_RED "failed to recover: {0}" __ANSI_NORMAL_COLOR "\n",
          e.what());
    }

    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, nullptr) != 0)
      tool.HumanOut() << "pthread_setcancelstate failed\n";
  }

  // (Clean-up handlers are not called if the thread terminates by performing a
  // return from the thread start function.)
  pthread_cleanup_pop(1 /* execute */);

  return nullptr;
}

}
