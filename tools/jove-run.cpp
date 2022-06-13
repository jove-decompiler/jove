#include "tool.h"
#include <atomic>
#include <boost/dll/runtime_symbol_info.hpp>
#include <boost/filesystem.hpp>
#include <cinttypes>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>
#include <string>
#include <thread>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <pthread.h>

#include "jove_macros.h"

namespace fs = boost::filesystem;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

struct RunTool : public Tool {
  struct Cmdline {
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
    cl::opt<bool> Verbose;
    cl::alias VerboseAlias;
    cl::opt<std::string> ChangeDirectory;
    cl::opt<bool> ForeignLibs;
    cl::alias ForeignLibsAlias;
    cl::opt<std::string> HumanOutput;
    cl::opt<bool> Silent;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Prog(cl::Positional, cl::desc("prog"), cl::Required,
               cl::value_desc("filename"), cl::cat(JoveCategory)),

          Args("args", cl::CommaSeparated,
               cl::value_desc("arg_1,arg_2,...,arg_n"),
               cl::desc("Program arguments"), cl::cat(JoveCategory)),

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

          Verbose("verbose", cl::desc("Output helpful messages for debugging"),
                  cl::cat(JoveCategory)),

          VerboseAlias("v", cl::desc("Alias for --verbose."),
                       cl::aliasopt(Verbose), cl::cat(JoveCategory)),

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
                 cl::cat(JoveCategory)) {}
  } opts;

public:
  RunTool() : opts(JoveCategory) {}

  int Run(void);

  template <bool WillChroot>
  int DoRun(void);
};

JOVE_REGISTER_TOOL("run", RunTool);

static fs::path jv_path;
static RunTool *pTool;

static bool WillChroot;
static bool LivingDangerously;

int RunTool::Run(void) {
  pTool = this;

  for (char *dashdash_arg : dashdash_args)
    opts.Args.push_back(dashdash_arg);

  if (!opts.HumanOutput.empty())
    HumanOutToFile(opts.HumanOutput);

  //
  // get paths to stuff
  //
  jv_path = fs::read_symlink(fs::path(opts.sysroot) / ".jv");
  if (!fs::exists(jv_path)) {
    HumanOut() << llvm::formatv("recover: no jv found at {0}\n",
                                jv_path.c_str());
    return 1;
  }

  WillChroot = !(opts.NoChroot || opts.ForeignLibs);
  LivingDangerously = !WillChroot && !opts.ForeignLibs;

  return !WillChroot ? DoRun<false>() :
                       DoRun<true>();
}

//
// set when jove-recover has been run (if nonzero then either 'f', 'b', 'F', 'r')
//
static std::atomic<char> recovered_ch;
static std::atomic<bool> FileSystemRestored(false);

static void *recover_proc(const char *fifo_path);

template <bool IsRead>
static ssize_t robust_read_or_write(int fd, void *const buf, const size_t count) {
  uint8_t *const _buf = (uint8_t *)buf;

  unsigned n = 0;
  do {
    unsigned left = count - n;

    ssize_t ret = IsRead ? read(fd, &_buf[n], left) :
                          write(fd, &_buf[n], left);

    if (ret == 0)
      return -EIO;

    if (ret < 0) {
      int err = errno;

      if (err == EINTR)
        continue;

      return -err;
    }

    n += ret;
  } while (n != count);

  return n;
}


static ssize_t robust_read(int fd, void *const buf, const size_t count) {
  return robust_read_or_write<true /* r */>(fd, buf, count);
}

static ssize_t robust_write(int fd, const void *const buf, const size_t count) {
  return robust_read_or_write<false /* w */>(fd, const_cast<void *>(buf), count);
}

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
      int ret = mount(this->source,
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
          if (tool.opts.Verbose)
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
      int ret = umount2(this->target, 0);

      if (ret < 0) {
        int err = errno;

        switch (err) {
        case EBUSY:
          if (retries++ < MAX_UMOUNT_RETRIES) {
            if (tool.opts.Verbose)
              tool.HumanOut() << llvm::formatv("retrying umount of {0} shortly...\n", this->target);

            usleep(10000 /* 0.01 s */);
          } else {
            tool.HumanOut() << llvm::formatv("unmounting %s failed: EBUSY...\n", this->target);
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
        /* unmount suceeded */
        break;
      }
    }
  }
};

static void touch(const fs::path &);

template <bool WillChroot>
int RunTool::DoRun(void) {
#if 0 /* is this necessary? */
  if (mount(opts.sysroot, opts.sysroot, "", MS_BIND, nullptr) < 0)
    fprintf(stderr, "bind mounting %s failed : %s\n", opts.sysroot,
            strerror(errno));
#endif

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
  // create recover fifo
  //
  fs::path recover_fifo_path =
      WillChroot ? fs::path(opts.sysroot) / "jove-recover.fifo"
                 : "/jove-recover.fifo";
  unlink(recover_fifo_path.c_str());
  if (mkfifo(recover_fifo_path.c_str(), 0666) < 0) {
    HumanOut() << llvm::formatv("mkfifo failed : %s\n", strerror(errno));
    return 1;
  }

  //
  // create thread reading from fifo
  //
  pthread_t recover_thd;
  if (pthread_create(&recover_thd, nullptr, (void *(*)(void *))recover_proc,
                     (void *)recover_fifo_path.c_str()) != 0) {
    HumanOut() << "failed to create recover_proc thread\n";
    return 1;
  }

  const bool LivingDangerously = !WillChroot && !opts.ForeignLibs;

  //
  // parse decompilation
  //
  decompilation_t decompilation;

  if (LivingDangerously)
    ReadDecompilationFromFile(jv_path.c_str(), decompilation);

  int rfd = -1;
  int wfd = -1;

  if (LivingDangerously) {
    //
    // this pipe will be used to make sure we don't proceed further unless the
    // execve(2) has already happened (close-on-exec)
    //
    {
      int pipefd[2] = {-1, -1};
      if (pipe(pipefd) < 0) {
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
    for (const binary_t &binary : decompilation.Binaries) {
      if (binary.IsExecutable)
        continue;
      if (binary.IsVDSO)
        continue;
      if (binary.IsDynamicLinker)
        continue;

      std::string sav_path = binary.Path + ".jove.sav";
      if (link(binary.Path.c_str(), sav_path.c_str()) < 0) {
        int err = errno;
        HumanOut() << llvm::formatv("failed to create hard link for {0}: {1}\n",
                                    binary.Path, strerror(err));
        return 1;
      }
    }

    //
    // (2) copy recompiled binaries to root filesystem
    //
    for (const binary_t &binary : decompilation.Binaries) {
      if (binary.IsExecutable)
        continue;
      if (binary.IsVDSO)
        continue;
      if (binary.IsDynamicLinker)
        continue;

      fs::path chrooted_path = fs::path(opts.sysroot) / binary.Path;
      std::string new_path = binary.Path + ".jove.new";

      if (link(chrooted_path.c_str(), new_path.c_str()) < 0) {
        if (opts.Verbose) {
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
  // now actually fork and exec the given executable
  //
  int pid = fork();
  if (!pid) {
    if (LivingDangerously) {
      //
      // close unused read end of pipe
      //
      close(rfd);

      //
      // make the write end of the pipe be close-on-exec
      //
      if (fcntl(wfd, F_SETFD, FD_CLOEXEC) < 0) {
        int err = errno;
        HumanOut() << llvm::formatv(
            "failed to set pipe write end close-on-exec: {0}\n", strerror(err));
      }
    }

    if (WillChroot) {
      if (chroot(opts.sysroot.c_str()) < 0) {
        int err = errno;
        HumanOut() << llvm::formatv("chroot failed : {0}\n", strerror(err));
        return 1;
      }

      const char *working_dir =
          !opts.ChangeDirectory.empty() ?
          opts.ChangeDirectory.c_str() : "/";

      if (chdir(working_dir) < 0) {
        int err = errno;
        HumanOut() << llvm::formatv("chdir failed : {0}\n", strerror(err));
        return 1;
      }
    }

    //
    // compute environment
    //
    std::list<std::string> env_file_args;
    std::vector<const char *> env_vec;

    if (!opts.EnvFromFile.empty()) {
      std::ifstream ifs(opts.EnvFromFile);

      while (ifs) {
        std::string &env_entry = env_file_args.emplace_back();
        char ch;
        while (ifs.read(&ch, sizeof(ch))) {
          if (ch == '\0')
            break;

          env_entry.push_back(ch);
        }

        if (!env_entry.empty())
          env_vec.push_back(env_entry.c_str());
      }
    } else {
      //
      // initialize env from environ
      //
      for (char **p = ::environ; *p; ++p)
        env_vec.push_back(*p);
    }

#if defined(TARGET_X86_64)
    // <3 glibc
    env_vec.push_back("GLIBC_TUNABLES=glibc.cpu.hwcaps="
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
    // <3 glibc
    env_vec.push_back("GLIBC_TUNABLES=glibc.cpu.hwcaps="
                      "-SSE4_1,"
                      "-SSE4_2,"
                      "-SSSE3,"
                      "-Fast_Rep_String,"
                      "-Fast_Unaligned_Load,"
                      "-SSE2");
#endif

    env_vec.push_back("LD_BIND_NOW=1"); /* disable lazy linking (please) */

    if (fs::exists("/firmadyne/libnvram.so")) /* XXX firmadyne */
      env_vec.push_back("LD_PRELOAD=/firmadyne/libnvram.so");

    for (std::string &s : opts.Envs)
      env_vec.push_back(s.c_str());

    env_vec.push_back(nullptr);

    //
    // compute args
    //
    std::list<std::string> args_file_args;
    std::vector<const char *> arg_vec;

    fs::path prog_path =
        WillChroot ? opts.Prog : fs::path(opts.sysroot) / opts.Prog;

    if (!opts.ArgsFromFile.empty()) {
      std::ifstream ifs(opts.ArgsFromFile);

      while (ifs) {
        std::string &arg_entry = args_file_args.emplace_back();
        char ch;
        while (ifs.read(&ch, sizeof(ch))) {
          if (ch == '\0')
            break;

          arg_entry.push_back(ch);
        }

        if (!arg_entry.empty())
          arg_vec.push_back(arg_entry.c_str());
      }
    } else {
      arg_vec.push_back(prog_path.c_str());

      for (std::string &s : opts.Args)
        arg_vec.push_back(s.c_str());
    }

    arg_vec.push_back(nullptr);

    if (opts.Verbose)
      print_command(&arg_vec[0]);

    if (LivingDangerously) {
      if (opts.Verbose)
        HumanOut() << (__ANSI_CYAN "modifying root file system..." __ANSI_NORMAL_COLOR "\n");

      //
      // (3) perform the renames!!!
      //
      for (const binary_t &binary : decompilation.Binaries) {
        if (binary.IsExecutable)
          continue;
        if (binary.IsVDSO)
          continue;
        if (binary.IsDynamicLinker)
          continue;

        std::string new_path = binary.Path + ".jove.new";

        if (rename(new_path.c_str(), binary.Path.c_str()) < 0) {
          int err = errno;
          HumanOut() << llvm::formatv("rename of {0} to {1} failed: {2}\n",
                                      new_path.c_str(),
                                      binary.Path.c_str(),
                                      strerror(err));
        }
      }

      if (opts.Verbose)
        HumanOut() << (__ANSI_CYAN "modified root file system." __ANSI_NORMAL_COLOR "\n");
    }

    execve(arg_vec[0],
           const_cast<char **>(&arg_vec[0]),
           const_cast<char **>(&env_vec[0]));

    int err = errno;
    HumanOut() << llvm::formatv("execve failed: {0}\n", strerror(err));

    if (LivingDangerously)
      close(wfd); /* close-on-exec didn't happen */

    return 1;
  }

  IgnoreCtrlC();

  //
  // if we were given a pipefd, then communicate the app child's PID
  //
  if (char *env = getenv("JOVE_RUN_PIPEFD")) {
    int pipefd = atoi(env);

    uint64_t uint64 = pid;
    ssize_t ret = robust_write(pipefd, &uint64, sizeof(uint64_t));

    if (ret != sizeof(uint64_t))
      HumanOut() << llvm::formatv("failed to write to pipefd: {0}\n", ret);

    if (close(pipefd) < 0) {
      int err = errno;
      HumanOut() << llvm::formatv("failed to close pipefd: {0}\n",
                                  strerror(err));
    }
  }

  if (LivingDangerously) {
    close(wfd);

    ssize_t ret;
    do {
      uint8_t byte;
      ret = read(rfd, &byte, 1);
    } while (!(ret <= 0));

    /* if we got here, the other end of the pipe must have been closed,
     * most likely by close-on-exec */

    if (usleep(opts.DangerousSleep1) < 0) { /* wait for the dynamic linker to load the program */
      int err = errno;
      HumanOut() << llvm::formatv("usleep failed: {0}\n", strerror(err));
    }

    if (opts.Verbose)
      HumanOut() << (__ANSI_MAGENTA "restoring root file system..." __ANSI_NORMAL_COLOR "\n");

    //
    // (4) perform the renames to undo the changes we made to the root
    // filesystem all DSO's except those dynamically loaded (we do that after the second sleep)
    //
    bool HaveDynamicallyLoaded = false;
    for (const binary_t &binary : decompilation.Binaries) {
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

      if (rename(sav_path.c_str(), binary.Path.c_str()) < 0) {
        int err = errno;
        HumanOut() << llvm::formatv("rename of {0} to {1} failed: {2}\n",
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
      for (const binary_t &binary : decompilation.Binaries) {
        if (binary.IsExecutable)
          continue;
        if (binary.IsVDSO)
          continue;
        if (binary.IsDynamicLinker)
          continue;
        if (!binary.IsDynamicallyLoaded)
          continue;

        std::string sav_path = binary.Path + ".jove.sav";

        if (rename(sav_path.c_str(), binary.Path.c_str()) < 0) {
          int err = errno;
          HumanOut() << llvm::formatv(
              "rename of {0} to {1} failed: {2}\n",
              sav_path.c_str(), binary.Path.c_str(), strerror(err));
        }
      }
    }

    FileSystemRestored.store(true);

    if (opts.Verbose)
      HumanOut() << (__ANSI_MAGENTA "root file system restored." __ANSI_NORMAL_COLOR "\n");

    close(rfd);
  }

  //
  // wait for process to exit
  //
  int ret = WaitForProcessToExit(pid);

  //
  // optionally sleep
  //
  if (unsigned sec = opts.Sleep) {
    HumanOut() << llvm::formatv("sleeping for {0} seconds...\n", sec);
    for (unsigned t = 0; t < sec; ++t) {
      sleep(1);

      if (interrupt_sleep.load()) {
        if (opts.Verbose)
          HumanOut() << "sleep interrupted\n";
        break;
      }

      if (recovered_ch.load()) {
        if (opts.Verbose)
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

  if (unlink(recover_fifo_path.c_str()) < 0) {
    int err = errno;
    HumanOut() << llvm::formatv("unlink of recover pipe failed: {0}\n", strerror(err));
  }

#if 0 /* is this necessary? */
  if (umount2(opts.sysroot, 0) < 0)
    fprintf(stderr, "unmounting %s failed : %s\n", opts.sysroot, strerror(errno));
#endif

  {
    //
    // robust means of determining whether jove-recover has run
    //
    char ch = recovered_ch.load();
    if (ch)
      return ch; /* return char jove-loop will recognize */
  }

  return ret;
}

void touch(const fs::path &p) {
  fs::create_directories(p.parent_path());
  if (!fs::exists(p))
    close(open(p.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666));
}

void *recover_proc(const char *fifo_path) {
  assert(pTool);
  RunTool &tool = *pTool;

  //
  // ATTENTION: this thread has to be cancel-able.
  //

  int recover_fd;
  do
    recover_fd = open(fifo_path, O_RDONLY);
  while (recover_fd < 0 && errno == EINTR);

  if (recover_fd < 0) {
    int err = errno;
    tool.HumanOut() << llvm::formatv("recover: failed to open fifo at {0} ({1})\n",
                                     fifo_path, strerror(err));
    return nullptr;
  }

  void (*cleanup_handler)(void *) = [](void *arg) -> void {
    int fd = reinterpret_cast<long>(arg);
    if (close(fd) < 0) {
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
      ssize_t ret = read(recover_fd, &ch, 1);
      if (ret != 1) {
        if (ret < 0) {
          int err = errno;

          if (err == EINTR)
            continue;

          tool.HumanOut() << llvm::formatv("recover: read failed ({0})\n",
                                           strerror(err));
        } else if (ret == 0) {
          // NOTE: open is a cancellation point
          int new_recover_fd = open(fifo_path, O_RDONLY);
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

          if (dup2(new_recover_fd, recover_fd) < 0) {
            int err = errno;
            tool.HumanOut() << llvm::formatv(
                "recover: failed to dup2({0}, {1})) ({2})\n", new_recover_fd,
                recover_fd, strerror(err));
          }

          if (close(new_recover_fd) < 0) {
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
    recovered_ch.store(ch);
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

      int pid = fork();
      if (!pid) {
        char buff[256];
        snprintf(buff, sizeof(buff),
                 "--dyn-target=%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32,
                 Caller.BIdx,
                 Caller.BBIdx,
                 Callee.BIdx,
                 Callee.FIdx);

        std::vector<const char *> arg_vec = {"-d", jv_path.c_str(), buff};
        if (tool.opts.Verbose)
          tool.print_tool_command("recover", arg_vec);

        tool.exec_tool("recover", arg_vec);
        int err = errno;
        tool.HumanOut() << llvm::formatv("recover: exec failed: {0}\n",
                                         strerror(err));
        exit(1);
      }

      (void)tool.WaitForProcessToExit(pid);
    } else if (ch == 'b') {
      struct {
        uint32_t BIdx;
        uint32_t BBIdx;
      } IndBr;

      uintptr_t FileAddr;

      {
        ssize_t ret;

        ret = robust_read(recover_fd, &IndBr.BIdx, sizeof(uint32_t));
        assert(ret == sizeof(uint32_t));

        ret = robust_read(recover_fd, &IndBr.BBIdx, sizeof(uint32_t));
        assert(ret == sizeof(uint32_t));

        ret = robust_read(recover_fd, &FileAddr, sizeof(uintptr_t));
        assert(ret == sizeof(uintptr_t));
      }

      int pid = fork();
      if (!pid) {
        char buff[256];
        snprintf(buff, sizeof(buff),
                 "--basic-block=%" PRIu32 ",%" PRIu32 ",%" PRIuPTR,
                 IndBr.BIdx,
                 IndBr.BBIdx,
                 FileAddr);

        std::vector<const char *> arg_vec = {"-d", jv_path.c_str(), buff};
        if (tool.opts.Verbose)
          tool.print_tool_command("recover", arg_vec);

        tool.exec_tool("recover", arg_vec);
        int err = errno;
        tool.HumanOut() << llvm::formatv("recover: exec failed: {0}\n",
                                         strerror(err));
        exit(1);
      }

      (void)tool.WaitForProcessToExit(pid);
    } else if (ch == 'F') {
      struct {
        uint32_t BIdx;
        uint32_t BBIdx;
      } IndCall;

      struct {
        uint32_t BIdx;
        uintptr_t FileAddr;
      } Callee;

      {
        ssize_t ret;

        ret = robust_read(recover_fd, &IndCall.BIdx, sizeof(uint32_t));
        assert(ret == sizeof(uint32_t));

        ret = robust_read(recover_fd, &IndCall.BBIdx, sizeof(uint32_t));
        assert(ret == sizeof(uint32_t));

        ret = robust_read(recover_fd, &Callee.BIdx, sizeof(uint32_t));
        assert(ret == sizeof(uint32_t));

        ret = robust_read(recover_fd, &Callee.FileAddr, sizeof(uintptr_t));
        assert(ret == sizeof(uintptr_t));
      }

      int pid = fork();
      if (!pid) {
        char buff[256];
        snprintf(buff, sizeof(buff),
                 "--function=%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIuPTR,
                 IndCall.BIdx,
                 IndCall.BBIdx,
                 Callee.BIdx,
                 Callee.FileAddr);

        std::vector<const char *> arg_vec = {"-d", jv_path.c_str(), buff};
        if (tool.opts.Verbose)
          tool.print_tool_command("recover", arg_vec);

        tool.exec_tool("recover", arg_vec);
        int err = errno;
        tool.HumanOut() << llvm::formatv("recover: exec failed: {0}\n",
                                         strerror(err));
        exit(1);
      }

      (void)tool.WaitForProcessToExit(pid);
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

      int pid = fork();
      if (!pid) {
        char buff[256];
        snprintf(buff, sizeof(buff),
                 "--abi=%" PRIu32 ",%" PRIu32,
                 NewABI.BIdx,
                 NewABI.FIdx);

        std::vector<const char *> arg_vec = {"-d", jv_path.c_str(), buff};
        if (tool.opts.Verbose)
          tool.print_tool_command("recover", arg_vec);

        tool.exec_tool("recover", arg_vec);
        int err = errno;
        tool.HumanOut() << llvm::formatv("recover: exec failed: {0}\n",
                                         strerror(err));
        exit(1);
      }

      (void)tool.WaitForProcessToExit(pid);
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

      int pid = fork();
      if (!pid) {
        char buff[256];
        snprintf(buff, sizeof(buff),
                 "--returns=%" PRIu32 ",%" PRIu32,
                 Call.BIdx,
                 Call.BBIdx);

        std::vector<const char *> arg_vec = {"-d", jv_path.c_str(), buff};
        if (tool.opts.Verbose)
          tool.print_tool_command("recover", arg_vec);

        tool.exec_tool("recover", arg_vec);
        int err = errno;
        tool.HumanOut() << llvm::formatv("recover: exec failed: {0}\n",
                                         strerror(err));
        exit(1);
      }

      (void)tool.WaitForProcessToExit(pid);
    } else {
      tool.HumanOut() << llvm::formatv("recover: unknown character! ({0})\n", ch);
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
