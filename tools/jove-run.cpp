#include "jove/jove.h"
#include <unistd.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <thread>
#include <cinttypes>
#include <atomic>
#include <boost/filesystem.hpp>
#include <boost/dll/runtime_symbol_info.hpp>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <pthread.h>
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/bitset.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/WithColor.h>

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

static cl::opt<std::string>
    EnvFromFile("env-from-file",
                cl::desc("use output from `cat /proc/<pid>/environ`"),
                cl::cat(JoveCategory));

static cl::opt<std::string>
    ArgsFromFile("args-from-file",
                 cl::desc("use output from `cat /proc/<pid>/cmdline`"),
                 cl::cat(JoveCategory));

static cl::list<std::string>
    BindMountDirs("bind", cl::CommaSeparated,
         cl::value_desc("/path/to/dir_1,/path/to/dir_2,...,/path/to/dir_n"),
         cl::desc("List of directories to bind mount"), cl::cat(JoveCategory));

static cl::opt<std::string> sysroot("sysroot", cl::desc("Output directory"),
                                    cl::Required, cl::cat(JoveCategory));

static cl::opt<unsigned> Sleep(
    "sleep", cl::value_desc("seconds"),
    cl::desc("Time in seconds to sleep for after finishing waiting on child; "
             "can be useful if the program being recompiled forks"),
    cl::cat(JoveCategory));

static cl::opt<unsigned> DangerousSleep1(
    "dangerous-sleep1", cl::value_desc("useconds"),
    cl::desc("Time in useconds to wait for the dynamic linker to do its thing (1)"),
    cl::init(10000), cl::cat(JoveCategory));

static cl::opt<unsigned> DangerousSleep2(
    "dangerous-sleep2", cl::value_desc("useconds"),
    cl::desc("Time in useconds to wait for the dynamic linker to do its thing (2)"),
    cl::init(10000), cl::cat(JoveCategory));

static cl::opt<bool>
    NoChroot("no-chroot",
             cl::desc("run program under real sysroot (useful when combined with --foreign-libs)"),
             cl::cat(JoveCategory));

static cl::opt<bool> Verbose("verbose",
                             cl::desc("Output helpful messages for debugging"),
                             cl::cat(JoveCategory));

static cl::alias VerboseAlias("v", cl::desc("Alias for --verbose."),
                              cl::aliasopt(Verbose), cl::cat(JoveCategory));

static cl::opt<std::string>
    ChangeDirectory("cd", cl::desc("change directory after chroot(2)'ing"),
                    cl::cat(JoveCategory));

static cl::opt<bool>
    ForeignLibs("foreign-libs",
                cl::desc("only recompile the executable itself; "
                         "treat all other binaries as \"foreign\". Implies "
                         "--no-chroot"),
                cl::cat(JoveCategory));

static cl::alias
    ForeignLibsAlias("x", cl::desc("Exe only. Alias for --foreign-libs."),
                     cl::aliasopt(ForeignLibs),
                     cl::cat(JoveCategory));
}

namespace jove {

static fs::path jove_recover_path, jv_path;

static void sighandler(int no);

static int run(void);
static int run_outside_chroot(void);

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
  cl::AddExtraVersionPrinter([](llvm::raw_ostream &OS) -> void {
    OS << "jove version " JOVE_VERSION "\n";
  });
  cl::ParseCommandLineOptions(_argc, _argv, "jove-run\n");

  //
  // get paths to stuff
  //
  jove::jove_recover_path =
      boost::dll::program_location().parent_path() / "jove-recover";
  if (!fs::exists(jove::jove_recover_path)) {
    WithColor::error() << llvm::formatv("couldn't find jove-recover at {0}\n",
                                        jove::jove_recover_path.c_str());
    return 1;
  }

  jove::jv_path = fs::read_symlink(fs::path(opts::sysroot) / ".jv");
  if (!fs::exists(jove::jv_path)) {
    WithColor::error() << llvm::formatv("recover: no jv found at {0}\n",
                                        jove::jv_path.c_str());
    return 1;
  }

  //
  // signal handlers
  //
  {
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = jove::sighandler;

    if (sigaction(SIGSEGV, &sa, nullptr) < 0 ||
        sigaction(SIGBUS, &sa, nullptr) < 0 ||
        sigaction(SIGUSR1, &sa, nullptr) < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv("[{0}] sigaction failed: {1}\n",
                                          __func__, strerror(err));
    }
  }

  return opts::NoChroot || opts::ForeignLibs ?
    jove::run_outside_chroot() :
    jove::run();
}

namespace jove {

//
// set when jove-recover has been run (if nonzero then either 'f', 'b', 'F', 'r')
//
static std::atomic<char> recovered_ch;

static int await_process_completion(pid_t);

static void *recover_proc(const char *fifo_path);
static void IgnoreCtrlC(void);

static void print_command(const char **argv);

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

void sighandler(int no) {
  switch (no) {
  case SIGBUS:
  case SIGSEGV: {
#if 0
    WithColor::error() << llvm::formatv("jove-run crashed! run gdb -p {0}\n", gettid());
#endif

    const char *msg = "jove-run crashed! attach with a debugger..";
    robust_write(STDERR_FILENO, msg, strlen(msg));

    for (;;)
      sleep(1);

    __builtin_unreachable();
  }

  case SIGUSR1:
    interrupt_sleep.store(true);
    break;

  default:
    WithColor::error() << llvm::formatv("unhandled signal {0}\n", no);
    abort();
  }
}

static constexpr unsigned MAX_UMOUNT_RETRIES = 10;

template <bool IsEnabled>
struct ScopedMount {
  const char *const source;
  const char *const target;
  const char *const filesystemtype;
  const unsigned long mountflags;
  const void *const data;

  bool mounted;

  ScopedMount(const char *source,
              const char *target,
              const char *filesystemtype,
              unsigned long mountflags,
              const void *data)
      : source(source),
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
          if (opts::Verbose)
            WithColor::warning() << llvm::formatv("mount(\"{0}\", \"{1}\", \"{2}\", {3:x}, {4}) failed: {5}\n",
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
            llvm::errs() << llvm::formatv("retrying umount of {0} shortly...\n", this->target);
            usleep(100000);
          } else {
            llvm::errs() << llvm::formatv("unmounting %s failed: EBUSY...\n", this->target);
            return;
          }
          /* fallthrough */
        case EINTR:
          continue;

        default:
          llvm::errs() << llvm::formatv("umount(\"{0}\") failed: {1}\n",
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
static int do_run(void) {
#if 0 /* is this necessary? */
  if (mount(opts::sysroot, opts::sysroot, "", MS_BIND, nullptr) < 0)
    fprintf(stderr, "bind mounting %s failed : %s\n", opts::sysroot,
            strerror(errno));
#endif

  fs::path proc_path = fs::path(opts::sysroot) / "proc";
  ScopedMount<WillChroot> proc_mnt("proc",
                                   proc_path.c_str(),
                                   "proc",
                                   MS_NOSUID | MS_NODEV | MS_NOEXEC,
                                   nullptr);

  fs::path sys_path = fs::path(opts::sysroot) / "sys";
  ScopedMount<WillChroot> sys_mnt("sys",
                                  sys_path.c_str(),
                                  "sysfs",
                                  MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
                                  nullptr);

  std::list<fs::path>                CmdLineBindMountChrootedDirs;
  std::list<ScopedMount<WillChroot>> CmdLineBindMounts;

  for (const std::string &Dir : opts::BindMountDirs) {
    fs::path &chrooted_dir =
        CmdLineBindMountChrootedDirs.emplace_back(fs::path(opts::sysroot) / Dir);
    fs::create_directories(chrooted_dir);

    CmdLineBindMounts.emplace_back(Dir.c_str(),
                                   chrooted_dir.c_str(),
                                   "",
                                   MS_BIND,
                                   nullptr);
  }

#if 0
  //
  // create /dev, /dev/pts, /dev/shm
  //
  fs::path dev_path = fs::path(opts::sysroot) / "dev";
  ScopedMount<WillChroot> dev_mnt("udev",
                                  dev_path.c_str(),
                                  "devtmpfs",
                                  MS_NOSUID,
                                  "mode=0755");

  fs::path dev_pts_path = fs::path(opts::sysroot) / "dev" / "pts";
  ScopedMount<WillChroot> dev_pts_mnt("devpts",
                                      dev_pts_path.c_str(),
                                      "devpts",
                                      MS_NOSUID | MS_NOEXEC,
                                      "mode=0620,gid=5");

  fs::path dev_shm_path = fs::path(opts::sysroot) / "dev" / "shm";
  ScopedMount<WillChroot> dev_shm_mnt("shm",
                                      dev_shm_path.c_str(),
                                      "tmpfs",
                                      MS_NOSUID | MS_NODEV,
                                      "mode=1777");
#else
  //
  // bind mount /dev
  //
  fs::path dev_path;
  try {
    dev_path = fs::canonical("/dev");
  } catch (...) {
    ; /* absorb */
  }

  fs::path chrooted_dev = fs::path(opts::sysroot) / "dev";

  fs::create_directories(chrooted_dev);

  ScopedMount<WillChroot> dev_mnt(dev_path.c_str(),
                                  chrooted_dev.c_str(),
                                  "",
                                  MS_BIND,
                                  nullptr);
#endif

  //
  // bind mount /run
  //
  fs::path run_path = fs::path(opts::sysroot) / "run";
  ScopedMount<WillChroot> run_mnt("/run",
                                  run_path.c_str(),
                                  "",
                                  MS_BIND,
                                  nullptr);

  //
  // bind mount /var/run
  //
  fs::path var_run_path = fs::path(opts::sysroot) / "var" / "run";
  ScopedMount<WillChroot> var_run_mnt("/var/run",
                                      var_run_path.c_str(),
                                      "",
                                      MS_BIND,
                                      nullptr);

#if 0
  //
  // create /tmp
  //
  fs::path tmp_path = fs::path(opts::sysroot) / "tmp";
  ScopedMount<WillChroot> tmp_mnt("tmp",
                                  tmp_path.c_str(),
                                  "tmpfs",
                                  MS_NOSUID | MS_NODEV | MS_STRICTATIME,
                                  "mode=1777");
#else
  //
  // bind mount /tmp
  //
  fs::path tmp_path;
  try {
    tmp_path = fs::canonical("/tmp");
  } catch (...) {
    ; /* absorb */
  }

  fs::path chrooted_tmp = fs::path(opts::sysroot) / "tmp";

  fs::create_directories(chrooted_tmp);

  ScopedMount<WillChroot> tmp_mnt(tmp_path.c_str(),
                                  chrooted_tmp.c_str(),
                                  "",
                                  MS_BIND,
                                  nullptr);
#endif

  //
  // bind mount /etc/resolv.conf
  //
  fs::path resolv_conf_path;
  try {
    resolv_conf_path = fs::canonical("/etc/resolv.conf");
  } catch (...) {
    ; /* absorb */
  }

  fs::path chrooted_resolv_conf =
      fs::path(opts::sysroot) / "etc" / "resolv.conf";

  if (!resolv_conf_path.empty())
    touch(chrooted_resolv_conf);

  ScopedMount<WillChroot> resolv_conf_mnt(resolv_conf_path.c_str(),
                                          chrooted_resolv_conf.c_str(),
                                          "",
                                          MS_BIND,
                                          nullptr);

  //
  // bind mount /etc/passwd
  //
  fs::path etc_passwd_path;
  try {
    etc_passwd_path = fs::canonical("/etc/passwd");
  } catch (...) {
    ; /* absorb */
  }

  fs::path chrooted_etc_passwd =
      fs::path(opts::sysroot) / "etc" / "passwd";

  if (!etc_passwd_path.empty())
    touch(chrooted_etc_passwd);

  ScopedMount<WillChroot> etc_passwd_mnt(etc_passwd_path.c_str(),
                                         chrooted_etc_passwd.c_str(),
                                         "",
                                         MS_BIND,
                                         nullptr);

  //
  // bind mount /etc/group
  //
  fs::path etc_group_path;
  try {
    etc_group_path = fs::canonical("/etc/group");
  } catch (...) {
    ; /* absorb */
  }

  fs::path chrooted_etc_group =
      fs::path(opts::sysroot) / "etc" / "group";

  if (!etc_group_path.empty())
    touch(chrooted_etc_group);

  ScopedMount<WillChroot> etc_group_mnt(etc_group_path.c_str(),
                                        chrooted_etc_group.c_str(),
                                        "",
                                        MS_BIND,
                                        nullptr);

  //
  // bind mount /etc/shadow
  //
  fs::path etc_shadow_path;
  try {
    etc_shadow_path = fs::canonical("/etc/shadow");
  } catch (...) {
    ; /* absorb */
  }

  fs::path chrooted_etc_shadow =
      fs::path(opts::sysroot) / "etc" / "shadow";

  if (!etc_shadow_path.empty())
    touch(chrooted_etc_shadow);

  ScopedMount<WillChroot> etc_shadow_mnt(etc_shadow_path.c_str(),
                                         chrooted_etc_shadow.c_str(),
                                         "",
                                         MS_BIND,
                                         nullptr);

  //
  // bind mount /etc/nsswitch.conf
  //
  fs::path etc_nsswitch_path;
  try {
    etc_nsswitch_path = fs::canonical("/etc/nsswitch.conf");
  } catch (...) {
    ; /* absorb */
  }

  fs::path chrooted_etc_nsswitch =
      fs::path(opts::sysroot) / "etc" / "nsswitch.conf";

  if (!etc_nsswitch_path.empty())
    touch(chrooted_etc_nsswitch);

  ScopedMount<WillChroot> etc_nsswitch_mnt(etc_nsswitch_path.c_str(),
                                           chrooted_etc_nsswitch.c_str(),
                                           "",
                                           MS_BIND,
                                           nullptr);

  //
  // bind mount /etc/hosts
  //
  fs::path etc_hosts_path;
  try {
    etc_hosts_path = fs::canonical("/etc/hosts");
  } catch (...) {
    ; /* absorb */
  }

  fs::path chrooted_etc_hosts =
      fs::path(opts::sysroot) / "etc" / "hosts";

  if (!etc_hosts_path.empty())
    touch(chrooted_etc_hosts);

  ScopedMount<WillChroot> etc_hosts_mnt(etc_hosts_path.c_str(),
                                        chrooted_etc_hosts.c_str(),
                                        "",
                                        MS_BIND,
                                        nullptr);

  //
  // bind mount /firmadyne/libnvram
  //
  fs::path firmadyne_libnvram_path;
  try {
    firmadyne_libnvram_path = fs::canonical("/firmadyne/libnvram");
  } catch (...) {
    ; /* absorb */
  }

  fs::path chrooted_firmadyne_libnvram =
      fs::path(opts::sysroot) / "firmadyne" / "libnvram";

  fs::create_directories(chrooted_firmadyne_libnvram);

  ScopedMount<WillChroot> firmadyne_libnvram_mnt(firmadyne_libnvram_path.c_str(),
                                                 chrooted_firmadyne_libnvram.c_str(),
                                                 "",
                                                 MS_BIND,
                                                 nullptr);

  //
  // create recover fifo
  //
  fs::path recover_fifo_path =
      WillChroot ? fs::path(opts::sysroot) / "jove-recover.fifo"
                 : "/jove-recover.fifo";
  unlink(recover_fifo_path.c_str());
  if (mkfifo(recover_fifo_path.c_str(), 0666) < 0) {
    llvm::errs() << llvm::formatv("mkfifo failed : %s\n", strerror(errno));
    return 1;
  }

  //
  // create thread reading from fifo
  //
  pthread_t recover_thd;
  if (pthread_create(&recover_thd, nullptr, (void *(*)(void *))recover_proc,
                     (void *)recover_fifo_path.c_str()) != 0) {
    llvm::errs() << "failed to create recover_proc thread\n";
    return 1;
  }

  //
  // parse decompilation
  //
  decompilation_t decompilation;
  {
    std::ifstream ifs(jv_path.c_str());

    boost::archive::text_iarchive ia(ifs);
    ia >> decompilation;
  }

  int rfd = -1;
  int wfd = -1;

  const bool LivingDangerously = !WillChroot && !opts::ForeignLibs;

  if (LivingDangerously) {
    //
    // this pipe will be used to make sure we don't proceed further unless the
    // execve(2) has already happened (close-on-exec)
    //
    {
      int pipefd[2] = {-1, -1};
      if (pipe(pipefd) < 0) {
        WithColor::error() << "pipe(2) failed. bug?\n";
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
      if (binary.IsVDSO)
        continue;
      if (binary.IsDynamicLinker)
        continue;

      std::string sav_path = binary.Path + ".jove.sav";
      if (link(binary.Path.c_str(), sav_path.c_str()) < 0) {
        WithColor::error() << llvm::formatv("failed to create hard link for {0}\n",
                                            binary.Path);
        return 1;
      }
    }

    //
    // (2) copy recompiled binaries to root filesystem
    //
    for (const binary_t &binary : decompilation.Binaries) {
      if (binary.IsVDSO)
        continue;
      if (binary.IsDynamicLinker)
        continue;

      fs::path chrooted_path = fs::path(opts::sysroot) / binary.Path;
      std::string new_path = binary.Path + ".jove.new";

      try {
        fs::copy_file(chrooted_path, new_path);
      } catch (...) {
        WithColor::warning() << llvm::formatv(
            "dangerous mode: failed to copy {0} to {1}; aborting\n",
            chrooted_path.c_str(), new_path.c_str());
        return 1;
      }
    }

    //
    // (3) perform the renames!!!
    //
    for (const binary_t &binary : decompilation.Binaries) {
      if (binary.IsVDSO)
        continue;
      if (binary.IsDynamicLinker)
        continue;

      std::string new_path = binary.Path + ".jove.new";

      if (rename(new_path.c_str(), binary.Path.c_str()) < 0) {
        int err = errno;
        WithColor::error() << llvm::formatv("rename of {0} to {1} failed: {2}\n",
                                            new_path.c_str(),
                                            binary.Path.c_str(),
                                            strerror(err));
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
        WithColor::error() << llvm::formatv(
            "failed to set pipe write end close-on-exec: {0}\n", strerror(err));
      }
    }

    if (WillChroot) {
      if (chroot(opts::sysroot.c_str()) < 0) {
        int err = errno;
        llvm::errs() << llvm::formatv("chroot failed : {0}\n", strerror(err));
        return 1;
      }

      const char *working_dir =
          !opts::ChangeDirectory.empty() ?
          opts::ChangeDirectory.c_str() : "/";

      if (chdir(working_dir) < 0) {
        int err = errno;
        llvm::errs() << llvm::formatv("chdir failed : {0}\n", strerror(err));
        return 1;
      }
    }

    //
    // compute environment
    //
    std::list<std::string> env_file_args;
    std::vector<const char *> env_vec;

    if (!opts::EnvFromFile.empty()) {
      std::ifstream ifs(opts::EnvFromFile);

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

    for (std::string &s : opts::Envs)
      env_vec.push_back(s.c_str());

    env_vec.push_back(nullptr);

    //
    // compute args
    //
    std::list<std::string> args_file_args;
    std::vector<const char *> arg_vec;

    fs::path prog_path =
        WillChroot ? opts::Prog : fs::path(opts::sysroot) / opts::Prog;

    if (!opts::ArgsFromFile.empty()) {
      std::ifstream ifs(opts::ArgsFromFile);

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

      for (std::string &s : opts::Args)
        arg_vec.push_back(s.c_str());
    }

    arg_vec.push_back(nullptr);

#if 0
    if (LivingDangerously)
      usleep(500000 /* 0.5 s */);
#endif

    print_command(&arg_vec[0]);
    execve(arg_vec[0],
           const_cast<char **>(&arg_vec[0]),
           const_cast<char **>(&env_vec[0]));

    int err = errno;
    WithColor::error() << llvm::formatv("execve failed: {0}\n", strerror(err));

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
      WithColor::error() << llvm::formatv("failed to write to pipefd: {0}\n",
                                          ret);

    if (close(pipefd) < 0) {
      int err = errno;
      WithColor::warning() << llvm::formatv("failed to close pipefd: {0}\n",
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

    usleep(opts::DangerousSleep1); /* wait for the dynamic linker to load the program */

    //
    // (4) perform the renames to undo the changes we made to the root
    // filesystem all DSO's except those dynamically loaded (we do that after the second sleep)
    //
    for (const binary_t &binary : decompilation.Binaries) {
      if (binary.IsVDSO)
        continue;
      if (binary.IsDynamicLinker)
        continue;
      if (binary.IsDynamicallyLoaded)
	continue;

      std::string sav_path = binary.Path + ".jove.sav";

      if (rename(sav_path.c_str(), binary.Path.c_str()) < 0) {
        int err = errno;
        WithColor::error() << llvm::formatv("rename of {0} to {1} failed: {2}\n",
                                            sav_path.c_str(),
                                            binary.Path.c_str(),
                                            strerror(err));
      }
    }

    usleep(opts::DangerousSleep2); /* wait for the dynamic linker to load the rest */

    //
    // (5) perform the renames to undo the changes we made to the root filesystem
    // for all the dynamically loaded DSOs
    //
    for (const binary_t &binary : decompilation.Binaries) {
      if (binary.IsVDSO)
        continue;
      if (binary.IsDynamicLinker)
        continue;
      if (!binary.IsDynamicallyLoaded)
	continue;

      std::string sav_path = binary.Path + ".jove.sav";

      if (rename(sav_path.c_str(), binary.Path.c_str()) < 0) {
        int err = errno;
        WithColor::error() << llvm::formatv("rename of {0} to {1} failed: {2}\n",
                                            sav_path.c_str(),
                                            binary.Path.c_str(),
                                            strerror(err));
      }
    }

    close(rfd);
  }

  //
  // wait for process to exit
  //
  int ret = await_process_completion(pid);

  //
  // optionally sleep
  //
  if (unsigned sec = opts::Sleep) {
    llvm::errs() << llvm::formatv("sleeping for {0} seconds...\n", sec);
    for (unsigned t = 0; t < sec; ++t) {
      sleep(1);

      if (interrupt_sleep.load()) {
        if (opts::Verbose)
          WithColor::note() << "sleep interrupted\n";
        break;
      }

      if (recovered_ch.load()) {
        if (opts::Verbose)
          WithColor::note() << "sleep interrupted by jove-recover\n";
        sleep(std::min<unsigned>(sec - t, 3));
        break;
      }

      llvm::errs() << ".";
    }
  }

  //
  // cancel the thread reading the fifo
  //
  if (pthread_cancel(recover_thd) != 0) {
    llvm::errs() << "error: failed to cancel recover_proc thread\n";

    void *retval;
    if (pthread_join(recover_thd, &retval) != 0)
      llvm::errs() << "error: pthread_join failed\n";
  } else {
    void *recover_retval;
    if (pthread_join(recover_thd, &recover_retval) != 0)
      llvm::errs() << "error: pthread_join failed\n";
    else if (recover_retval != PTHREAD_CANCELED)
      llvm::errs() << llvm::formatv(
              "warning: expected retval to equal PTHREAD_CANCELED, but is {0}\n",
              recover_retval);
  }

  if (unlink(recover_fifo_path.c_str()) < 0) {
    int err = errno;
    llvm::errs() << llvm::formatv("unlink of recover pipe failed: {0}\n", strerror(err));
  }

#if 0 /* is this necessary? */
  if (umount2(opts::sysroot, 0) < 0)
    fprintf(stderr, "unmounting %s failed : %s\n", opts::sysroot, strerror(errno));
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

int run(void) {
  return do_run<true>();
}

int run_outside_chroot(void) {
  return do_run<false>();
}

void touch(const fs::path &p) {
  fs::create_directories(p.parent_path());
  if (!fs::exists(p))
    close(open(p.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666));
}

void *recover_proc(const char *fifo_path) {
  //
  // ATTENTION: this thread has to be cancel-able.
  //

  int recover_fd;
  do
    recover_fd = open(fifo_path, O_RDONLY);
  while (recover_fd < 0 && errno == EINTR);

  if (recover_fd < 0) {
    int err = errno;
    llvm::errs() << llvm::formatv("recover: failed to open fifo at {0} ({1})\n",
                                  fifo_path,
                                  strerror(err));
    return nullptr;
  }

  void (*cleanup_handler)(void *) = [](void *arg) -> void {
    if (close(reinterpret_cast<long>(arg)) < 0) {
      int err = errno;
      llvm::errs() << llvm::formatv(
          "recover_proc: cleanup_handler: close failed ({0})\n", strerror(err));
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

          llvm::errs() << llvm::formatv("recover: read failed ({0})\n",
                                        strerror(err));
        } else if (ret == 0) {
          // NOTE: open is a cancellation point
          int new_recover_fd = open(fifo_path, O_RDONLY);
          if (new_recover_fd < 0) {
            int err = errno;
            llvm::errs() << llvm::formatv(
                "recover: failed to open fifo at {0} ({1})\n", fifo_path,
                strerror(err));
            return nullptr;
          }

          if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, nullptr) != 0) {
            llvm::errs() << "pthread_setcancelstate failed\n";
          }

          assert(new_recover_fd != recover_fd);

          if (dup2(new_recover_fd, recover_fd) < 0) {
            int err = errno;
            llvm::errs() << llvm::formatv(
                "recover: failed to dup2({0}, {1})) ({2})\n", new_recover_fd,
                recover_fd, strerror(err));
          }

          if (close(new_recover_fd) < 0) {
            int err = errno;
            llvm::errs() << llvm::formatv("recover_proc: close failed ({0})\n",
                                          strerror(err));
          }

          if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, nullptr) != 0)
            llvm::errs() << "pthread_setcancelstate failed\n";

          continue;
        } else {
          llvm::errs() << llvm::formatv("recover: read gave {0}\n", ret);
        }

        break;
      }
    }

    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, nullptr) != 0)
      llvm::errs() << "pthread_setcancelstate failed\n";

    //
    // we assume ch is loaded with a byte from the fifo. it's got to be either
    // 'f', 'F', 'b', or 'r'.
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

        const char *argv[] = {jove_recover_path.c_str(), "-d", jv_path.c_str(),
                              buff, nullptr};
        print_command(&argv[0]);
        execve(jove_recover_path.c_str(), const_cast<char **>(argv), ::environ);
        int err = errno;
        llvm::errs() << llvm::formatv("recover: exec failed ({0})\n", strerror(err));
        exit(1);
      }

      (void)await_process_completion(pid);
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

        const char *argv[] = {jove_recover_path.c_str(), "-d", jv_path.c_str(),
                              buff, nullptr};
        print_command(&argv[0]);
        execve(jove_recover_path.c_str(), const_cast<char **>(argv), ::environ);
        int err = errno;
        llvm::errs() << llvm::formatv("recover: exec failed ({0})\n", strerror(err));
        exit(1);
      }

      (void)await_process_completion(pid);
    } else if (ch == 'F') {
      struct {
        uint32_t BIdx;
        uint32_t BBIdx;
      } IndCall;

      uintptr_t FileAddr;

      {
        ssize_t ret;

        ret = robust_read(recover_fd, &IndCall.BIdx, sizeof(uint32_t));
        assert(ret == sizeof(uint32_t));

        ret = robust_read(recover_fd, &IndCall.BBIdx, sizeof(uint32_t));
        assert(ret == sizeof(uint32_t));

        ret = robust_read(recover_fd, &FileAddr, sizeof(uintptr_t));
        assert(ret == sizeof(uintptr_t));
      }

      int pid = fork();
      if (!pid) {
        char buff[256];
        snprintf(buff, sizeof(buff),
                 "--function=%" PRIu32 ",%" PRIu32 ",%" PRIuPTR,
                 IndCall.BIdx,
                 IndCall.BBIdx,
                 FileAddr);

        const char *argv[] = {jove_recover_path.c_str(), "-d", jv_path.c_str(),
                              buff, nullptr};
        print_command(&argv[0]);
        execve(jove_recover_path.c_str(), const_cast<char **>(argv), ::environ);
        int err = errno;
        llvm::errs() << llvm::formatv("recover: exec failed ({0})\n", strerror(err));
        exit(1);
      }

      (void)await_process_completion(pid);
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

        const char *argv[] = {jove_recover_path.c_str(), "-d", jv_path.c_str(),
                              buff, nullptr};
        print_command(&argv[0]);
        execve(jove_recover_path.c_str(), const_cast<char **>(argv), ::environ);
        int err = errno;
        llvm::errs() << llvm::formatv("recover: exec failed ({0})\n", strerror(err));
        exit(1);
      }

      (void)await_process_completion(pid);
    } else {
      llvm::errs() << llvm::formatv("recover: unknown character! ({0})\n", ch);
    }

    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, nullptr) != 0)
      llvm::errs() << "pthread_setcancelstate failed\n";
  }

  // (Clean-up handlers are not called if the thread terminates by performing a
  // return from the thread start function.)
  pthread_cleanup_pop(1 /* execute */);

  return nullptr;
}

int await_process_completion(pid_t pid) {
  int wstatus;
  do {
    if (waitpid(pid, &wstatus, WUNTRACED | WCONTINUED) < 0) {
      int err = errno;
      switch (err) {
      case ECHILD:
        return 0;
      case EINTR:
        continue;
      default:
        llvm::errs() << llvm::formatv("waitpid failed: {0}\n", strerror(err));
        continue;
      }
    }

    if (WIFEXITED(wstatus)) {
      llvm::errs() << llvm::formatv("exited, status={0}\n", WEXITSTATUS(wstatus));
      return WEXITSTATUS(wstatus);
    } else if (WIFSIGNALED(wstatus)) {
      llvm::errs() << llvm::formatv("killed by signal {0}\n", WTERMSIG(wstatus));
      return 1;
    } else if (WIFSTOPPED(wstatus)) {
      llvm::errs() << llvm::formatv("stopped by signal {0}\n", WSTOPSIG(wstatus));
      return 1;
    } else if (WIFCONTINUED(wstatus)) {
      llvm::errs() << "continued\n";
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

void print_command(const char **argv) {
  std::string msg;

  for (const char **s = argv; *s; ++s) {
    msg.append(*s);
    msg.push_back(' ');
  }

  if (msg.empty())
    return;

  msg[msg.size() - 1] = '\n';

  llvm::errs() << msg.c_str();
}

}
