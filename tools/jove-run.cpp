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

static cl::opt<std::string> sysroot("sysroot", cl::desc("Output directory"),
                                    cl::Required, cl::cat(JoveCategory));

static cl::opt<unsigned>
    pipefd("pipefd", cl::value_desc("file descriptor"),
           cl::desc("Write-end of a pipe used to communicate app pid"),
           cl::cat(JoveCategory));

static cl::opt<unsigned> Sleep(
    "sleep", cl::value_desc("seconds"),
    cl::desc("Time in seconds to sleep for after finishing waiting on child; "
             "can be useful if the program being recompiled forks"),
    cl::cat(JoveCategory));

static cl::opt<bool>
    OutsideChroot("outside-chroot",
                  cl::desc("run program under real sysroot (useful when "
                           "combined with --foreign-libs)"),
                  cl::cat(JoveCategory));
}

namespace jove {

static fs::path jove_recover_path, jv_path;

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
    fprintf(stderr, "couldn't find jove-recover at %s\n",
            jove::jove_recover_path.c_str());
    return 1;
  }

  jove::jv_path = fs::read_symlink(fs::path(opts::sysroot) / ".jv");
  if (!fs::exists(jove::jv_path)) {
    fprintf(stderr, "recover: no jv found\n");
    return 1;
  }

  return opts::OutsideChroot ? jove::run_outside_chroot() : jove::run();
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

static constexpr unsigned MAX_UMOUNT_RETRIES = 10;

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
          fprintf(stderr, "mount(\"%s\", \"%s\", \"%s\", 0x%lx, %p) failed: %s\n",
                  this->source,
                  this->target,
                  this->filesystemtype,
                  (long)this->mountflags,
                  this->data,
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
            fprintf(stderr, "retrying umount of %s shortly...\n", this->target);
            usleep(100000);
          } else {
            fprintf(stderr, "unmounting %s failed: EBUSY...\n", this->target);
            return;
          }
          /* fallthrough */
        case EINTR:
          continue;

        default:
          fprintf(stderr, "umount(\"%s\") failed: %s\n",
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

int run(void) {
#if 0
  if (mount(opts::sysroot, opts::sysroot, "", MS_BIND, nullptr) < 0)
    fprintf(stderr, "bind mounting %s failed : %s\n", opts::sysroot,
            strerror(errno));
#endif

  fs::path proc_path = fs::path(opts::sysroot) / "proc";
  ScopedMount proc_mnt("proc",
                       proc_path.c_str(),
                       "proc",
                       MS_NOSUID | MS_NODEV | MS_NOEXEC,
                       nullptr);

  fs::path sys_path = fs::path(opts::sysroot) / "sys";
  ScopedMount sys_mnt("sys",
                      sys_path.c_str(),
                      "sysfs",
                      MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
                      nullptr);

  fs::path dev_path = fs::path(opts::sysroot) / "dev";
  ScopedMount dev_mnt("udev",
                      dev_path.c_str(),
                      "devtmpfs",
                      MS_NOSUID,
                      "mode=0755");

  fs::path dev_pts_path = fs::path(opts::sysroot) / "dev" / "pts";
  ScopedMount dev_pts_mnt("devpts",
                          dev_pts_path.c_str(),
                          "devpts",
                          MS_NOSUID | MS_NOEXEC,
                          "mode=0620,gid=5");

  fs::path dev_shm_path = fs::path(opts::sysroot) / "dev" / "shm";
  ScopedMount dev_shm_mnt("shm",
                          dev_shm_path.c_str(),
                          "tmpfs",
                          MS_NOSUID | MS_NODEV,
                          "mode=1777");

  fs::path run_path = fs::path(opts::sysroot) / "run";
  ScopedMount run_mnt("/run",
                      run_path.c_str(),
                      "",
                      MS_BIND,
                      nullptr);

  fs::path var_run_path = fs::path(opts::sysroot) / "var" / "run";
  ScopedMount var_run_mnt("/var/run",
                          var_run_path.c_str(),
                          "",
                          MS_BIND,
                          nullptr);

#if 0
  fs::path tmp_path = fs::path(opts::sysroot) / "tmp";
  ScopedMount tmp_mnt("tmp",
                      tmp_path.c_str(),
                      "tmpfs",
                      MS_NOSUID | MS_NODEV | MS_STRICTATIME,
                      "mode=1777");
#endif

  fs::path resolv_conf_path;
  try {
    resolv_conf_path = fs::canonical("/etc/resolv.conf");
  } catch (...) {
    ; /* absorb */
  }

  fs::path chrooted_resolv_conf =
      fs::path(opts::sysroot) / "etc" / "resolv.conf";

  ScopedMount resolv_conf_mnt(resolv_conf_path.c_str(),
                              chrooted_resolv_conf.c_str(),
                              "",
                              MS_BIND,
                              nullptr);

  fs::path etc_passwd_path;
  try {
    etc_passwd_path = fs::canonical("/etc/passwd");
  } catch (...) {
    ; /* absorb */
  }

  fs::path chrooted_etc_passwd =
      fs::path(opts::sysroot) / "etc" / "passwd";

  ScopedMount etc_passwd_mnt(etc_passwd_path.c_str(),
                             chrooted_etc_passwd.c_str(),
                             "",
                             MS_BIND,
                             nullptr);

  fs::path etc_group_path;
  try {
    etc_group_path = fs::canonical("/etc/group");
  } catch (...) {
    ; /* absorb */
  }

  fs::path chrooted_etc_group =
      fs::path(opts::sysroot) / "etc" / "group";

  ScopedMount etc_group_mnt(etc_group_path.c_str(),
                            chrooted_etc_group.c_str(),
                            "",
                            MS_BIND,
                            nullptr);

  fs::path etc_shadow_path;
  try {
    etc_shadow_path = fs::canonical("/etc/shadow");
  } catch (...) {
    ; /* absorb */
  }

  fs::path chrooted_etc_shadow =
      fs::path(opts::sysroot) / "etc" / "shadow";

  ScopedMount etc_shadow_mnt(etc_shadow_path.c_str(),
                             chrooted_etc_shadow.c_str(),
                             "",
                             MS_BIND,
                             nullptr);

  fs::path etc_nsswitch_path;
  try {
    etc_nsswitch_path = fs::canonical("/etc/nsswitch.conf");
  } catch (...) {
    ; /* absorb */
  }

  fs::path chrooted_etc_nsswitch =
      fs::path(opts::sysroot) / "etc" / "nsswitch.conf";

  ScopedMount etc_nsswitch_mnt(etc_nsswitch_path.c_str(),
                              chrooted_etc_nsswitch.c_str(),
                              "",
                              MS_BIND,
                              nullptr);

  fs::path etc_hosts_path;
  try {
    etc_hosts_path = fs::canonical("/etc/hosts");
  } catch (...) {
    ; /* absorb */
  }

  fs::path chrooted_etc_hosts =
      fs::path(opts::sysroot) / "etc" / "hosts";

  ScopedMount etc_hosts_mnt(etc_hosts_path.c_str(),
                            chrooted_etc_hosts.c_str(),
                            "",
                            MS_BIND,
                            nullptr);

  fs::path firmadyne_libnvram_path;
  try {
    firmadyne_libnvram_path = fs::canonical("/firmadyne/libnvram");
  } catch (...) {
    ; /* absorb */
  }

#if 0
  fs::path chrooted_firmadyne_libnvram =
      fs::path(opts::sysroot) / "firmadyne" / "libnvram";

  fs::create_directories(chrooted_firmadyne_libnvram);

  ScopedMount firmadyne_libnvram_mnt(firmadyne_libnvram_path.c_str(),
                                     chrooted_firmadyne_libnvram.c_str(),
                                     "",
                                     MS_BIND,
                                     nullptr);
#endif

#if 0
  {
    std::string input;
    std::getline(std::cin, input);
  }
#endif

  fs::path recover_fifo_path = fs::path(opts::sysroot) / "jove-recover.fifo";
  unlink(recover_fifo_path.c_str());
  if (mkfifo(recover_fifo_path.c_str(), 0666) < 0) {
    fprintf(stderr, "mkfifo failed : %s\n", strerror(errno));
    return 1;
  }

  //
  // create thread reading from fifo
  //
  pthread_t recover_thd;
  if (pthread_create(&recover_thd, nullptr, (void *(*)(void *))recover_proc,
                     (void *)recover_fifo_path.c_str()) != 0) {
    fprintf(stderr, "failed to create recover_proc thread\n");
    return 1;
  }

  //
  // now actually fork and exec the given executable
  //
  int pid = fork();
  if (!pid) {
    if (chroot(opts::sysroot.c_str()) < 0) {
      fprintf(stderr, "chroot failed : %s\n", strerror(errno));
      return 1;
    }

    if (chdir("/") < 0) {
      fprintf(stderr, "chdir failed : %s\n", strerror(errno));
      return 1;
    }

    //
    // compute new environment
    //
    struct {
      std::vector<std::string> s_vec;
      std::vector<const char *> a_vec;
    } env;

    for (char **p = ::environ; *p; ++p) {
      const std::string s(*p);

      auto beginswith = [&](const std::string &x) -> bool {
        return s.compare(0, x.size(), x) == 0;
      };

      //
      // filter pre-existing environment entries
      //
      if (beginswith("JOVE_RECOVER_FIFO="))
        continue;

      env.s_vec.push_back(s);
    }

    env.s_vec.push_back("JOVE_RECOVER_FIFO=/jove-recover.fifo");

#if defined(__x86_64__)
    // <3 glibc
    env.s_vec.push_back("GLIBC_TUNABLES=glibc.cpu.hwcaps="
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
    env.s_vec.push_back("GLIBC_TUNABLES=glibc.cpu.hwcaps="
                        "-SSE4_1,"
                        "-SSE4_2,"
                        "-SSSE3,"
                        "-Fast_Rep_String,"
                        "-Fast_Unaligned_Load,"
                        "-SSE2");
#endif

    //
    // disable lazy linking (please)
    //
    env.s_vec.push_back("LD_BIND_NOW=1");

    for (std::string &s : opts::Envs)
      env.s_vec.push_back(s);

    for (const std::string &s : env.s_vec)
      env.a_vec.push_back(s.c_str());
    env.a_vec.push_back(nullptr);

    std::vector<const char *> arg_vec = {
        opts::Prog.c_str(),
    };

    for (std::string &s : opts::Args)
      arg_vec.push_back(s.c_str());

    arg_vec.push_back(nullptr);

    print_command(&arg_vec[0]);
    execve(arg_vec[0],
           const_cast<char **>(&arg_vec[0]),
           const_cast<char **>(&env.a_vec[0]));

    fprintf(stderr, "execve failed: %s\n", strerror(errno));
    return 1;
  }

  //
  // if we were given a pipefd, then communicate the app child's PID
  //
  if (int pipefd = opts::pipefd) {
    ssize_t ret;

    uint64_t uint64 = pid;
    ret = robust_write(pipefd, &uint64, sizeof(uint64_t));

    if (ret != sizeof(uint64_t))
      WithColor::error() << llvm::formatv("failed to write to pipefd: {0}\n",
                                          ret);

    if (close(pipefd) < 0) {
      int err = errno;
      WithColor::warning() << llvm::formatv("failed to close pipefd: {0}\n",
                                            strerror(err));
    }
  }

  IgnoreCtrlC();

  //
  // wait for process to exit
  //
#if 1
  int ret = await_process_completion(pid);
#else
  int ret = 0;

  //
  // wait for all children to exit
  //
  for (;;) {
    int status;
    pid_t child = waitpid(-1, &status, __WALL);

    if (child < 0) {
      int err = errno;
      if (err != ECHILD) {
        fprintf(stderr, "waitpid failed: %s\n", strerror(err));
      }
      break;
    }

    if (WIFEXITED(status))
      ret = WEXITSTATUS(status);
  }
#endif

  if (unsigned sec = opts::Sleep) {
    fprintf(stderr, "sleeping for %u seconds...\n", sec);
    sleep(sec);
  }

  //
  // cancel the thread reading the fifo
  //
  if (pthread_cancel(recover_thd) != 0) {
    fprintf(stderr, "error: failed to cancel recover_proc thread\n");

    void *retval;
    if (pthread_join(recover_thd, &retval) != 0)
      fprintf(stderr, "error: pthread_join failed\n");
  } else {
    void *recover_retval;
    if (pthread_join(recover_thd, &recover_retval) != 0)
      fprintf(stderr, "error: pthread_join failed\n");
    else if (recover_retval != PTHREAD_CANCELED)
      fprintf(stderr,
              "warning: expected retval to equal PTHREAD_CANCELED, but is %p\n",
              recover_retval);
  }

  if (unlink(recover_fifo_path.c_str()) < 0)
    fprintf(stderr, "unlink of recover pipe failed : %s\n", strerror(errno));

#if 0
  if (umount2(opts::sysroot, 0) < 0)
    fprintf(stderr, "unmounting %s failed : %s\n", opts::sysroot, strerror(errno));
#endif

  {
    char ch = recovered_ch.load();
    if (ch)
      return ch;
  }

  return ret;
}

int run_outside_chroot(void) {
  //
  // this is a stripped-down version of run() XXX code duplication
  //
  fs::path recover_fifo_path = "/jove-recover.fifo";
  unlink(recover_fifo_path.c_str());
  if (mkfifo(recover_fifo_path.c_str(), 0666) < 0) {
    fprintf(stderr, "mkfifo failed : %s\n", strerror(errno));
    return 1;
  }

  //
  // create thread reading from fifo
  //
  pthread_t recover_thd;
  if (pthread_create(&recover_thd, nullptr, (void *(*)(void *))recover_proc,
                     (void *)recover_fifo_path.c_str()) != 0) {
    fprintf(stderr, "failed to create recover_proc thread\n");
    return 1;
  }

  //
  // now actually fork and exec the given executable
  //
  int pid = fork();
  if (!pid) {
    //
    // compute new environment
    //
    struct {
      std::vector<std::string> s_vec;
      std::vector<const char *> a_vec;
    } env;

    for (char **p = ::environ; *p; ++p) {
      const std::string s(*p);

      auto beginswith = [&](const std::string &x) -> bool {
        return s.compare(0, x.size(), x) == 0;
      };

      //
      // filter pre-existing environment entries
      //
      if (beginswith("JOVE_RECOVER_FIFO="))
        continue;

      env.s_vec.push_back(s);
    }

    env.s_vec.push_back("JOVE_RECOVER_FIFO=/jove-recover.fifo");

#if defined(__x86_64__)
    // <3 glibc
    env.s_vec.push_back("GLIBC_TUNABLES=glibc.cpu.hwcaps="
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
    env.s_vec.push_back("GLIBC_TUNABLES=glibc.cpu.hwcaps="
                        "-SSE4_1,"
                        "-SSE4_2,"
                        "-SSSE3,"
                        "-Fast_Rep_String,"
                        "-Fast_Unaligned_Load,"
                        "-SSE2");
#endif

    //
    // disable lazy linking (please)
    //
    env.s_vec.push_back("LD_BIND_NOW=1");

    for (std::string &s : opts::Envs)
      env.s_vec.push_back(s);

    for (const std::string &s : env.s_vec)
      env.a_vec.push_back(s.c_str());
    env.a_vec.push_back(nullptr);

    fs::path prog_path = fs::path(opts::sysroot) / opts::Prog.c_str();

    std::vector<const char *> arg_vec = {
        prog_path.c_str(),
    };

    for (std::string &s : opts::Args)
      arg_vec.push_back(s.c_str());

    arg_vec.push_back(nullptr);

    print_command(&arg_vec[0]);
    execve(arg_vec[0],
           const_cast<char **>(&arg_vec[0]),
           const_cast<char **>(&env.a_vec[0]));

    fprintf(stderr, "execve failed: %s\n", strerror(errno));
    return 1;
  }

  IgnoreCtrlC();

  //
  // if we were given a pipefd, then communicate the app child's PID
  //
  if (int pipefd = opts::pipefd) {
    ssize_t ret;

    uint64_t uint64 = pid;
    ret = robust_write(pipefd, &uint64, sizeof(uint64_t));

    if (ret != sizeof(uint64_t))
      WithColor::error() << llvm::formatv("failed to write to pipefd: {0}\n",
                                          ret);

    if (close(pipefd) < 0) {
      int err = errno;
      WithColor::warning() << llvm::formatv("failed to close pipefd: {0}\n",
                                            strerror(err));
    }
  }

  //
  // wait for process to exit
  //
  int ret = await_process_completion(pid);

  if (unsigned sec = opts::Sleep) {
    fprintf(stderr, "sleeping for %u seconds...\n", sec);
    for (unsigned t = 0; t < sec; ++t) {
      sleep(1);
      fprintf(stderr, "%s", ".");
    }
  }

  //
  // cancel the thread reading the fifo
  //
  if (pthread_cancel(recover_thd) != 0) {
    fprintf(stderr, "error: failed to cancel recover_proc thread\n");

    void *retval;
    if (pthread_join(recover_thd, &retval) != 0)
      fprintf(stderr, "error: pthread_join failed\n");
  } else {
    void *recover_retval;
    if (pthread_join(recover_thd, &recover_retval) != 0)
      fprintf(stderr, "error: pthread_join failed\n");
    else if (recover_retval != PTHREAD_CANCELED)
      fprintf(stderr,
              "warning: expected retval to equal PTHREAD_CANCELED, but is %p\n",
              recover_retval);
  }

  if (unlink(recover_fifo_path.c_str()) < 0)
    fprintf(stderr, "unlink of recover pipe failed : %s\n", strerror(errno));

#if 0
  if (umount2(opts::sysroot, 0) < 0)
    fprintf(stderr, "unmounting %s failed : %s\n", opts::sysroot, strerror(errno));
#endif

  {
    char ch = recovered_ch.load();
    if (ch)
      return ch;
  }

  return ret;
}

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define _IOV_ENTRY(var) {.iov_base = &var, .iov_len = sizeof(var)}

static size_t _sum_iovec_lengths(const struct iovec *iov, unsigned n) {
  size_t expected = 0;
  for (unsigned i = 0; i < n; ++i)
    expected += iov[i].iov_len;
  return expected;
}

void *recover_proc(const char *fifo_path) {
  //
  // ATTENTION: this thread has to be cancel-able. That means no C++ objects at
  // any time, in this function.
  //

  int recover_fd;
  do
    recover_fd = open(fifo_path, O_RDONLY);
  while (recover_fd < 0 && errno == EINTR);

  if (recover_fd < 0) {
    fprintf(stderr, "recover: failed to open fifo at %s (%s)\n", fifo_path,
            strerror(errno));
    return nullptr;
  }

  void (*cleanup_handler)(void *) = [](void *arg) -> void {
    if (close(reinterpret_cast<long>(arg)) < 0)
      fprintf(stderr, "recover_proc: cleanup_handler: close failed (%s)\n",
              strerror(errno));
  };

  pthread_cleanup_push(cleanup_handler, reinterpret_cast<void *>(recover_fd));

  for (;;) {
    char ch;

    {
      // NOTE: read is a cancellation point
      ssize_t ret = read(recover_fd, &ch, 1);
      if (ret != 1) {
        if (ret < 0) {
          if (errno == EINTR)
            continue;

          fprintf(stderr, "recover: read failed (%s)\n", strerror(errno));
        } else if (ret == 0) {
          // NOTE: open is a cancellation point
          int new_recover_fd = open(fifo_path, O_RDONLY);
          if (new_recover_fd < 0) {
            fprintf(stderr, "recover: failed to open fifo at %s (%s)\n",
                    fifo_path, strerror(errno));
            return nullptr;
          }

          if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, nullptr) != 0)
            fprintf(stderr, "warning: pthread_setcancelstate failed\n");

          assert(new_recover_fd != recover_fd);

          if (dup2(new_recover_fd, recover_fd) < 0) {
            fprintf(stderr, "recover: failed to dup2(%d, %d)) (%s)\n",
                    new_recover_fd, recover_fd, strerror(errno));
          }

          if (close(new_recover_fd) < 0)
            fprintf(stderr, "recover_proc: close failed (%s)\n",
                    strerror(errno));

          if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, nullptr) != 0)
            fprintf(stderr, "warning: pthread_setcancelstate failed\n");

          continue;
        } else {
          fprintf(stderr, "recover: read gave %zd\n", ret);
        }

        break;
      }
    }

    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, nullptr) != 0)
      fprintf(stderr, "warning: pthread_setcancelstate failed\n");

    //
    // we assume ch is loaded with a byte from the fifo. it's got to be either
    // 'f', 'b', or 'r'.
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
        fprintf(stderr, "recover: exec failed (%s)\n", strerror(errno));
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
        fprintf(stderr, "recover: exec failed (%s)\n", strerror(errno));
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
        print_command(argv);
        execve(jove_recover_path.c_str(), const_cast<char **>(argv), ::environ);
        fprintf(stderr, "recover: exec failed (%s)\n", strerror(errno));
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
        fprintf(stderr, "recover: exec failed (%s)\n", strerror(errno));
        exit(1);
      }

      (void)await_process_completion(pid);
    } else {
      fprintf(stderr, "recover: unknown character! (%c)\n", ch);
    }

    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, nullptr) != 0)
      fprintf(stderr, "warning: pthread_setcancelstate failed\n");
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
        fprintf(stderr, "waitpid failed: %s\n", strerror(err));
        continue;
      }
    }

    if (WIFEXITED(wstatus)) {
      printf("exited, status=%d\n", WEXITSTATUS(wstatus));
      return WEXITSTATUS(wstatus);
    } else if (WIFSIGNALED(wstatus)) {
      printf("killed by signal %d\n", WTERMSIG(wstatus));
      return 1;
    } else if (WIFSTOPPED(wstatus)) {
      printf("stopped by signal %d\n", WSTOPSIG(wstatus));
      return 1;
    } else if (WIFCONTINUED(wstatus)) {
      printf("continued\n");
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

  fprintf(stderr, "%s", msg.c_str());
  fflush(stderr);
}

}
