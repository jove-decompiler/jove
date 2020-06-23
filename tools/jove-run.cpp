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

namespace fs = boost::filesystem;

namespace jove {
namespace opts {
static const char *sysroot;
static char **prog_argv;
}

static int ParseCommandLineArguments(int argc, char **argv);
static int run(void);

} // namespace jove

int main(int argc, char **argv) {
  if (int ret = jove::ParseCommandLineArguments(argc, argv))
    return ret;

  return jove::run();
}

namespace jove {

static fs::path jove_recover_path, jv_path;

static void Usage(void);

static int await_process_completion(pid_t);

int ParseCommandLineArguments(int argc, char **argv) {
  if (argc < 3) {
    Usage();
    return 1;
  }

  {
    const char *arg = argv[1];
    if (!fs::exists(arg)) {
      fprintf(stderr, "supplied path does not exist\n");
      return 1;
    }

    if (!fs::is_directory(arg)) {
      fprintf(stderr, "supplied path is not directory\n");
      return 1;
    }

    opts::sysroot = arg;
  }

  {
    const char *arg = argv[2];

    fs::path chrooted_path(opts::sysroot);
    chrooted_path /= arg;

    if (!fs::exists(chrooted_path)) {
      fprintf(stderr, "supplied path to prog does not exist\n");
      return 1;
    }

    if (!fs::exists(chrooted_path)) {
      fprintf(stderr, "supplied path to prog does not exist under sysroot\n");
      return 1;
    }

    opts::prog_argv = &argv[2];
  }

  return 0;
}

static void *recover_proc(const char *fifo_path);
static void IgnoreCtrlC(void);

int run(void) {
#if 0
  if (mount(opts::sysroot, opts::sysroot, "", MS_BIND, nullptr) < 0)
    fprintf(stderr, "bind mounting %s failed : %s\n", opts::sysroot,
            strerror(errno));
#endif

  {
    fs::path subdir = fs::path(opts::sysroot) / "proc";

    if (mount("proc", subdir.c_str(), "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC,
              nullptr) < 0)
      fprintf(stderr, "mounting procfs failed : %s\n", strerror(errno));
  }

  {
    fs::path subdir = fs::path(opts::sysroot) / "sys";

    if (mount("sys", subdir.c_str(), "sysfs",
              MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) < 0)
      fprintf(stderr, "mounting sysfs failed : %s\n", strerror(errno));
  }

  {
    fs::path subdir = fs::path(opts::sysroot) / "dev";

    if (mount("udev", subdir.c_str(), "devtmpfs", MS_NOSUID, "mode=0755") < 0)
      fprintf(stderr, "mounting devtmpfs failed : %s\n", strerror(errno));
  }

  {
    fs::path subdir = fs::path(opts::sysroot) / "dev" / "pts";

    if (mount("devpts", subdir.c_str(), "devpts", MS_NOSUID | MS_NOEXEC,
              "mode=0620,gid=5") < 0)
      fprintf(stderr, "mounting devpts failed : %s\n", strerror(errno));
  }

  {
    fs::path subdir = fs::path(opts::sysroot) / "dev" / "shm";

    if (mount("shm", subdir.c_str(), "tmpfs", MS_NOSUID | MS_NODEV,
              "mode=1777") < 0)
      fprintf(stderr, "mounting tmpfs failed : %s\n", strerror(errno));
  }

  {
    fs::path subdir = fs::path(opts::sysroot) / "run";

    if (mount("/run", subdir.c_str(), "", MS_BIND, nullptr) < 0)
      fprintf(stderr, "mounting /run failed : %s\n", strerror(errno));
  }

#if 0
  {
    fs::path subdir = fs::path(opts::sysroot) / "tmp";

    if (mount("tmp", subdir.c_str(), "tmpfs",
              MS_NOSUID | MS_NODEV | MS_STRICTATIME, "mode=1777") < 0)
      fprintf(stderr, "mounting /tmp failed : %s\n", strerror(errno));
  }
#endif

  {
    fs::path chrooted_resolv_conf =
        fs::path(opts::sysroot) / "etc" / "resolv.conf";

    //
    // ensure file exists to bind mount over
    //
    if (!fs::exists(chrooted_resolv_conf)) {
      int fd = open(chrooted_resolv_conf.c_str(),
                    O_WRONLY | O_CREAT | O_NOCTTY | O_NONBLOCK, 0666);
      if (fd < 0) {
        fprintf(stderr, "failed to create /etc/resolv.conf : %s\n",
                strerror(errno));
      }
      close(fd);
    }

    fs::path resolv_conf_path = fs::canonical("/etc/resolv.conf");

    if (mount(resolv_conf_path.c_str(), chrooted_resolv_conf.c_str(), "",
              MS_BIND, nullptr) < 0)
      fprintf(stderr, "mounting /etc/resolv.conf failed : %s\n",
              strerror(errno));
  }

  {
    fs::path chrooted_path =
        fs::path(opts::sysroot) / "etc" / "passwd";

    //
    // ensure file exists to bind mount over
    //
    if (!fs::exists(chrooted_path)) {
      int fd = open(chrooted_path.c_str(),
                    O_WRONLY | O_CREAT | O_NOCTTY | O_NONBLOCK, 0666);
      if (fd < 0) {
        fprintf(stderr, "failed to create %s : %s\n", chrooted_path.c_str(),
                strerror(errno));
      }
      close(fd);
    }

    fs::path path = fs::canonical("/etc/passwd");

    if (mount(path.c_str(), chrooted_path.c_str(), "", MS_BIND, nullptr) < 0)
      fprintf(stderr, "mounting %s failed : %s\n", path.c_str(),
              strerror(errno));
  }

  {
    fs::path chrooted_path = fs::path(opts::sysroot) / "etc" / "group";

    //
    // ensure file exists to bind mount over
    //
    if (!fs::exists(chrooted_path)) {
      int fd = open(chrooted_path.c_str(),
                    O_WRONLY | O_CREAT | O_NOCTTY | O_NONBLOCK, 0666);
      if (fd < 0) {
        fprintf(stderr, "failed to create %s : %s\n", chrooted_path.c_str(),
                strerror(errno));
      }
      close(fd);
    }

    fs::path path = fs::canonical("/etc/group");

    if (mount(path.c_str(), chrooted_path.c_str(), "", MS_BIND, nullptr) < 0)
      fprintf(stderr, "mounting %s failed : %s\n", path.c_str(),
              strerror(errno));
  }

  {
    fs::path chrooted_path = fs::path(opts::sysroot) / "etc" / "shadow";

    //
    // ensure file exists to bind mount over
    //
    if (!fs::exists(chrooted_path)) {
      int fd = open(chrooted_path.c_str(),
                    O_WRONLY | O_CREAT | O_NOCTTY | O_NONBLOCK, 0666);
      if (fd < 0) {
        fprintf(stderr, "failed to create %s : %s\n", chrooted_path.c_str(),
                strerror(errno));
      }
      close(fd);
    }

    fs::path path = fs::canonical("/etc/shadow");

    if (mount(path.c_str(), chrooted_path.c_str(), "", MS_BIND, nullptr) < 0)
      fprintf(stderr, "mounting %s failed : %s\n", path.c_str(),
              strerror(errno));
  }

  {
    fs::path chrooted_path = fs::path(opts::sysroot) / "etc" / "nsswitch.conf";

    //
    // ensure file exists to bind mount over
    //
    if (!fs::exists(chrooted_path)) {
      int fd = open(chrooted_path.c_str(),
                    O_WRONLY | O_CREAT | O_NOCTTY | O_NONBLOCK, 0666);
      if (fd < 0) {
        fprintf(stderr, "failed to create %s : %s\n", chrooted_path.c_str(),
                strerror(errno));
      }
      close(fd);
    }

    fs::path path = fs::canonical("/etc/nsswitch.conf");

    if (mount(path.c_str(), chrooted_path.c_str(), "", MS_BIND, nullptr) < 0)
      fprintf(stderr, "mounting %s failed : %s\n", path.c_str(),
              strerror(errno));
  }

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
  // get paths to stuff
  //
  jove_recover_path =
      boost::dll::program_location().parent_path() / "jove-recover";
  if (!fs::exists(jove_recover_path)) {
    fprintf(stderr, "couldn't find jove-recover at %s\n",
            jove_recover_path.c_str());
    return 1;
  }

  jv_path = fs::read_symlink(fs::path(opts::sysroot) / ".jv");
  if (!fs::exists(jv_path)) {
    fprintf(stderr, "recover: no jv found\n");
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
    if (chroot(opts::sysroot) < 0) {
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

    for (const std::string &s : env.s_vec)
      env.a_vec.push_back(s.c_str());
    env.a_vec.push_back(nullptr);

    execve(opts::prog_argv[0], opts::prog_argv,
           const_cast<char **>(&env.a_vec[0]));

    fprintf(stderr, "execve failed : %s\n", strerror(errno));
    return 1;
  }

  IgnoreCtrlC();

  //
  // wait for process to exit
  //
  int ret = await_process_completion(pid);

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

  {
    fs::path chrooted_path = fs::path(opts::sysroot) / "etc" / "nsswitch.conf";

    if (umount2(chrooted_path.c_str(), 0) < 0)
      fprintf(stderr, "unmounting %s failed : %s\n", chrooted_path.c_str(),
              strerror(errno));
  }

  {
    fs::path chrooted_path = fs::path(opts::sysroot) / "etc" / "shadow";

    if (umount2(chrooted_path.c_str(), 0) < 0)
      fprintf(stderr, "unmounting %s failed : %s\n", chrooted_path.c_str(),
              strerror(errno));
  }

  {
    fs::path chrooted_path = fs::path(opts::sysroot) / "etc" / "group";

    if (umount2(chrooted_path.c_str(), 0) < 0)
      fprintf(stderr, "unmounting %s failed : %s\n", chrooted_path.c_str(),
              strerror(errno));
  }

  {
    fs::path chrooted_path = fs::path(opts::sysroot) / "etc" / "passwd";

    if (umount2(chrooted_path.c_str(), 0) < 0)
      fprintf(stderr, "unmounting %s failed : %s\n", chrooted_path.c_str(),
              strerror(errno));
  }

  {
    fs::path chrooted_resolv_conf =
        fs::path(opts::sysroot) / "etc" / "resolv.conf";

    if (umount2(chrooted_resolv_conf.c_str(), 0) < 0)
      fprintf(stderr, "unmounting /etc/resolv.conf failed : %s\n",
              strerror(errno));
  }

#if 0
  {
    fs::path subdir = fs::path(opts::sysroot) / "tmp";

    if (umount2(subdir.c_str(), 0) < 0)
      fprintf(stderr, "unmounting /tmp failed : %s\n", strerror(errno));
  }
#endif

  {
    fs::path subdir = fs::path(opts::sysroot) / "run";

    if (umount2(subdir.c_str(), 0) < 0)
      fprintf(stderr, "unmounting /run failed : %s\n", strerror(errno));
  }

  {
    fs::path subdir = fs::path(opts::sysroot) / "dev" / "shm";

    if (umount2(subdir.c_str(), 0) < 0)
      fprintf(stderr, "unmounting tmpfs failed : %s\n", strerror(errno));
  }

  {
    fs::path subdir = fs::path(opts::sysroot) / "dev" / "pts";

    if (umount2(subdir.c_str(), 0) < 0)
      fprintf(stderr, "unmounting devpts failed : %s\n", strerror(errno));
  }

  {
    fs::path subdir = fs::path(opts::sysroot) / "dev";

    if (umount2(subdir.c_str(), 0) < 0)
      fprintf(stderr, "unmounting devtmpfs failed : %s\n", strerror(errno));
  }

  {
    fs::path subdir = fs::path(opts::sysroot) / "sys";

    if (umount2(subdir.c_str(), 0) < 0)
      fprintf(stderr, "unmounting sysfs failed : %s\n", strerror(errno));
  }

  {
    fs::path subdir = fs::path(opts::sysroot) / "proc";

    if (umount2(subdir.c_str(), 0) < 0)
      fprintf(stderr, "unmounting procfs failed : %s\n", strerror(errno));
  }

#if 0
  if (umount2(opts::sysroot, 0) < 0)
    fprintf(stderr, "unmounting %s failed : %s\n", opts::sysroot, strerror(errno));
#endif

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

  int recover_fd = open(fifo_path, O_RDONLY);
  if (recover_fd < 0) {
    fprintf(stderr, "recover: failed to open fifo at %s (%s)\n", fifo_path,
            strerror(errno));
    return nullptr;
  }

  auto cleanup_handler = [](void *arg) -> void {
    if (close(reinterpret_cast<long>(arg)) < 0)
      fprintf(stderr, "recover_proc: cleanup_handler: close failed (%s)\n",
              strerror(errno));
  };

  pthread_cleanup_push(cleanup_handler, reinterpret_cast<void *>(recover_fd));

  for (;;) {
    char ch;

    {
do_1b_read:
      // NOTE: read is a cancellation point
      ssize_t ret = read(recover_fd, &ch, 1);
      if (ret != 1) {
        if (ret < 0) {
          if (errno == EINTR)
            goto do_1b_read;

          fprintf(stderr, "recover: read failed (%s)\n", strerror(errno));
        } else if (ret == 0) {
          if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, nullptr) != 0)
            fprintf(stderr, "warning: pthread_setcancelstate failed\n");

          int new_recover_fd = open(fifo_path, O_RDONLY);
          if (new_recover_fd < 0) {
            fprintf(stderr, "recover: failed to open fifo at %s (%s)\n",
                    fifo_path, strerror(errno));
            return nullptr;
          }

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

          goto do_1b_read;
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
    // 'f' or 'b'.
    //
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
        struct iovec iov_arr[] = {
            _IOV_ENTRY(Caller.BIdx),
            _IOV_ENTRY(Caller.BBIdx),
            _IOV_ENTRY(Callee.BIdx),
            _IOV_ENTRY(Callee.FIdx)
        };

        size_t expected = _sum_iovec_lengths(iov_arr, ARRAY_SIZE(iov_arr));
do_f_read:
        ssize_t ret = readv(recover_fd, iov_arr, ARRAY_SIZE(iov_arr));
        if (ret != expected) {
          if (ret < 0) {
            if (errno == EINTR)
              goto do_f_read;

            fprintf(stderr, "recover: read failed (%s)\n", strerror(errno));
          } else {
            fprintf(stderr, "recover: read gave (%zd != %zu)\n", ret, expected);
          }

          break;
        }
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
        struct iovec iov_arr[] = {
            _IOV_ENTRY(IndBr.BIdx),
            _IOV_ENTRY(IndBr.BBIdx),
            _IOV_ENTRY(FileAddr)
        };

        size_t expected = _sum_iovec_lengths(iov_arr, ARRAY_SIZE(iov_arr));
do_b_read:
        ssize_t ret = readv(recover_fd, iov_arr, ARRAY_SIZE(iov_arr));
        if (ret != expected) {
          if (ret < 0) {
            if (errno == EINTR)
              goto do_b_read;

            fprintf(stderr, "recover: read failed (%s)\n", strerror(errno));
          } else {
            fprintf(stderr, "recover: read gave (%zd != %zu)\n", ret, expected);
          }
          break;
        }
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
        execve(jove_recover_path.c_str(), const_cast<char **>(argv), ::environ);
        fprintf(stderr, "recover: exec failed (%s)\n", strerror(errno));
        exit(1);
      }

      (void)await_process_completion(pid);
    } else {
      fprintf(stderr, "recover: unknown character (%c)\n", ch);
      break;
    }

    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, nullptr) != 0)
      fprintf(stderr, "warning: pthread_setcancelstate failed\n");
  }

  // (Clean-up handlers are not called if the thread terminates by performing a
  // return from the thread start function.)
  pthread_cleanup_pop(1 /* execute */);

  return nullptr;
}

void Usage(void) {
  puts("jove-run sysroot/ /path/to/prog [ARG]...");
}

int await_process_completion(pid_t pid) {
  int wstatus;
  do {
    if (waitpid(pid, &wstatus, WUNTRACED | WCONTINUED) < 0)
      abort();

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

}
