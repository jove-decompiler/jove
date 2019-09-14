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
#include <fcntl.h>

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

static void recover(const char *fifo_path);

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

  {
    fs::path subdir = fs::path(opts::sysroot) / "tmp";

    if (mount("tmp", subdir.c_str(), "tmpfs",
              MS_NOSUID | MS_NODEV | MS_STRICTATIME, "mode=1777") < 0)
      fprintf(stderr, "mounting /tmp failed : %s\n", strerror(errno));
  }

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
  if (mkfifo(recover_fifo_path.c_str(), 0666) < 0) {
    fprintf(stderr, "pipe failed : %s\n", strerror(errno));
    return 1;
  }

  int pid = fork();
  if (!pid) {
    fs::path canon_sysroot = fs::canonical(opts::sysroot);

    if (chdir("/") < 0) {
      fprintf(stderr, "chdir failed : %s\n", strerror(errno));
      return 1;
    }

    if (chroot(canon_sysroot.c_str()) < 0) {
      fprintf(stderr, "chroot failed : %s\n", strerror(errno));
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

    for (const std::string &s : env.s_vec)
      env.a_vec.push_back(s.c_str());
    env.a_vec.push_back(nullptr);

    execve(opts::prog_argv[0], opts::prog_argv,
           const_cast<char **>(&env.a_vec[0]));

    fprintf(stderr, "execve failed : %s\n", strerror(errno));
    return 1;
  }

  std::thread pipe_reader(recover, recover_fifo_path.c_str());

  //
  // wait for process to exit
  //
  int ret = await_process_completion(pid);

  {
    int fd = open(recover_fifo_path.c_str(), O_WRONLY);

    {
      char ch = 'z';
      write(fd, &ch, 1);
    }

    close(fd);
  }

  pipe_reader.join();

  if (unlink(recover_fifo_path.c_str()) < 0) {
    fprintf(stderr, "unlink of recover pipe failed : %s\n", strerror(errno));
    return 1;
  }

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

  {
    fs::path subdir = fs::path(opts::sysroot) / "tmp";

    if (umount2(subdir.c_str(), 0) < 0)
      fprintf(stderr, "unmounting /tmp failed : %s\n", strerror(errno));
  }

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

void recover(const char *fifo_path) {
  for (;;) {
    std::vector<uint8_t> bytes;

    {
      int fd = open(fifo_path, O_RDONLY);
      if (fd < 0) {
        fprintf(stderr, "recover: failed to open fifo at %s (%s)\n", fifo_path,
                strerror(errno));
        return;
      }

      for (;;) {
        uint8_t byte;
        ssize_t ret = read(fd, &byte, 1);

        if (ret == 1) {
          bytes.push_back(byte);
          continue;
        }

        if (ret == 0) {
          //fprintf(stderr, "recover: read gave 0\n");
          break;
        }

        assert(ret < 0);
        fprintf(stderr, "recover: read failed (%s)\n", strerror(errno));
        break;
      }

      if (close(fd) < 0)
        fprintf(stderr, "recover: couldn't close fd (%s)\n", strerror(errno));
    }

    if (bytes.empty()) {
      fprintf(stderr, "recover: got 0 bytes\n");
      return;
    }

    if (bytes[0] == 'z')
      return;

    fprintf(stderr, "recover: %c (%zu bytes)\n", bytes[0], bytes.size());

    //
    // get paths to stuff
    //
    fs::path jove_recover_path =
        boost::dll::program_location().parent_path() / "jove-recover";
    if (!fs::exists(jove_recover_path)) {
      fprintf(stderr, "recover: couldn't find jove-recover at %s\n",
              jove_recover_path.c_str());
      return;
    }

    fs::path jv_path = fs::read_symlink(fs::path(opts::sysroot) / ".jv");
    if (!fs::exists(jv_path)) {
      fprintf(stderr, "recover: no jv found\n");
      return;
    }

    switch (bytes[0]) {
    case 'b': {
      //
      // goto
      //
      assert(bytes.size() == 1 + 2 * sizeof(uint32_t) + sizeof(uintptr_t));

      struct {
        uint32_t BIdx;
        uint32_t BBIdx;
      } IndBr;

      uintptr_t FileAddr;

      IndBr.BIdx  = *reinterpret_cast<uint32_t *>(&bytes[1]);
      IndBr.BBIdx = *reinterpret_cast<uint32_t *>(&bytes[1 + sizeof(uint32_t)]);
      FileAddr = *reinterpret_cast<uintptr_t *>(&bytes[1 + 2 * sizeof(uint32_t)]);

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

      await_process_completion(pid);
      break;
    }

    case 'f': {
      //
      // call
      //
      assert(bytes.size() == 1 + 4 * sizeof(uint32_t));

      struct {
        uint32_t BIdx;
        uint32_t BBIdx;
      } Caller;

      struct {
        uint32_t BIdx;
        uint32_t FIdx;
      } Callee;

      Caller.BIdx  = *reinterpret_cast<uint32_t *>(&bytes[1 + 0 * sizeof(uint32_t)]);
      Caller.BBIdx = *reinterpret_cast<uint32_t *>(&bytes[1 + 1 * sizeof(uint32_t)]);

      Callee.BIdx  = *reinterpret_cast<uint32_t *>(&bytes[1 + 2 * sizeof(uint32_t)]);
      Callee.FIdx  = *reinterpret_cast<uint32_t *>(&bytes[1 + 3 * sizeof(uint32_t)]);

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

      await_process_completion(pid);
      break;
    }

    default:
      fprintf(stderr, "recover: unknown byte %02x\n", bytes[0]);
      break;
    }
  }
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

}
