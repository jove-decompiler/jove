#include <unistd.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <boost/filesystem.hpp>
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

    if (!fs::is_regular_file(chrooted_path)) {
      fprintf(stderr, "supplied path to prog is not directory\n");
      return 1;
    }

    opts::prog_argv = &argv[2];
  }

  return 0;
}

int run(void) {
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

#if 0
  {
    std::string input;
    std::getline(std::cin, input);
  }
#endif

  int pid = fork();
  if (!pid) {
    if (chroot(opts::sysroot) < 0) {
      fprintf(stderr, "chroot failed : %s\n", strerror(errno));
      return 1;
    }

    execve(opts::prog_argv[0], opts::prog_argv, ::environ);

    fprintf(stderr, "execve failed : %s\n", strerror(errno));
    return 1;
  }

  int ret = await_process_completion(pid);

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

  return ret;
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
