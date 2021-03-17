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
#include <sys/sendfile.h>
#include <fcntl.h>
#include <pthread.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/WithColor.h>
#include <llvm/Support/FormatVariadic.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

namespace fs = boost::filesystem;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace opts {
static cl::OptionCategory JoveCategory("Specific Options");

static cl::opt<bool> Verbose("verbose",
                             cl::desc("Output helpful messages for debugging"),
                             cl::cat(JoveCategory));

static cl::alias VerboseAlias("v", cl::desc("Alias for --verbose."),
                              cl::aliasopt(Verbose), cl::cat(JoveCategory));

} // namespace opts

namespace jove {

static int server(void);

} // namespace jove

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::HideUnrelatedOptions({&opts::JoveCategory, &llvm::ColorCategory});
  cl::AddExtraVersionPrinter([](llvm::raw_ostream &OS) -> void {
    OS << "jove version " JOVE_VERSION "\n";
  });
  cl::ParseCommandLineOptions(argc, argv, "Jove Server\n");

  return jove::server();
}

namespace jove {

static fs::path jove_recompile_path, jove_run_path, jove_analyze_path;

static int await_process_completion(pid_t);

static void IgnoreCtrlC(void);

static void print_command(const char **argv);

static std::atomic<bool> Cancelled(false);

static std::atomic<pid_t> app_pid;

static void sighandler(int no) {
  switch (no) {
  case SIGTERM:
    if (pid_t pid = app_pid.load()) {
      // what we really want to do is terminate the child.
      if (kill(pid, SIGTERM) < 0) {
        int err = errno;
        WithColor::warning() << llvm::formatv(
            "failed to redirect SIGTERM: {0}\n", strerror(err));
      }
    } else {
      WithColor::warning() << "received SIGTERM but no app to redirect to!\n";
    }
    break;

  case SIGINT:
    llvm::errs() << "Received SIGINT. Cancelling..\n";
    Cancelled.store(true);
    break;

  default:
    abort();
  }
}

struct ConnectionProcArgs {
  int data_socket;

  ConnectionProcArgs(int data_socket)
      : data_socket(data_socket) {
    struct stat64 st;
    if (fstat64(data_socket, &st) < 0)
      memset(&st, 0, sizeof(st));

    WithColor::note() << llvm::formatv("connection established [{0:x}]\n", st.st_ino);
  }

  ~ConnectionProcArgs() {
    struct stat64 st;
    if (fstat64(data_socket, &st) < 0)
      memset(&st, 0, sizeof(st));

    WithColor::note() << llvm::formatv("connection closed [{0:x}]\n", st.st_ino);

    close(data_socket);
  }
};

static void *ConnectionProc(void *);

int server(void) {
  jove_analyze_path = (boost::dll::program_location().parent_path() /
                       std::string("jove-analyze"))
                          .string();
  if (!fs::exists(jove_analyze_path)) {
    WithColor::error() << llvm::formatv(
        "could not find jove-analyze at {0}\n", jove_analyze_path.c_str());

    return 1;
  }

  //
  // Create TCP socket
  //
  int connection_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (connection_socket < 0) {
    int err = errno;
    WithColor::error() << llvm::formatv("socket failed: {0}\n", strerror(err));
    return 1;
  }

  {
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(2000);
    server_addr.sin_addr.s_addr = INADDR_ANY; //inet_addr("127.0.0.1");

    int ret = bind(connection_socket,
                   (const struct sockaddr *)&server_addr,
                   sizeof(server_addr));
    if (ret < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv("bind failed: {0}\n", strerror(err));
      return 1;
    }
  }

  //
  // Prepare for accepting connections. The backlog size is set
  // to BACKLOG. So while one request is being processed other requests
  // can be waiting.
  //
  {
    constexpr unsigned BACKLOG = 20;

    int ret = listen(connection_socket, BACKLOG);
    if (ret < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv("listen failed: {0}\n", strerror(err));
      return 1;
    }
  }

  //
  // This is the main loop for handling connections
  //
  for (;;) {
    //
    // Wait for incoming connection
    //
    int data_socket = accept(connection_socket, nullptr, nullptr);
    if (unlikely(data_socket < 0)) {
      int err = errno;
      WithColor::error() << llvm::formatv("accept failed: {0}\n", strerror(err));
      return 1;
    }

    //
    // Create thread to service that connection
    //
    {
      ConnectionProcArgs *args = new ConnectionProcArgs(data_socket);

      pthread_t thd;
      int ret = pthread_create(&thd, nullptr, ConnectionProc, args);
      if (unlikely(ret != 0)) {
        int err = errno;
        WithColor::error() << llvm::formatv("pthread_create failed: {0}\n",
                                            strerror(err));
        delete args;
      }
    }
  }

  //
  // cleanup
  //
  close(connection_socket);

  return 0;
}

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

void *ConnectionProc(void *arg) {
  std::unique_ptr<ConnectionProcArgs> args(
      reinterpret_cast<ConnectionProcArgs *>(arg));

  int data_socket = args->data_socket;

  auto do_read = [&](void *out, ssize_t n) -> bool {
    ssize_t ret = recv(data_socket, out, n, 0);

    if (unlikely(ret <= 0)) {
      if (ret < 0) {
        int err = errno;
        WithColor::error() << llvm::formatv("{0}: recv failed (%s)", __func__,
                                            strerror(err));
      }

      return false;
    }

    return ret == n;
  };

  for (;;) {
    uint32_t JvSize = 0;
    if (unlikely(!do_read(&JvSize, sizeof(JvSize))))
      return nullptr;

    if (opts::Verbose)
      llvm::errs() << llvm::formatv("JvSize is {0}\n", JvSize);

    {
      std::vector<uint8_t> jv_contents;
      jv_contents.resize(JvSize);
      if (robust_read(data_socket, &jv_contents[0], JvSize) < 0)
        return nullptr;

      {
        int jvfd = open("/tmp/tmp.jv", O_WRONLY | O_CREAT, 0666);
        robust_write(jvfd, &jv_contents[0], jv_contents.size());
        close(jvfd);
      }
    }

    //
    // analyze
    //
    pid_t pid = fork();
    if (!pid) {
      const char *arg_arr[] = {
          jove_analyze_path.c_str(),

          "-d", "/tmp/tmp.jv",

          nullptr
      };

      print_command(&arg_arr[0]);
      execve(arg_arr[0], const_cast<char **>(&arg_arr[0]), ::environ);

      int err = errno;
      WithColor::error() << llvm::formatv("execve failed: {0}\n",
                                          strerror(err));
      return nullptr;
    }

    if (int ret = await_process_completion(pid)) {
      WithColor::error() << llvm::formatv("jove-analyze failed [{0}]\n", ret);
      return nullptr;
    }

    return nullptr;
  }

  return nullptr;
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

  llvm::errs() << msg;
  llvm::errs().flush();
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
