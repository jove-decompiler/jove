#include "jove/jove.h"
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
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/bitset.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/graph/adj_list_serialize.hpp>
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

static char tmpdir[] = {'/', 't', 'm', 'p', '/', 'X',
                        'X', 'X', 'X', 'X', 'X', '\0'};

static fs::path jove_recompile_path, jove_analyze_path;

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

  jove_recompile_path = (boost::dll::program_location().parent_path() /
                         std::string("jove-recompile"))
                            .string();
  if (!fs::exists(jove_recompile_path)) {
    WithColor::error() << llvm::formatv(
        "could not find jove-recompile at {0}\n", jove_analyze_path.c_str());

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
  // prepare to process the binaries by creating a unique temporary directory
  //
  if (!mkdtemp(tmpdir)) {
    int err = errno;
    WithColor::error() << llvm::formatv("mkdtemp failed: {0}\n", strerror(err));
    return 1;
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

static bool receive_file_with_size(int data_socket, const char *out, unsigned size) {
  int fd = open(out, O_WRONLY | O_TRUNC | O_CREAT | O_TRUNC, 0666);
  if (fd < 0) {
    WithColor::error() << llvm::formatv("failed to receive {0}!\n", out);
    return;
  }

  if (ftruncate(fd, size) < 0) {
    int err = errno;
    WithColor::error() << llvm::formatv("ftruncate failed: {0}\n", strerror(err));
    return;
  }

  void *p = mmap(NULL, size, PROT_WRITE, MAP_PRIVATE, fd, 0)
  if (p == MAP_FAILED) {
    int err = errno;
    WithColor::error() << llvm::formatv("mmap failed: {0}\n", strerror(err));
    return;
  }

  {
    ssize_t ret = robust_read(data_socket, p, size);
    if (ret < 0) {
      WithColor::error() << llvm::formatv("robust_read failed: {0}\n", strerror(-ret));
      return nullptr;
    }
  }

  if (msync(p, size, MS_SYNC) < 0) {
    int err = errno;
    WithColor::error() << llvm::formatv("msync failed: {0}\n", strerror(err));
    return;
  }

  if (munmap(p, size) < 0) {
    int err = errno;
    WithColor::error() << llvm::formatv("munmap failed: {0}\n", strerror(err));
    return;
  }

  if (close(fd) < 0) {
    int err = errno;
    WithColor::error() << llvm::formatv("close failed: {0}\n", strerror(err));
    return;
  }
}

void *ConnectionProc(void *arg) {
  std::unique_ptr<ConnectionProcArgs> args(
      reinterpret_cast<ConnectionProcArgs *>(arg));

  int data_socket = args->data_socket;

  for (;;) {
    //
    // get size of jv file
    //
    std::string tmpjv;
    {
      uint32_t JvSize = 0;
      if (robust_read(data_socket, &JvSize, sizeof(JvSize)) < 0)
        return nullptr;

      tmpjv = (fs::path(tmpdir) / "decompilation.jv").string();
      receive_file_with_size(tmpjv.c_str(), JvSize);
    }

    //
    // analyze
    //
    pid_t pid = fork();
    if (!pid) {
      const char *arg_arr[] = {
          jove_analyze_path.c_str(),

          "-d", tmpjv.c_str(),

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

    //
    // recompile
    //
    std::string sysroot_dir = (fs::path(tmpdir) / "sysroot").string();
    fs::create_directory(sysroot_dir);

    pid = fork();
    if (!pid) {
      const char *arg_arr[] = {
          jove_recompile_path.c_str(),

          "-d", tmpjv.c_str(),
          "-o", sysroot_dir.c_str(),

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
      WithColor::error() << llvm::formatv("jove-recompile failed [{0}]\n", ret);
      return nullptr;
    }

    {
      //
      // get size of new jv
      //
      uint32_t jv_size = 0;
      {
        struct stat st;
        if (stat(tmpjv.c_str(), &st) < 0) {
          int err = errno;
          WithColor::error() << llvm::formatv("stat failed: {0}\n", strerror(err));
          break;
        }

        jv_size = st.st_size;
      }

      if (robust_write(data_socket, &jv_size, sizeof(uint32_t)) < 0)
        break;

      //
      // send new jv
      //
      {
        int jvfd = open(tmpjv.c_str(), O_RDONLY);

        do {
          ssize_t ret = sendfile(data_socket, jvfd, nullptr, jv_size);
          if (ret < 0) {
            int err = errno;
            WithColor::error()
                << llvm::formatv("sendfile failed: {0}\n", strerror(err));
            return nullptr;
          }

          jv_size -= ret;
        } while (jv_size > 0);

        close(jvfd);
      }
    }

    //
    // send the rest of the DSO's that were recompiled
    //
    decompilation_t decompilation;
    {
      std::ifstream ifs(tmpjv.c_str());

      boost::archive::text_iarchive ia(ifs);
      ia >> decompilation;
    }

    for (const binary_t &binary : decompilation.Binaries) {
      if (binary.IsVDSO)
        continue;
      if (binary.IsDynamicLinker)
        continue;

      fs::path chrooted_path(fs::path(sysroot_dir) / binary.Path);
      if (!fs::exists(chrooted_path)) {
        WithColor::warning() << llvm::formatv("skipping {0} (not found)\n",
                                              chrooted_path.c_str());
        continue;
      }

      uint32_t dso_size = 0;
      {
        struct stat st;
        if (stat(chrooted_path.c_str(), &st) < 0) {
          int err = errno;
          WithColor::error() << llvm::formatv("stat failed: {0}\n", strerror(err));
          break;
        }

        dso_size = st.st_size;
      }

      if (opts::Verbose)
        llvm::errs() << llvm::formatv("sending {0}\n", chrooted_path.c_str());

      if (robust_write(data_socket, &dso_size, sizeof(uint32_t)) < 0)
        break;

      {
        int dsofd = open(chrooted_path.c_str(), O_RDONLY);

        do {
          ssize_t ret = sendfile(data_socket, dsofd, nullptr, dso_size);
          if (ret < 0) {
            int err = errno;
            WithColor::error()
                << llvm::formatv("sendfile failed: {0}\n", strerror(err));
            return nullptr;
          }

          dso_size -= ret;
        } while (dso_size > 0);

        close(dsofd);
      }
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
