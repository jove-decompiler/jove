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
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/mman.h>

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

static cl::opt<std::string> TemporaryDir("tmpdir", cl::value_desc("directory"),
                                         cl::cat(JoveCategory));

static cl::opt<unsigned> Port("port", cl::desc("Network port to listen on"),
                              cl::Required, cl::cat(JoveCategory));

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

static std::string tmpdir;

static fs::path jove_recompile_path, jove_analyze_path, libjove_rt_path, dfsan_rt_path;

static int await_process_completion(pid_t);

static void IgnoreCtrlC(void);

static void print_command(const char **argv);

static std::atomic<bool> Cancelled(false);

static std::atomic<pid_t> app_pid;

static std::string string_of_sockaddr(const struct sockaddr *addr, socklen_t addrlen);

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
  int data_socket = -1;

  struct sockaddr_in addr;
  socklen_t addrlen;

  ConnectionProcArgs() {
    addrlen = sizeof(addr);
  }

  ~ConnectionProcArgs() {
    WithColor::note() << llvm::formatv(
        "connection closed [{0}]\n",
        string_of_sockaddr((struct sockaddr *)&this->addr, this->addrlen));

    if (close(data_socket) < 0) {
      int err = errno;
      WithColor::warning() << llvm::formatv(
          "failed to close data_socket: {0}]\n", strerror(err));
    }
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

  libjove_rt_path = (boost::dll::program_location().parent_path() /
                         std::string("libjove_rt.so.0"))
                            .string();
  if (!fs::exists(libjove_rt_path)) {
    WithColor::error() << llvm::formatv(
        "could not find jove runtime at {0}\n", libjove_rt_path.c_str());

    return 1;
  }

  {
    const char *dfsan_rt_filename = "libclang_rt.dfsan.jove-" TARGET_ARCH_NAME ".so";

    dfsan_rt_path =
	(boost::dll::program_location().parent_path().parent_path().parent_path() /
	 "third_party" / "llvm-project" / "install" / "lib" / "clang" / "10.0.0" /
	 "lib" / "linux" / dfsan_rt_filename).string();

    if (!fs::exists(dfsan_rt_path)) {
      WithColor::error() << llvm::formatv(
	  "could not find jove dfsan runtime at {0}\n", dfsan_rt_path.c_str());

      return 1;
    }
  }

  //
  // prepare to process the binaries by creating a unique temporary directory
  //
  if (opts::TemporaryDir.empty()) {
    char tmpdir_c_str[] = {'/', 't', 'm', 'p', '/', 'X', 'X', 'X', 'X', 'X', 'X', '\0'};
    if (!mkdtemp(tmpdir_c_str)) {
      int err = errno;
      WithColor::error() << llvm::formatv("mkdtemp failed: {0}\n", strerror(err));
      return 1;
    }

    tmpdir = tmpdir_c_str;
  } else {
    srand(time(NULL));
    tmpdir = opts::TemporaryDir + "/" + std::to_string(rand());

    if (opts::Verbose)
      llvm::errs() << "temporary dir: " << tmpdir.c_str() << '\n';

    if (mkdir(tmpdir.c_str(), 0777) < 0 && errno != EEXIST) {
      int err = errno;
      llvm::errs() << "could not create temporary directory: " << strerror(err) << '\n';
      return 1;
    }
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
    server_addr.sin_port = htons(opts::Port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

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
    ConnectionProcArgs *args = new ConnectionProcArgs;

    int data_socket = accept(connection_socket, (struct sockaddr *)&args->addr, &args->addrlen);
    if (unlikely(data_socket < 0)) {
      int err = errno;
      WithColor::error() << llvm::formatv("accept failed: {0}\n", strerror(err));

      delete args;
      return 1;
    }

    args->data_socket = data_socket;

    WithColor::note() << llvm::formatv(
        "connection established [{0}]\n",
        string_of_sockaddr((struct sockaddr *)&args->addr, args->addrlen));

    //
    // Create thread to service that connection
    //
    {
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

static ssize_t robust_sendfile(int socket, const char *file_path, size_t file_size) {
  int fd = open(file_path, O_RDONLY);

  if (fd < 0)
    return -errno;

  struct closeme_t {
    int fd;
    closeme_t (int fd) : fd(fd) {}
    ~closeme_t() { close(fd); }
  } closeme(fd);

  const size_t saved_file_size = file_size;

  do {
    ssize_t ret = sendfile(socket, fd, nullptr, file_size);

    if (ret == 0)
      return -EIO;

    if (ret < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv("sendfile failed: {0}\n",
                                          strerror(err));
      return -err;
    }

    file_size -= ret;
  } while (file_size > 0);

  return saved_file_size;
}

static uint32_t size_of_file32(const char *path) {
  uint32_t res;
  {
    struct stat st;
    if (stat(path, &st) < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv("stat failed: {0}\n", strerror(err));
      return 0;
    }

    res = st.st_size;
  }

  return res;
}

static ssize_t robust_sendfile_with_size(int socket, const char *file_path) {
  ssize_t ret;

  uint32_t file_size = size_of_file32(file_path);

  ret = robust_write(socket, &file_size, sizeof(file_size));
  if (ret < 0)
    return ret;

  ret = robust_sendfile(socket, file_path, file_size);
  if (ret < 0)
    return ret;

  return file_size;
}

static ssize_t receive_file_with_size(int socket, const char *out, unsigned file_perm) {
  uint32_t file_size;
  if (robust_read(socket, &file_size, sizeof(uint32_t)) < 0)
    return false;

  std::vector<uint8_t> buff;
  buff.resize(file_size);

  {
    ssize_t res = robust_read(socket, &buff[0], buff.size());
    if (res < 0)
      return res;
  }

  ssize_t res = -EBADF;
  {
    int fd = open(out, O_WRONLY | O_TRUNC | O_CREAT, file_perm);
    if (fd < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv("failed to receive file {0}: {1}\n",
                                          out, strerror(err));
      return -err;
    }

    res = robust_write(fd, &buff[0], buff.size());

    if (close(fd) < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv("failed to close received file {0}: {1}\n",
                                          out, strerror(err));
      return -err;
    }
  }

  return res;
}

std::string string_of_sockaddr(const struct sockaddr *addr, socklen_t addrlen) {
  char hbuf[NI_MAXHOST];
  int ret = getnameinfo(addr, addrlen, hbuf, sizeof(hbuf), nullptr, 0,
                        NI_NUMERICHOST);
  if (ret != 0) {
    llvm::errs() << llvm::formatv("{0}: getnameinfo failed ({1})", __func__,
                                  gai_strerror(ret));
    return "";
  }

  return std::string(hbuf);
}

void *ConnectionProc(void *arg) {
  std::unique_ptr<ConnectionProcArgs> args(
      reinterpret_cast<ConnectionProcArgs *>(arg));

  int data_socket = args->data_socket;

  //
  // check for magic bytes
  //
  {
    char magic[4];
    if (robust_read(data_socket, &magic[0], sizeof(magic)) < 0 ||
       !(magic[0] == 'J' &&
         magic[1] == 'O' &&
         magic[2] == 'V' &&
         magic[3] == 'E')) {
      WithColor::error() << "invalid magic bytes\n";
      return nullptr;
    }
  }

  //
  // create a temporary directory
  //
  srand(time(NULL));
  fs::path TemporaryDir = fs::path(tmpdir) / std::to_string(rand());
  fs::create_directory(TemporaryDir);

  //
  // read header
  //
  uint8_t header;
  if (robust_read(data_socket, &header, sizeof(header)) != sizeof(header)) {
    WithColor::error() << "failed to read header\n";
    return nullptr;
  }

  //
  // --pinned-globals XXX
  //
  std::vector<std::string> PinnedGlobals;
  {
    uint8_t NPinnedGlobals = 0;
    if (robust_read(data_socket, &NPinnedGlobals, sizeof(NPinnedGlobals)) != sizeof(NPinnedGlobals)) {
      WithColor::error() << "failed to read NPinnedGlobals\n";
      return nullptr;
    }

    PinnedGlobals.resize(NPinnedGlobals);
  }

  if (opts::Verbose)
    llvm::errs() << llvm::formatv("NPinnedGlobals: {0}\n", PinnedGlobals.size());

  for (unsigned i = 0; i < PinnedGlobals.size(); ++i) {
    std::string &PinnedGlobalStr = PinnedGlobals[i];

    {
      uint8_t PinnedGlobalStrLen;
      if (robust_read(data_socket, &PinnedGlobalStrLen, sizeof(PinnedGlobalStrLen)) != sizeof(PinnedGlobalStrLen)) {
        WithColor::error() << "failed to read PinnedGlobalStrLen\n";
        return nullptr;
      }

      PinnedGlobalStr.resize(PinnedGlobalStrLen);
    }

    if (PinnedGlobalStr.size() == 0)
      continue;

    if (robust_read(data_socket, &PinnedGlobalStr[0], PinnedGlobalStr.size()) != PinnedGlobalStr.size()) {
      WithColor::error() << "failed to read PinnedGlobalStr\n";
      return nullptr;
    }
  }

  //
  // parse the header
  //
  struct {
    bool dfsan, foreign_libs, trace, optimize;
  } options;

  std::bitset<8> headerBits(header);

  options.dfsan        = headerBits.test(0);
  options.foreign_libs = headerBits.test(1);
  options.trace        = headerBits.test(2);
  options.optimize     = headerBits.test(3);

  std::string tmpjv = (TemporaryDir / "decompilation.jv").string();
  {
    ssize_t ret = receive_file_with_size(data_socket, tmpjv.c_str(), 0666);
    if (ret < 0) {
      WithColor::error()
          << llvm::formatv("failed to receive file {0} from remote: {1}\n",
                           tmpjv.c_str(), strerror(-ret));
      return nullptr;
    }
  }

  //
  // analyze
  //
  pid_t pid = fork();
  if (!pid) {
    std::vector<const char *> arg_vec = {
        jove_analyze_path.c_str(),

        "-d", tmpjv.c_str()
    };

    std::string pinned_globals_arg = "--pinned-globals=";
    if (!PinnedGlobals.empty()) {
      for (const std::string &PinnedGlbStr : PinnedGlobals) {
        pinned_globals_arg.append(PinnedGlbStr);
        pinned_globals_arg.push_back(',');
      }
      assert(!pinned_globals_arg.empty());
      pinned_globals_arg.resize(pinned_globals_arg.size() - 1);

      arg_vec.push_back(pinned_globals_arg.c_str());
    }

    arg_vec.push_back(nullptr);

    print_command(&arg_vec[0]);
    execve(arg_vec[0], const_cast<char **>(&arg_vec[0]), ::environ);

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
  std::string sysroot_dir = (TemporaryDir / "sysroot").string();
  fs::create_directory(sysroot_dir);

  pid = fork();
  if (!pid) {
    std::vector<const char *> arg_vec = {
        jove_recompile_path.c_str(),

        "-d", tmpjv.c_str(),
        "-o", sysroot_dir.c_str(),
    };

    if (options.dfsan)
      arg_vec.push_back("--dfsan");
    if (options.foreign_libs)
      arg_vec.push_back("--foreign-libs");
    if (options.trace)
      arg_vec.push_back("--trace");
    if (options.optimize)
      arg_vec.push_back("--optimize");

    std::string pinned_globals_arg = "--pinned-globals=";
    if (!PinnedGlobals.empty()) {
      for (const std::string &PinnedGlbStr : PinnedGlobals) {
        pinned_globals_arg.append(PinnedGlbStr);
        pinned_globals_arg.push_back(',');
      }
      assert(!pinned_globals_arg.empty());
      pinned_globals_arg.resize(pinned_globals_arg.size() - 1);

      arg_vec.push_back(pinned_globals_arg.c_str());
    }

    arg_vec.push_back(nullptr);

    print_command(&arg_vec[0]);
    execve(arg_vec[0], const_cast<char **>(&arg_vec[0]), ::environ);

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
    // send new jv
    //
    ssize_t ret = robust_sendfile_with_size(data_socket, tmpjv.c_str());
    if (ret < 0) {
      WithColor::error() << llvm::formatv(
          "robust_sendfile_with_size failed: {0}\n", strerror(-ret));
      return nullptr;
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
      WithColor::error() << llvm::formatv("{0} not found\n",
                                          chrooted_path.c_str());
      return nullptr;
    }

    if (opts::Verbose)
      llvm::errs() << llvm::formatv("sending {0}\n", chrooted_path.c_str());

    ssize_t ret = robust_sendfile_with_size(data_socket, chrooted_path.c_str());

    if (ret < 0) {
      WithColor::error() << llvm::formatv(
          "robust_sendfile_with_size failed: {0}\n", strerror(-ret));
      return nullptr;
    }
  }

  {
    if (opts::Verbose)
      llvm::errs() << "sending jove runtime\n";

    ssize_t ret = robust_sendfile_with_size(data_socket, libjove_rt_path.c_str());

    if (ret < 0) {
      WithColor::error() << llvm::formatv(
          "robust_sendfile_with_size failed: {0}\n", strerror(-ret));
      return nullptr;
    }
  }

  if (options.dfsan) {
    if (opts::Verbose)
      llvm::errs() << "sending jove dfsan runtime\n";

    ssize_t ret = robust_sendfile_with_size(data_socket, dfsan_rt_path.c_str());

    if (ret < 0) {
      WithColor::error() << llvm::formatv(
          "robust_sendfile_with_size failed: {0}\n", strerror(-ret));
      return nullptr;
    }
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
