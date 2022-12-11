#include "tool.h"

#include <boost/dll/runtime_symbol_info.hpp>
#include <boost/filesystem.hpp>

#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

#include <cinttypes>
#include <string>
#include <thread>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

namespace fs = boost::filesystem;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

class ServerTool : public Tool {
  struct Cmdline {
    cl::opt<unsigned> Port;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Port("port", cl::desc("Network port to listen on"), cl::Required,
               cl::cat(JoveCategory)) {}
  } opts;

public:
  ServerTool() : opts(JoveCategory) {}

  int Run(void);

  void *ConnectionProc(void *);
};

JOVE_REGISTER_TOOL("server", ServerTool);

static fs::path libjove_rt_path, dfsan_rt_path;

static std::atomic<bool> Cancelled(false);

static std::atomic<pid_t> app_pid;

static std::string string_of_sockaddr(const struct sockaddr *addr, socklen_t addrlen);

static void sighandler(int no) {
  switch (no) {
  case SIGTERM:
    if (pid_t pid = app_pid.load()) {
      // what we really want to do is terminate the child.
      if (::kill(pid, SIGTERM) < 0) {
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

    if (::close(data_socket) < 0) {
      int err = errno;
      WithColor::warning() << llvm::formatv(
          "failed to close data_socket: {0}]\n", strerror(err));
    }
  }
};

int ServerTool::Run(void) {
  libjove_rt_path =
      (boost::dll::program_location().parent_path() / "libjove_rt.so").string();
  if (!fs::exists(libjove_rt_path)) {
    WithColor::error() << llvm::formatv(
        "could not find jove runtime at {0}\n", libjove_rt_path.c_str());

    return 1;
  }

  dfsan_rt_path =
      (boost::dll::program_location().parent_path().parent_path().parent_path() /
       "prebuilts" / "lib" / ("libclang_rt.dfsan.jove-" TARGET_ARCH_NAME ".so")).string();

  if (!fs::exists(dfsan_rt_path)) {
    WithColor::error() << llvm::formatv(
        "could not find jove dfsan runtime at {0}\n", dfsan_rt_path.c_str());

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
    server_addr.sin_port = htons(opts.Port);
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
      std::thread thd(&ServerTool::ConnectionProc, this, args);
      thd.detach();
    }
  }

  //
  // cleanup
  //
  ::close(connection_socket);

  return 0;
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

void *ServerTool::ConnectionProc(void *arg) {
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
  fs::path TemporaryDir;
  {
    static std::atomic<unsigned> x = 0;

    TemporaryDir = fs::path(temporary_dir()) / std::to_string(x++);
    fs::create_directory(TemporaryDir);
  }

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

  if (IsVerbose())
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
    bool dfsan, foreign_libs, trace, optimize, skip_copy_reloc_hack, debug_sjlj, abi_calls;
  } options;

  std::bitset<8> headerBits(header);

  options.dfsan        = headerBits.test(0);
  options.foreign_libs = headerBits.test(1);
  options.trace        = headerBits.test(2);
  options.optimize     = headerBits.test(3);
  options.skip_copy_reloc_hack = headerBits.test(4);
  options.debug_sjlj = headerBits.test(5);
  options.abi_calls = headerBits.test(6);

  std::string tmpjv = (TemporaryDir / "jv.jv").string();
  {
    ssize_t ret = robust_receive_file_with_size(data_socket, tmpjv.c_str(), 0666);
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
  int rc = RunToolToExit("analyze", [&](auto Arg) {
    Arg("-d");
    Arg(tmpjv);

#if 0
    if (!PinnedGlobals.empty()) {
      std::string pinned_globals_arg = "--pinned-globals=";

      for (const std::string &PinnedGlbStr : PinnedGlobals) {
        pinned_globals_arg.append(PinnedGlbStr);
        pinned_globals_arg.push_back(',');
      }
      assert(!pinned_globals_arg.empty());
      pinned_globals_arg.resize(pinned_globals_arg.size() - 1);

      Arg(pinned_globals_arg);
    }
#endif
  });

  if (rc) {
    WithColor::error() << llvm::formatv("jove analyze failed!\n");
    return nullptr;
  }

  //
  // recompile
  //
  std::string sysroot_dir = (TemporaryDir / "sysroot").string();
  fs::create_directory(sysroot_dir);

  rc = RunToolToExit("recompile", [&](auto Arg) {
    Arg("-d");
    Arg(tmpjv);
    Arg("-o");
    Arg(sysroot_dir);

    if (options.dfsan)
      Arg("--dfsan");
    if (options.foreign_libs)
      Arg("--foreign-libs");
    if (options.trace)
      Arg("--trace");
    if (options.optimize)
      Arg("--optimize");
    if (options.skip_copy_reloc_hack)
      Arg("--skip-copy-reloc-hack");
    if (options.debug_sjlj)
      Arg("--debug-sjlj");
    if (!options.abi_calls)
      Arg("--abi-calls=0");

#if 0
    if (!PinnedGlobals.empty()) {
      std::string pinned_globals_arg = "--pinned-globals=";

      for (const std::string &PinnedGlbStr : PinnedGlobals) {
        pinned_globals_arg.append(PinnedGlbStr);
        pinned_globals_arg.push_back(',');
      }
      assert(!pinned_globals_arg.empty());
      pinned_globals_arg.resize(pinned_globals_arg.size() - 1);

      Arg(pinned_globals_arg);
    }
#endif
  });

  if (rc) {
    WithColor::error() << llvm::formatv("jove recompile failed!\n");
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
  ReadJvFromFile(tmpjv, jv);

  for (const binary_t &binary : jv.Binaries) {
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

    if (IsVerbose())
      llvm::errs() << llvm::formatv("sending {0}\n", chrooted_path.c_str());

    ssize_t ret = robust_sendfile_with_size(data_socket, chrooted_path.c_str());

    if (ret < 0) {
      WithColor::error() << llvm::formatv(
          "robust_sendfile_with_size failed: {0}\n", strerror(-ret));
      return nullptr;
    }
  }

  {
    if (IsVerbose())
      llvm::errs() << "sending jove runtime\n";

    ssize_t ret = robust_sendfile_with_size(data_socket, libjove_rt_path.c_str());

    if (ret < 0) {
      WithColor::error() << llvm::formatv(
          "robust_sendfile_with_size failed: {0}\n", strerror(-ret));
      return nullptr;
    }
  }

  if (options.dfsan) {
    if (IsVerbose())
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

}
