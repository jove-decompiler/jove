#include "tool.h"
#include "serialize.h"
#include "B.h"
#include "analyze.h"
#include "tcg.h"
#include "recompile.h"

#ifndef JOVE_NO_BACKEND

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

  tiny_code_generator_t TCG;

public:
  ServerTool() : opts(JoveCategory) {}

  int Run(void) override;

  void *ConnectionProc(void *);
};

JOVE_REGISTER_TOOL("server", ServerTool);

static std::string string_of_sockaddr(const struct sockaddr *addr, socklen_t addrlen);

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
  //
  // Create TCP socket
  //
  int connection_socket = ::socket(AF_INET, SOCK_STREAM, 0);
  if (connection_socket < 0) {
    int err = errno;
    WithColor::error() << llvm::formatv("socket failed: {0}\n", strerror(err));
    return 1;
  }

  //
  // Set SO_REUSEADDR option
  //
  int opt = 1;
  if (::setsockopt(connection_socket, SOL_SOCKET, SO_REUSEADDR, &opt,
                   sizeof(opt)) < 0) {
    int err = errno;
    WithColor::error() << llvm::formatv("setsockopt failed: {0}\n",
                                        strerror(err));
    return 1;
  }

  {
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(opts.Port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    int ret = ::bind(connection_socket,
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

    int ret = ::listen(connection_socket, BACKLOG);
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

    int data_socket = ::accept(connection_socket, (struct sockaddr *)&args->addr, &args->addrlen);
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
  uint16_t header;
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
    bool DFSan, ForeignLibs, Trace, Optimize, SkipCopyRelocHack, DebugSjlj, ABICalls, RuntimeMT, CallStack, LayOutSections, MT, MinSize;
  } options;

  std::bitset<16> headerBits(header);

  options.DFSan             = headerBits.test(0);
  options.ForeignLibs       = headerBits.test(1);
  options.Trace             = headerBits.test(2);
  options.Optimize          = headerBits.test(3);
  options.SkipCopyRelocHack = headerBits.test(4);
  options.DebugSjlj         = headerBits.test(5);
  options.ABICalls          = headerBits.test(6);
  options.RuntimeMT         = headerBits.test(7);
  options.CallStack         = headerBits.test(8);
  options.LayOutSections    = headerBits.test(9);
  options.MT                = headerBits.test(10);
  options.MinSize           = headerBits.test(11);

  std::string jv_s_path = (TemporaryDir / "serialized.jv").string();
  std::string tmpjv = (TemporaryDir / ".jv").string();

  if (IsVerbose())
    llvm::errs() << llvm::formatv("receiving {0}...\n", jv_s_path);

  {
    ssize_t ret =
        robust_receive_file_with_size(data_socket, jv_s_path.c_str(), 0666);
    if (ret < 0) {
      WithColor::error()
          << llvm::formatv("failed to receive file {0} from remote: {1}\n",
                           jv_s_path.c_str(), strerror(-ret));
      return nullptr;
    }
  }

  if (IsVerbose())
    llvm::errs() << llvm::formatv("received {0}.\n", jv_s_path);

  jv_file_t jv_file(boost::interprocess::create_only, tmpjv.c_str(),
                    jvDefaultInitialSize() /* FIXME */);

  if (IsVerbose())
    WithColor::note() << llvm::formatv("{0}\n", tmpjv);

  BOOST_SCOPE_DEFER [&] {
    if (ShouldDeleteTemporaryFiles())
      boost::interprocess::file_mapping::remove(tmpjv.c_str());
  };

  boost::concurrent_flat_set<dynamic_target_t> inflight;
  std::atomic<uint64_t> done = 0;

  analyzer_options_t analyzer_opts;
  analyzer_opts.VerbosityLevel = VerbosityLevel();
  //analyzer_opts.Conservative = opts.Conservative;

  recompiler_options_t recompiler_opts;

#define PROPOGATE_OPTION(name)                                                 \
  do {                                                                         \
    recompiler_opts.name = options.name;                                       \
  } while (false)

  PROPOGATE_OPTION(DFSan);
  PROPOGATE_OPTION(ForeignLibs);
  PROPOGATE_OPTION(Trace);
  PROPOGATE_OPTION(Optimize);
  PROPOGATE_OPTION(SkipCopyRelocHack);
  PROPOGATE_OPTION(DebugSjlj);
  PROPOGATE_OPTION(ABICalls);
  PROPOGATE_OPTION(RuntimeMT);
  PROPOGATE_OPTION(CallStack);
  PROPOGATE_OPTION(LayOutSections);

  recompiler_opts.temp_dir = temporary_dir();

  const std::string sysroot_dir = (TemporaryDir / "sysroot").string();
  recompiler_opts.Output = sysroot_dir;

  bool DidRun = false;

  auto run = [&]<bool MT, bool MinSize>(void) -> void {
    assert(!DidRun);
    DidRun = true;

    bool IsCOFF = false;

    using jv_t_1 = jv_base_t<MT, MinSize>;
    ip_unique_ptr<jv_t_1> jv1 = boost::interprocess::make_managed_unique_ptr(
        jv_file.construct<jv_t_1>(boost::interprocess::anonymous_instance)(
            jv_file),
        jv_file);
    {
    auto &jv = *jv1;
    UnserializeJVFromFile(jv, jv_file, jv_s_path.c_str());
    }

    using jv_t_2 = jv_base_t<AreWeMT, MinSize>;
    ip_unique_ptr<jv_t_2> jv2 = boost::interprocess::make_managed_unique_ptr(
        jv_file.construct<jv_t_2>(boost::interprocess::anonymous_instance)(
            std::move(*jv1), jv_file),
        jv_file);
    jv1.release();
    {
    auto &jv = *jv2;

    IsCOFF = ({
      auto Bin = B::Create(jv.Binaries.at(0).data());
      B::is_coff(*Bin);
    });

    llvm::LLVMContext Context;

    int rc = ({
    analyzer_t analyzer(analyzer_opts, TCG, Context, jv, inflight, done);

    analyzer.update_callers();
    analyzer.update_parents();
    analyzer.identify_ABIs();
    analyzer.identify_Sjs();

    (int)(analyzer.analyze_blocks() || analyzer.analyze_functions());
    });

    if (rc)
      throw std::runtime_error("jove analyze failed!");

    fs::create_directory(sysroot_dir);

    rc = ({
    recompiler_t recompiler(jv, recompiler_opts, TCG, Context, locator());
    recompiler.go();
    });

    if (rc)
      throw std::runtime_error("jove recompile failed!");
    }

    using jv_t_3 = jv_t_1;
    ip_unique_ptr<jv_t_3> jv3 = boost::interprocess::make_managed_unique_ptr(
        jv_file.construct<jv_t_3>(boost::interprocess::anonymous_instance)(
            std::move(*jv2), jv_file),
        jv_file);
    jv2.release();
    {
      auto &jv = *jv3;

      SerializeJVToFile(jv, jv_file, jv_s_path.c_str(), true /* text */);

      {
        //
        // send new jv
        //
        ssize_t ret = robust_sendfile_with_size(data_socket, jv_s_path.c_str());
        if (ret < 0)
          throw std::runtime_error(
              std::string("robust_sendfile_with_size failed: ") +
              strerror(-ret));
      }

      //
      // send the rest of the DSO's that were recompiled
      //
      for (const auto &binary : jv.Binaries) {
        if (binary.IsVDSO)
          continue;
        if (binary.IsDynamicLinker)
          continue;
        if (!binary.is_file())
          continue;

        fs::path chrooted_path(fs::path(sysroot_dir) / binary.path_str());
        if (!fs::exists(chrooted_path))
          throw std::runtime_error(chrooted_path.string() + " not found");

        if (IsVerbose())
          llvm::errs() << llvm::formatv("sending {0}\n", chrooted_path.c_str());

        ssize_t ret =
            robust_sendfile_with_size(data_socket, chrooted_path.c_str());

        if (ret < 0)
          throw std::runtime_error(
              std::string("robust_sendfile_with_size failed: ") +
              strerror(-ret));
      }

      {
        if (IsVerbose())
          llvm::errs() << "sending jove runtime\n";

        ssize_t ret = robust_sendfile_with_size(
            data_socket, IsCOFF
                             ? locator().runtime_dll(options.RuntimeMT).c_str()
                             : locator().runtime_so(options.RuntimeMT).c_str());

        if (ret < 0)
          throw std::runtime_error(
              std::string("robust_sendfile_with_size failed: ") +
              strerror(-ret));
      }

      if (options.DFSan) {
        if (IsVerbose())
          llvm::errs() << "sending jove dfsan runtime\n";

        ssize_t ret = robust_sendfile_with_size(
            data_socket, locator().dfsan_runtime().c_str());

        if (ret < 0)
          throw std::runtime_error(
              std::string("robust_sendfile_with_size failed: ") +
              strerror(-ret));
      }
    }

    jv3.release();
  };

#define MT_POSSIBILTIES                                                        \
    ((true))                                                                   \
    ((false))
#define MINSIZE_POSSIBILTIES                                                   \
    ((true))                                                                   \
    ((false))

#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)

#define DO_JV_CASE(r, product)                                                 \
  if (options.MT == GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)) &&                \
      options.MinSize == GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))) {           \
    run.template operator()<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),          \
                            GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))>();       \
  }

  BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_JV_CASE, (MT_POSSIBILTIES)(MINSIZE_POSSIBILTIES))

  assert(DidRun);

  return nullptr;
}

}
#endif /* JOVE_NO_BACKEND */
