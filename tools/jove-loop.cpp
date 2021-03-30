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
#include <sys/sendfile.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/mman.h>

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

static cl::opt<std::string> jv("decompilation", cl::desc("Jove decompilation"),
                               cl::Required, cl::value_desc("filename"),
                               cl::cat(JoveCategory));

static cl::alias jvAlias("d", cl::desc("Alias for -decompilation."),
                         cl::aliasopt(jv), cl::cat(JoveCategory));

static cl::opt<std::string> sysroot("sysroot", cl::desc("Output directory"),
                                    cl::Required, cl::cat(JoveCategory));

static cl::opt<bool> DFSan("dfsan", cl::desc("Run dfsan on bitcode"),
                           cl::cat(JoveCategory));

static cl::opt<bool>
    ForceRecompile("force-recompile",
                   cl::desc("Skip running the prog the first time"),
                   cl::cat(JoveCategory));

static cl::opt<bool> JustRun("just-run",
                             cl::desc("Just run, nothing else"),
                             cl::cat(JoveCategory));

static cl::opt<std::string>
    UseLd("use-ld",
          cl::desc("Force using particular linker (lld,bfd,gold)"),
          cl::cat(JoveCategory));

static cl::opt<bool>
    Trace("trace",
          cl::desc("Instrument code to output basic block execution trace"),
          cl::cat(JoveCategory));

static cl::opt<bool> Verbose("verbose",
                             cl::desc("Output helpful messages for debugging"),
                             cl::cat(JoveCategory));

static cl::alias VerboseAlias("v", cl::desc("Alias for --verbose."),
                              cl::aliasopt(Verbose), cl::cat(JoveCategory));

static cl::opt<std::string> Connect("connect",
                                    cl::desc("Offload work to remote server"),
                                    cl::value_desc("ip address:port"),
                                    cl::cat(JoveCategory));

static cl::alias ConnectAlias("c", cl::desc("Alias for -connect."),
                              cl::aliasopt(Connect), cl::cat(JoveCategory));

} // namespace opts

namespace jove {

static int loop(void);

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
  cl::ParseCommandLineOptions(_argc, _argv, "Jove Loop\n");

  return jove::loop();
}

namespace jove {

static fs::path jove_recompile_path, jove_run_path, jove_analyze_path;

static int await_process_completion(pid_t);

static void IgnoreCtrlC(void);

static void print_command(const char **argv);

static std::atomic<bool> Cancelled(false);

static std::atomic<pid_t> app_pid;

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
    const int fd;
    closeme_t(int fd) : fd(fd) {}
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

static ssize_t robust_receive_file_with_size(int data_socket, const char *out, unsigned file_perm) {
  uint32_t file_size;
  {
    ssize_t ret = robust_read(data_socket, &file_size, sizeof(uint32_t));
    if (ret < 0)
      return ret;
  }

  std::vector<uint8_t> buff;
  buff.resize(file_size);

  {
    ssize_t ret = robust_read(data_socket, &buff[0], buff.size());
    if (ret < 0)
      return ret;
  }

  ssize_t res;
  {
    int fd = open(out, O_WRONLY | O_TRUNC | O_CREAT, file_perm);
    if (fd < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv("open of \"{0}\" failed ({1})\n", out,
                                          strerror(err));
      return -err;
    }

    res = robust_write(fd, &buff[0], buff.size());

    if (close(fd) < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv("close failed ({1})\n",
                                          strerror(err));
      return -err;
    }
  }

  return res;
}

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


int loop(void) {
  //
  // install signal handler for Ctrl-C to gracefully cancel
  //
  {
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = sighandler;

    if (sigaction(SIGINT, &sa, nullptr) < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv("{0}: sigaction failed ({1})\n",
                                          __func__, strerror(err));
    }
  }

  {
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = sighandler;

    if (sigaction(SIGTERM, &sa, nullptr) < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv("{0}: sigaction failed ({1})\n",
                                          __func__, strerror(err));
    }
  }

  if (!fs::exists(opts::sysroot))
    fs::create_directory(opts::sysroot);

  if (!fs::exists(opts::sysroot) || !fs::is_directory(opts::sysroot)) {
    WithColor::error() << llvm::formatv(
        "provided sysroot {0} is not directory\n", opts::sysroot);
    return 1;
  }

  jove_recompile_path = (boost::dll::program_location().parent_path() /
                         std::string("jove-recompile"))
                            .string();
  if (!fs::exists(jove_recompile_path)) {
    WithColor::error() << llvm::formatv(
        "could not find jove-recompile at {0}\n", jove_recompile_path.c_str());

    return 1;
  }

  jove_run_path =
      (boost::dll::program_location().parent_path() / std::string("jove-run"))
          .string();
  if (!fs::exists(jove_run_path)) {
    WithColor::error() << llvm::formatv(
        "could not find jove-run at {0}\n", jove_run_path.c_str());

    return 1;
  }

  jove_analyze_path = (boost::dll::program_location().parent_path() /
                       std::string("jove-analyze"))
                          .string();
  if (!fs::exists(jove_analyze_path)) {
    WithColor::error() << llvm::formatv(
        "could not find jove-analyze at {0}\n", jove_analyze_path.c_str());

    return 1;
  }

  if (!opts::Connect.empty() && opts::Connect.find(':') == std::string::npos) {
    WithColor::error() << "usage: --connect IPADDRESS:PORT\n";
  }

  std::string jv_path(fs::is_directory(opts::jv)
                        ? (fs::path(opts::jv) / "decompilation.jv").string()
                        : opts::jv);

  decompilation_t decompilation;
  {
    std::ifstream ifs(jv_path.c_str());

    boost::archive::text_iarchive ia(ifs);
    ia >> decompilation;
  }

  while (!Cancelled) {
    pid_t pid;

    if (opts::ForceRecompile) {
      opts::ForceRecompile = false; /* XXX just the first time */
      goto skip_run;
    }

    {
      fs::path chrooted_path(opts::sysroot);
      chrooted_path /= opts::Prog;

      if (!fs::exists(chrooted_path)) {
        WithColor::note() << llvm::formatv(
            "{0} does not exist; recompiling...\n", chrooted_path.c_str());
        goto skip_run;
      }
    }

    //
    // run
    //
run:
    {
      int pipefd[2];
      if (pipe(pipefd) < 0) {
        int err = errno;
        WithColor::error() << llvm::formatv("pipe failed: {0}\n", strerror(err));
        return 1;
      }

      int rdFd = pipefd[0];
      int wrFd = pipefd[1];

      pid = fork();
      if (!pid) {
        if (close(rdFd) < 0) {
          int err = errno;
          WithColor::error() << llvm::formatv("failed to close rdFd: {0}\n",
                                              strerror(err));
        }
        std::string wrFdStr = std::to_string(wrFd);

        std::vector<const char *> arg_vec = {
            jove_run_path.c_str(),

            "--pipefd",
            wrFdStr.c_str(),

            "--sysroot",
            opts::sysroot.c_str(),
        };

        std::string env_arg;

        if (!opts::Envs.empty()) {
          for (std::string &s : opts::Envs) {
            env_arg.append(s);
            env_arg.push_back(',');
          }
          env_arg.resize(env_arg.size() - 1);

          arg_vec.push_back("--env");
          arg_vec.push_back(env_arg.c_str());
        }

        //
        // program + args
        //
        arg_vec.push_back(opts::Prog.c_str());
        if (!opts::Args.empty())
          arg_vec.push_back("--");
        for (std::string &s : opts::Args)
          arg_vec.push_back(s.c_str());

        arg_vec.push_back(nullptr);

        print_command(&arg_vec[0]);
        execve(arg_vec[0], const_cast<char **>(&arg_vec[0]), ::environ);

        int err = errno;
        WithColor::error() << llvm::formatv("execve failed: {0}\n",
                                            strerror(err));
        return 1;
      }

      if (close(wrFd) < 0) {
        int err = errno;
        WithColor::error() << llvm::formatv("failed to close wrFd: {0}\n",
                                            strerror(err));
      }

      //
      // read app pid from pipe
      //
      {
        uint64_t uint64;

        ssize_t ret;
        do
          ret = read(rdFd, &uint64, sizeof(uint64));
        while (ret < 0 && errno == EINTR);

        if (ret != sizeof(uint64)) {
          WithColor::warning() << llvm::formatv(
              "failed to read pid from pipe: got {0}\n", ret);
        } else {
          app_pid.store(uint64);
        }
      }

      if (close(rdFd) < 0) {
        int err = errno;
        WithColor::error() << llvm::formatv("failed to close rdFd: {0}\n",
                                            strerror(err));
      }

      {
        int ret = await_process_completion(pid);

        //
        // XXX currently the only way to know that jove-recover was run is by
        // looking at the exit status
        //
        if (ret != 'b' &&
            ret != 'f' &&
            ret != 'F' &&
            ret != 'r')
          break;
      }

      app_pid.store(0); /* reset */
    }

    if (opts::JustRun)
      break;

skip_run:
    if (!opts::Connect.empty()) { /* remote */
      //
      // connect to jove-server
      //
      int remote_fd = socket(AF_INET, SOCK_STREAM, 0);
      if (remote_fd < 0) {
        int err = errno;
        WithColor::error() << llvm::formatv("socket failed: {0}\n", strerror(err));
        return 1;
      }

      struct closeme_t {
        const int fd;
        closeme_t(int fd) : fd(fd) {}
        ~closeme_t() { close(fd); }
      } closeme(remote_fd);

      std::string addr_str;

      unsigned port = 0;
      {
        auto colon_idx = opts::Connect.find(':');
        assert(colon_idx != std::string::npos);
        std::string port_s = opts::Connect.substr(colon_idx + 1, std::string::npos);
        if (opts::Verbose)
          llvm::errs() << llvm::formatv("parsed port as {0}\n", port_s);
        port = atoi(port_s.c_str());

        addr_str = opts::Connect.substr(0, colon_idx);
      }

      struct sockaddr_in server_addr;

      server_addr.sin_family = AF_INET;
      server_addr.sin_port = htons(port);
      server_addr.sin_addr.s_addr = inet_addr(addr_str.c_str());

      int connect_ret;
      llvm::errs() << llvm::formatv("connecting to remote {0}...\n", opts::Connect);
      connect_ret = connect(remote_fd,
                            reinterpret_cast<struct sockaddr *>(&server_addr),
                            sizeof(sockaddr_in));
      if (connect_ret < 0 && errno != EINPROGRESS) {
        int err = errno;
        WithColor::warning() << llvm::formatv("connect failed: {0}\n", strerror(err));
        return 1;
      }

      //
      // send magic bytes
      //
      {
        char magic[4] = {'J', 'O', 'V', 'E'};

        ssize_t ret = robust_write(remote_fd, &magic[0], sizeof(magic));

        if (ret < 0) {
          if (opts::Verbose)
            WithColor::error() << llvm::formatv(
                "failed to send magic bytes: {0}\n", strerror(-ret));
          break;
        }
      }

      //
      // send header
      //
      {
        uint8_t header = opts::DFSan;
        ssize_t ret = robust_write(remote_fd, &header, sizeof(header));

        if (ret < 0) {
          if (opts::Verbose)
            WithColor::error() << llvm::formatv(
                "failed to send header to remote: {0}\n", strerror(-ret));

          break;
        }
      }

      //
      // send the jv
      //
      {
        ssize_t ret = robust_sendfile_with_size(remote_fd, jv_path.c_str());

        if (ret < 0) {
          if (opts::Verbose)
            WithColor::error() << llvm::formatv(
                "failed to send decompilation: {0}\n", strerror(-ret));

          break;
        }
      }

      //
      // ... the remote analyzes and recompiles and sends us a new jv
      //
      if (!robust_receive_file_with_size(remote_fd, jv_path.c_str(), 0666)) {
        if (opts::Verbose)
          WithColor::error() << "failed to receive decompilation from remote\n";
        break;
      }

      for (const binary_t &binary : decompilation.Binaries) {
        if (binary.IsVDSO)
          continue;
        if (binary.IsDynamicLinker)
          continue;

        fs::path chrooted_path(fs::path(opts::sysroot) / binary.Path);

        if (!robust_receive_file_with_size(remote_fd, chrooted_path.c_str(), 0777)) {
          if (opts::Verbose)
            WithColor::error()
                << llvm::formatv("failed to receive file {0} from remote\n",
                                 chrooted_path.c_str());
          return 1;
        }
      }
    } else { /* local */
      //
      // analyze
      //
      pid = fork();
      if (!pid) {
        const char *arg_arr[] = {
            jove_analyze_path.c_str(),

            "-d", opts::jv.c_str(),

            nullptr
        };

        print_command(&arg_arr[0]);
        execve(arg_arr[0], const_cast<char **>(&arg_arr[0]), ::environ);

        int err = errno;
        WithColor::error() << llvm::formatv("execve failed: {0}\n",
                                            strerror(err));
        return 1;
      }

      if (int ret = await_process_completion(pid)) {
        WithColor::error() << llvm::formatv("jove-analyze failed [{0}]\n", ret);
        return ret;
      }

      //
      // recompile
      //
      pid = fork();
      if (!pid) {
        std::vector<const char *> arg_vec = {
            jove_recompile_path.c_str(),

            "-d", opts::jv.c_str(),
            "-o", opts::sysroot.c_str(),
        };

        std::string use_ld_arg;
        if (!opts::UseLd.empty()) {
          use_ld_arg = "--use-ld=" + opts::UseLd;
          arg_vec.push_back(use_ld_arg.c_str());
        }

        if (opts::DFSan)
          arg_vec.push_back("--dfsan");

        if (opts::Trace)
          arg_vec.push_back("--trace");

        arg_vec.push_back(nullptr);

        print_command(&arg_vec[0]);
        execve(arg_vec[0], const_cast<char **>(&arg_vec[0]), ::environ);

        int err = errno;
        WithColor::error() << llvm::formatv("execve failed: {0}\n",
                                            strerror(err));
        return 1;
      }

      if (int ret = await_process_completion(pid)) {
        WithColor::error() << llvm::formatv("jove-recompile failed [{0}]\n", ret);
        return ret;
      }
    }
  }

  return 0;
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
