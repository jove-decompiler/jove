#include "tool.h"
#include <stdexcept>
#include <fstream>
#include <llvm/Support/WithColor.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/raw_ostream.h>
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/bitset.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/graph/adj_list_serialize.hpp>

#include <fcntl.h>
#include <signal.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sched.h>

namespace jove {

//
// AllTools must be constructed before any global instances of
// AutoRegisterTool, so tool.o should come first on the command-line when
// linking jove.
//
static std::vector<std::pair<const char *, jove::ToolCreationProc>> AllTools;

void RegisterTool(const char *name, ToolCreationProc proc) {
  AllTools.emplace_back(name, proc);
}

}

using llvm::WithColor;

int main(int argc, char **argv) {
  auto usage = [&](void) -> std::string {
    std::string res =
"jove " JOVE_VERSION " multi-call binary." "\n"
"\n"
"Usage: jove [tool [arguments]...]"        "\n"
"   or: tool [arguments]..."               "\n"
                                           "\n"
"Currently defined tools:"                 "\n"
"       ";

    for (const auto &x : jove::AllTools) {
      res.push_back(' ');
      res.append(x.first);
    }
    res.push_back('\n');

    return res;
  };

  //
  // scan for '--' on the command-line, and if found, collect trailing arguments
  //
  std::vector<char *> dashdash_args;
  std::vector<char *> __argv;
  for (unsigned i = 0; i < argc; ++i) {
    if (strcmp(argv[i], "--") == 0) {
      for (unsigned j = i + 1; j < argc; ++j)
        dashdash_args.push_back(argv[j]);

      //
      // shuffle argc/argv
      //
      __argv.reserve(argc);
      for (unsigned j = 0; j < i; ++j)
        __argv.push_back(argv[j]);
      __argv.push_back(nullptr);

      argc = i;
      argv = &__argv[0];
      break;
    }
  }

  //
  // examine argv[0]
  //
  const char *name = nullptr;
  std::unique_ptr<jove::Tool> tool;

  std::string prefix("jove-");
  std::string arg0 = argv[0];

  //
  // is it a path?
  //
  {
    std::string::size_type slash = arg0.rfind('/');
    if (slash != std::string::npos)
      arg0 = arg0.substr(slash + 1); /* chop off leading directories */
  }

  //
  // does it start with 'jove-'?
  //
  bool has_prefix = arg0.rfind(prefix, 0) == 0;
  if (has_prefix)
    arg0 = arg0.substr(prefix.size()); /* chop off prefix */

  //
  // is the multi-call binary being invoked?
  //
  std::vector<char *> _argv;
  if (arg0 == "jove") {
    //
    // interpret first argument as tool to call
    //
    if (argc < 2) {
      llvm::errs() << usage();
      return 1;
    }

    std::string tool_name(argv[1]);

    //
    // search tools
    //
    for (const auto &x : jove::AllTools) {
      if (x.first == tool_name) {
        name = x.first;
        tool.reset(x.second()); /* instantiate */
        goto found_tool;
      }
    }

    llvm::errs() << llvm::formatv("unknown tool '{0}'\n{1}", tool_name, usage());
    return 1;

found_tool:
    //
    // shuffle argc/argv
    //
    _argv.reserve(argc);
    _argv.push_back(argv[0]);
    for (unsigned i = 2; i < argc; ++i)
      _argv.push_back(argv[i]);
    _argv.push_back(nullptr);

    argc = argc - 1;
    argv = &_argv[0];
  } else {
    //
    // search tools
    //
    for (const auto &x : jove::AllTools) {
      if (x.first == arg0) {
        name = x.first;
        tool.reset(x.second()); /* instantiate */
        break;
      }
    }
  }

  if (!tool) {
    llvm::errs() << usage();
    return 1;
  }

  assert(name);
  assert(tool);

  tool->set_dashdash_args(dashdash_args);

  llvm::InitLLVM X(argc, argv);

  //
  // select tool
  //
  llvm::cl::HideUnrelatedOptions({&tool->JoveCategory, &llvm::ColorCategory});
  llvm::cl::AddExtraVersionPrinter([](llvm::raw_ostream &OS) -> void {
    OS << "jove version " JOVE_VERSION "\n";
  });
  std::string Desc = (std::string("jove-") + name) + "\n";
  llvm::cl::ParseCommandLineOptions(argc, argv, Desc);

  int res = tool->Run();

  return res;
}

namespace jove {

Tool::Tool()
    : HumanOutputStreamPtr(&llvm::errs()),
      JoveCategory("Specific Options") {}

Tool::~Tool() {}

void Tool::HumanOutToFile(const std::string &path) {
  std::error_code EC;
  HumanOutputFileStream.reset(
      new llvm::raw_fd_ostream(path, EC, llvm::sys::fs::OF_Text));

  if (EC) {
    throw std::runtime_error("HumanOutToFile: failed to open file");
  }

  HumanOutputStreamPtr = HumanOutputFileStream.get();
}

int Tool::WaitForProcessToExit(pid_t pid, bool verbose) {
  int wstatus;
  do {
    if (::waitpid(pid, &wstatus, WUNTRACED | WCONTINUED) < 0) {
      int err = errno;
      if (err == EINTR)
        continue;
      if (err == ECHILD)
        break;

      HumanOut() << llvm::formatv("waitpid failed: {0}\n", strerror(err));
      break;
    }

    if (WIFEXITED(wstatus)) {
      if (verbose)
        HumanOut() << llvm::formatv("child exited ({0})\n",
                                    WEXITSTATUS(wstatus));
      return WEXITSTATUS(wstatus);
    } else if (WIFSIGNALED(wstatus)) {
      if (verbose)
        HumanOut() << llvm::formatv("child killed by signal {0}\n",
                                    WTERMSIG(wstatus));
      break;
    } else if (WIFSTOPPED(wstatus)) {
      if (verbose)
        HumanOut() << llvm::formatv("child stopped by signal {0}\n",
                                    WSTOPSIG(wstatus));
      break;
    } else if (WIFCONTINUED(wstatus)) {
      if (verbose)
        HumanOut() << "child continued\n";
    }
  } while (!WIFEXITED(wstatus) && !WIFSIGNALED(wstatus));

  return 1;
}

unsigned Tool::num_cpus(void) {
  cpu_set_t cpu_mask;
  if (sched_getaffinity(0, sizeof(cpu_mask), &cpu_mask) < 0) {
    int err = errno;
    throw std::runtime_error(std::string("sched_getaffinity failed: ") + strerror(err));
  }

  return CPU_COUNT(&cpu_mask);
}

void Tool::IgnoreCtrlC(void) {
  struct sigaction sa;

  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
#if 0
  sa.sa_handler = [](int) -> void {};
#else
  sa.sa_handler = SIG_IGN;
#endif

  if (::sigaction(SIGINT, &sa, nullptr) < 0) {
    int err = errno;
    HumanOut() << llvm::formatv("sigaction failed: {0}\n", strerror(err));
  }
}

void Tool::print_command(const char **c_str_arr) {
  for (const char **p = c_str_arr; *p; ++p) {
    HumanOut() << *p << ' ';
  }

  HumanOut() << '\n';
}

void Tool::exec_tool(const char *name,
                     const std::vector<const char *> &_arg_vec,
                     const char **envp) {
  std::vector<const char *> arg_vec(_arg_vec);
  arg_vec.insert(arg_vec.begin(), name);
  arg_vec.push_back(nullptr);

  ::execve("/proc/self/exe",
           const_cast<char **>(&arg_vec[0]),
           envp ? const_cast<char **>(envp) : ::environ);
}

void Tool::ReadDecompilationFromFile(const std::string &path,
                                     decompilation_t &out) {
  std::ifstream ifs(path);
  if (!ifs.is_open())
    throw std::runtime_error("ReadDecompilationFromFile: failed to open " + path);

  boost::archive::text_iarchive ia(ifs);
  ia >> out;
}

void Tool::WriteDecompilationToFile(const std::string &path,
                                    const decompilation_t &in) {
  assert(!path.empty());

  std::string tmp_fp(path);
  tmp_fp.append(".XXXXXX");

  int fd = mkstemp(&tmp_fp[0]);
  if (fd < 0) {
    int err = errno;
    throw std::runtime_error(
        "WriteDecompilationToFile: failed to make temporary file: " +
        std::string(strerror(err)));
  } else {
    if (::fchmod(fd, 0666) < 0) {
      int err = errno;
      throw std::runtime_error(
          "WriteDecompilationToFile: changing permissions of temporary file failed: " +
          std::string(strerror(err)));
    }

    if (::close(fd) < 0) {
      int err = errno;
      throw std::runtime_error(
          "WriteDecompilationToFile: closing temporary file failed: " +
          std::string(strerror(err)));
    }
  }

  {
    std::ofstream ofs(tmp_fp);
    if (!ofs.is_open())
      throw std::runtime_error(
          "WriteDecompilationToFile: failed to open temporary file " + tmp_fp);

    boost::archive::text_oarchive oa(ofs);
    oa << in;
  }

  if (::rename(tmp_fp.c_str(), path.c_str()) < 0) { /* atomically replace */
    int err = errno;
    throw std::runtime_error("WriteDecompilationToFile: failed to rename " +
                             tmp_fp + " to " + path + ": " +
                             std::string(strerror(err)));
  }
}

template <bool IsRead>
static ssize_t robust_read_or_write(int fd, void *const buf, const size_t count) {
  uint8_t *const _buf = (uint8_t *)buf;

  unsigned n = 0;
  do {
    unsigned left = count - n;

    ssize_t ret = IsRead ? ::read(fd, &_buf[n], left) :
                          ::write(fd, &_buf[n], left);

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

ssize_t Tool::robust_read(int fd, void *const buf, const size_t count) {
  return robust_read_or_write<true /* r */>(fd, buf, count);
}

ssize_t Tool::robust_write(int fd, const void *const buf, const size_t count) {
  return robust_read_or_write<false /* w */>(fd, const_cast<void *>(buf), count);
}

uint32_t Tool::size_of_file32(const char *path) {
  uint32_t res;
  {
    struct stat st;
    if (::stat(path, &st) < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv("stat failed: {0}\n", strerror(err));
      return 0;
    }

    res = st.st_size;
  }

  return res;
}

ssize_t Tool::robust_sendfile(int socket, const char *file_path, size_t file_size) {
  int fd = ::open(file_path, O_RDONLY);

  if (fd < 0)
    return -errno;

  struct closeme_t {
    int fd;
    closeme_t (int fd) : fd(fd) {}
    ~closeme_t() { ::close(fd); }
  } closeme(fd);

  const size_t saved_file_size = file_size;

  do {
    ssize_t ret = ::sendfile(socket, fd, nullptr, file_size);

    if (ret == 0)
      return -EIO;

    if (ret < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv("sendfile failed: {0}\n",
                                          strerror(err));
      return -err;
    }

    file_size -= ret;
  } while (file_size != 0);

  return saved_file_size;
}

// TODO refactor
ssize_t Tool::robust_sendfile_with_size(int socket, const char *file_path) {
  ssize_t ret;

  uint32_t file_size = size_of_file32(file_path);

  std::string file_size_str = std::to_string(file_size);

  ret = robust_write(socket, file_size_str.c_str(), file_size_str.size() + 1);
  if (ret < 0)
    return ret;

  ret = robust_sendfile(socket, file_path, file_size);
  if (ret < 0)
    return ret;

  return file_size;
}

ssize_t Tool::robust_receive_file_with_size(int socket, const char *out, unsigned file_perm) {
  uint32_t file_size;
  {
    std::string file_size_str;

    char ch;
    do {
      ssize_t n = robust_read(socket, &ch, sizeof(char));
      if (n < 0)
        return n;

      assert(n == sizeof(char));

      file_size_str.push_back(ch);
    } while (ch != '\0');

    file_size = std::atoi(file_size_str.c_str());
  }
  assert(file_size > 0);

  std::vector<uint8_t> buff;
  buff.resize(file_size);

  {
    ssize_t res = robust_read(socket, &buff[0], buff.size());
    if (res < 0)
      return res;
  }

  ssize_t res = -EBADF;
  {
    int fd = ::open(out, O_WRONLY | O_TRUNC | O_CREAT, file_perm);
    if (fd < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv("failed to receive file {0}: {1}\n",
                                          out, strerror(err));
      return -err;
    }

    res = robust_write(fd, &buff[0], buff.size());

    if (::close(fd) < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv("failed to close received file {0}: {1}\n",
                                          out, strerror(err));
      return -err;
    }
  }

  return res;
}

}
