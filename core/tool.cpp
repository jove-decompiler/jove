#include "tool.h"
#include "crypto.h"

#include <stdexcept>
#include <fstream>

#include <llvm/Support/WithColor.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/raw_ostream.h>

#include <pwd.h>

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

  if (EC)
    throw std::runtime_error("HumanOutToFile: failed to open \"" + path + "\"");

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

std::string Tool::home_dir(void) {
  errno = 0;
  const char *homedir = getpwuid(getuid())->pw_dir;
  if (int err = errno)
    throw std::runtime_error(std::string("home_dir: getpwuid failed: ") +
                             strerror(err));

  assert(homedir);
  return homedir;
}

std::string Tool::jove_dir(void) {
  return home_dir() + "/.jove";
}

std::string Tool::path_to_jv(const char *exe_path) {
  std::vector<uint8_t> exe_bytes;
  read_file_into_vector(exe_path, exe_bytes);

  return jove_dir() + "/" + crypto::sha3(&exe_bytes[0], exe_bytes.size()) +
         ".jv";
}

std::string Tool::path_to_sysroot(const char *exe_path, bool ForeignLibs) {
  std::vector<uint8_t> exe_bytes;
  read_file_into_vector(exe_path, exe_bytes);

  std::string res = jove_dir() + "/" +
                    crypto::sha3(&exe_bytes[0], exe_bytes.size()) + ".sysroot";
  if (ForeignLibs)
    res.append(".x");

  return res;
}

}
