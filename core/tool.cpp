#include "tool.h"
#include <stdexcept>
#include <fstream>
#include <signal.h>
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
  std::string usage =
"jove " JOVE_VERSION " multi-call binary." "\n"
"\n"
"Usage: jove [tool [arguments]...]"        "\n"
"   or: tool [arguments]..."               "\n"
                                           "\n"
"Currently defined tools:"                 "\n"
"       ";

  for (const auto &x : jove::AllTools) {
    usage.push_back(' ');
    usage.append(x.first);
  }
  usage.push_back('\n');

  //
  // scan for '--' on the command-line
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
  jove::Tool *tool = nullptr;

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
      llvm::errs() << usage;
      return 1;
    }

    std::string tool_name(argv[1]);

    //
    // search tools
    //
    for (const auto &x : jove::AllTools) {
      if (x.first == tool_name) {
        name = x.first;
        tool = x.second(); /* instantiate */
        goto found_tool;
      }
    }

    llvm::errs() << llvm::formatv("unknown tool '{0}'\n{1}", tool_name, usage);
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
        tool = x.second(); /* instantiate */
        break;
      }
    }
  }

  if (!tool) {
    llvm::errs() << usage;
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

  return tool->Run();
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

int Tool::WaitForProcessToExit(pid_t pid) {
  int wstatus;
  do {
    if (::waitpid(pid, &wstatus, WUNTRACED | WCONTINUED) < 0)
      abort();

    if (WIFEXITED(wstatus)) {
      // printf("exited, status=%d\n", WEXITSTATUS(wstatus));
      return WEXITSTATUS(wstatus);
    } else if (WIFSIGNALED(wstatus)) {
      // printf("killed by signal %d\n", WTERMSIG(wstatus));
      return 1;
    } else if (WIFSTOPPED(wstatus)) {
      // printf("stopped by signal %d\n", WSTOPSIG(wstatus));
      return 1;
    } else if (WIFCONTINUED(wstatus)) {
      // printf("continued\n");
    }
  } while (!WIFEXITED(wstatus) && !WIFSIGNALED(wstatus));

  abort();
}

void Tool::IgnoreCtrlC(void) {
  struct sigaction sa;

  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = [](int) -> void {};

  if (sigaction(SIGINT, &sa, nullptr) < 0) {
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

void Tool::ReadDecompilationFromFile(const std::string &path,
                                     decompilation_t &out) {
  std::ifstream ifs(path);

  boost::archive::text_iarchive ia(ifs);
  ia >> out;
}

void Tool::WriteDecompilationToFile(const std::string &path,
                                    const decompilation_t &in) {
  std::ofstream ofs(path);

  boost::archive::text_oarchive oa(ofs);
  oa << in;
}

}
