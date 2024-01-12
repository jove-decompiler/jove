#include "tool.h"
#include "crypto.h"

#include <stdexcept>
#include <fstream>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/dll/runtime_symbol_info.hpp>
#include <boost/filesystem.hpp>

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
  if (arg0 == "jove" || arg0 == TARGET_ARCH_NAME) {
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
        try {
          tool.reset(x.second()); /* instantiate */
        } catch (const boost::interprocess::interprocess_exception &e) {
          llvm::errs() << llvm::formatv("interprocess exception: {0}\n", e.what());
          return 1;
        }
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

  tool->_name = name;
  tool->set_dashdash_args(dashdash_args);

  llvm::InitLLVM X(argc, argv);

  //
  // select tool
  //
  llvm::cl::HideUnrelatedOptions({&tool->JoveCategory, &llvm::getColorCategory()});
  llvm::cl::AddExtraVersionPrinter([](llvm::raw_ostream &OS) -> void {
    OS << "jove version " JOVE_VERSION "\n";
  });
  std::string Desc = (std::string("jove-") + name) + "\n";
  llvm::cl::ParseCommandLineOptions(argc, argv, Desc);

  int res = tool->Run();

  return res;
}

namespace fs = boost::filesystem;

namespace jove {

Tool::Tool()
    : HumanOutputStreamPtr(&llvm::outs()),

      JoveCategory("Specific Options"),

      opt_Verbose("verbose", llvm::cl::desc("Print debugging messages"),
                  llvm::cl::cat(JoveCategory)),

      opt_VerboseAlias("v", llvm::cl::desc("Alias for -verbose."),
                       llvm::cl::aliasopt(opt_Verbose),
                       llvm::cl::cat(JoveCategory)),

      opt_VeryVerbose("very-verbose",
                      llvm::cl::desc("Print debugging messages"),
                      llvm::cl::cat(JoveCategory)),

      opt_VeryVerboseAlias("vv", llvm::cl::desc("Alias for -verbose."),
                           llvm::cl::aliasopt(opt_VeryVerbose),
                           llvm::cl::cat(JoveCategory)),

      opt_TemporaryDir("temp-dir", llvm::cl::value_desc("directory"),
                       llvm::cl::cat(JoveCategory)),

      opt_NoDeleteTemporaryDir(
          "no-rm-temp-dir",
          llvm::cl::desc("Do not remove temporary directory on exit"),
          llvm::cl::cat(JoveCategory)) {}

Tool::~Tool() {
  cleanup_temp_dir();
}

void Tool::HumanOutToFile(const std::string &path) {
  std::error_code EC;
  HumanOutputFileStream.reset(new llvm::raw_fd_ostream(path, EC));

  if (EC)
    throw std::runtime_error("HumanOutToFile: failed to open \"" + path + "\"");

  HumanOutputStreamPtr = HumanOutputFileStream.get();
}

[[noreturn]] void Tool::die(const std::string &reason) {
  throw std::runtime_error(reason);
}

void Tool::curiosity(const std::string &message) {
  if (!IsVerbose())
    return;

  HumanOut() << llvm::formatv("CURIOSITY: {0}\n", message);
}

bool Tool::ShouldSleepOnCrash(void) const {
  const char *const s = std::getenv("JOVE_SLEEP_ON_CRASH");
  return s && s[0] == '1';
}

void Tool::print_command(const char **argv) {
  for (const char **argp = argv; *argp; ++argp) {
    HumanOut() << *argp;

    if (*(argp + 1))
      HumanOut() << ' ';
  }

  HumanOut() << '\n';
}

void Tool::on_exec(const char **argv, const char **envp) {
  if (!IsVerbose())
    return;

  print_command(argv);
}

void Tool::on_exec_tool(const char **argv, const char **envp) {
  if (!IsVerbose())
    return;

  HumanOut() << path_to_jove() << ' ';

  print_command(argv);
}

pid_t Tool::RunExecutable(const std::string &exe_path,
                          compute_args_t compute_args,
                          const std::string &stdout_path,
                          const std::string &stderr_path) {
  using namespace std::placeholders;

  return jove::RunExecutable(
      exe_path,
      compute_args,
      stdout_path,
      stderr_path,
      std::bind(&Tool::on_exec, this, _1, _2));
}

pid_t Tool::RunExecutable(const std::string &exe_path,
                          compute_args_t compute_args,
                          compute_envs_t compute_envs,
                          const std::string &stdout_path,
                          const std::string &stderr_path) {
  using namespace std::placeholders;

  return jove::RunExecutable(
      exe_path,
      compute_args,
      compute_envs,
      stdout_path,
      stderr_path,
      std::bind(&Tool::on_exec, this, _1, _2));
}

void Tool::persist_tool_options(std::function<void(const std::string &)> Arg) {
  if (IsVerbose())
    Arg("-v");
  if (opt_NoDeleteTemporaryDir)
    Arg("--no-rm-temp-dir");
}

std::string Tool::path_to_jove(void) {
  std::string jove_path = boost::dll::program_location().string();

  if (boost::algorithm::ends_with(jove_path, " (deleted)")) /* XXX */
    jove_path = jove_path.substr(0, jove_path.size() - sizeof(" (deleted)") + 1);

  if (!fs::exists(jove_path))
    throw std::runtime_error("could not locate jove executable");

  return jove_path;
}

int Tool::RunTool(const char *tool_name,
                  compute_args_t compute_args,
                  const std::string &stdout_path,
                  const std::string &stderr_path,
                  const RunToolExtraArgs &Extra) {
  using namespace std::placeholders;

  if (Extra.sudo.On) {
    const char *sudo_path = "/usr/bin/sudo";
    std::string jove_path = path_to_jove();

    return jove::RunExecutable(sudo_path,
        [&](auto Arg) {
          Arg(sudo_path);

          if (Extra.sudo.PreserveEnvironment)
            Arg("-E");

          Arg(jove_path);
          Arg(tool_name);

          persist_tool_options(Arg);

          compute_args(Arg);
        },
        stdout_path,
        stderr_path,
        std::bind(&Tool::on_exec, this, _1, _2));
  }

  return jove::RunExecutable(
      "/proc/self/exe",
      [&](auto Arg) {
        Arg(tool_name);

        persist_tool_options(Arg);

        compute_args(Arg);
      },
      stdout_path,
      stderr_path,
      std::bind(&Tool::on_exec_tool, this, _1, _2));
}

int Tool::RunTool(const char *tool_name,
                  compute_args_t compute_args,
                  compute_envs_t compute_envs,
                  const std::string &stdout_path,
                  const std::string &stderr_path,
                  const RunToolExtraArgs &Extra) {
  using namespace std::placeholders;

  if (Extra.sudo.On) {
    const char *sudo_path = "/usr/bin/sudo";
    std::string jove_path = path_to_jove();

    return jove::RunExecutable(sudo_path,
        [&](auto Arg) {
          Arg(sudo_path);

          if (Extra.sudo.PreserveEnvironment)
            Arg("-E");

          Arg(jove_path);
          Arg(tool_name);

          persist_tool_options(Arg);

          compute_args(Arg);
        },
        compute_envs,
        stdout_path,
        stderr_path,
        std::bind(&Tool::on_exec, this, _1, _2));
  }

  return jove::RunExecutable(
      "/proc/self/exe",
      [&](auto Arg) {
        Arg(tool_name);

        persist_tool_options(Arg);

        compute_args(Arg);
      },
      compute_envs,
      stdout_path,
      stderr_path,
      std::bind(&Tool::on_exec_tool, this, _1, _2));
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

std::string Tool::path_to_jv(void) {
  if (char *var = getenv("JVPATH"))
    return var;

  return home_dir() + "/.jv";
}

#if 0
std::string Tool::path_to_jv(const char *exe_path) {
  std::vector<uint8_t> exe_bytes;
  read_file_into_vector(exe_path, exe_bytes);

  return jove_dir() + "/" + crypto::hash(&exe_bytes[0], exe_bytes.size()) +
         ".jv";
}
#endif

std::string Tool::path_to_sysroot(const char *exe_path, bool ForeignLibs) {
  std::vector<uint8_t> exe_bytes;
  read_file_into_vector(exe_path, exe_bytes);

  std::string res = jove_dir() + "/" +
                    crypto::hash(&exe_bytes[0], exe_bytes.size()) + ".sysroot";
  if (ForeignLibs)
    res.append(".x");

  return res;
}

const std::string &Tool::temporary_dir(void) {
  std::lock_guard<std::mutex> lck(_temp_dir_mtx);

  auto &dir = _temp_dir;
  if (dir.empty()) {
    if (opt_TemporaryDir.empty())
      dir = "/tmp";
    else
      dir = opt_TemporaryDir;

    dir.append("/jove.");

    assert(_name);
    dir.append(_name);

    dir.append(".XXXXXX");

    if (!mkdtemp(&dir[0])) {
      int err = errno;
      throw std::runtime_error(std::string("Tool::temporary_dir: mkdtemp failed: ") +
                               strerror(err));
    }

    assert(!dir.empty());

    if (IsVerbose())
      HumanOut() << llvm::formatv("created temporary directory at {0}\n", dir);
  }

  return dir;
}

void Tool::cleanup_temp_dir(void) {
  if (opt_NoDeleteTemporaryDir)
    return;

  if (!_temp_dir.empty() &&
      fs::exists(_temp_dir) &&
      fs::is_directory(_temp_dir)) {
    fs::remove_all(_temp_dir);
  }
}

JVTool::JVTool(const char *_jv_path)
    : jv_path(_jv_path ? std::string(_jv_path) : path_to_jv()),
      jv_file(boost::interprocess::open_or_create, jv_path.c_str(), JV_DEFAULT_INITIAL_SIZE),
      Alloc(jv_file.get_segment_manager()),
      jv(*jv_file.find_or_construct<jv_t>("JV")(ip_void_allocator_t(jv_file.get_segment_manager())))
{
  /* FIXME */
  for (binary_t &b : jv.Binaries)
    __builtin_memset(&b.Analysis.ICFG.m_property, 0, sizeof(b.Analysis.ICFG.m_property));

}

}
