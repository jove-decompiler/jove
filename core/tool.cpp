#define NO_JOVE_ASSERT
#include "tool.h"
#include "crypto.h"
#include "locator.h"
#include "sizes.h"
#include "reflink.h"
#include "ansi.h"
#include "tbb_hacks.h"
#include "crash.h"

#include <stdexcept>
#include <fstream>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/dll/runtime_symbol_info.hpp>
#include <boost/filesystem.hpp>
#include <boost/stacktrace.hpp>
#include <boost/stacktrace/this_thread.hpp>
#include <boost/scope/defer.hpp>

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
static boost::unordered::unordered_flat_map<std::string_view,
                                            jove::ToolCreationProc>
    AllTools;

void RegisterTool(const char *name, ToolCreationProc proc) {
  AllTools.emplace(name, proc);
}

}

using llvm::WithColor;

int main(int argc, char **argv) {
  //
  // ld.lld --wrap is broken on MIPS.
  //
#if !defined(__mips64) && !defined(__mips__)
  boost::stacktrace::this_thread::set_capture_stacktraces_at_throw(true);
  assert(boost::stacktrace::this_thread::get_capture_stacktraces_at_throw());
#endif

#ifndef JOVE_NO_TBB
  jove::tbb_hacks::disable();
#endif

  auto usage = [&](void) -> std::string {
    std::string res =
"jove multi-call binary."                  "\n"
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

#if 0
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
#endif

  //
  // examine argv[0]
  //
  std::string name_str;
  const char *name = nullptr;
  std::unique_ptr<jove::Tool> tool;

  auto make_tool = [&](const char *tool_name) -> void {
    auto it = jove::AllTools.find(tool_name);
    if (it != jove::AllTools.end()) {
      auto &x = *it;

      name_str = x.first;
      name = name_str.c_str();
      tool.reset(x.second()); /* instantiate */
    }
  };

  if (argc < 1) {
    llvm::errs() << usage();
    return 1;
  }
  make_tool(argv[0]);

  std::vector<char *> _argv;
  if (!tool) {
    if (argc < 2) {
      WithColor::error() << llvm::formatv("unknown tool requested (\"{0}\")\n",
                                          argv[0]);

      llvm::errs() << usage();
      return 1;
    }
    make_tool(argv[1]);

    if (tool) {
      //
      // shuffle argc/argv
      //
      _argv.reserve(argc);
      _argv.push_back(argv[1]);
      for (unsigned i = 2; i < argc; ++i)
        _argv.push_back(argv[i]);
      _argv.push_back(nullptr);

      argc = argc - 1;
      argv = _argv.data();
    } else {
      WithColor::error() << llvm::formatv(
          "unknown tool requested (\"{0}\") (\"{1}\")\n", argv[0], argv[1]);
      llvm::errs() << usage();
      return 1;
    }
  }

  assert(name);
  assert(tool);

  tool->_name = name;

  std::string message;
  {
#ifndef JOVE_NO_TBB
  BOOST_SCOPE_DEFER [] {
    jove::tbb_hacks::pre_fork();
    jove::tbb_hacks::disable();
  };
#endif

  //
  // select tool
  //
  llvm::cl::HideUnrelatedOptions({&tool->JoveCategory, &llvm::getColorCategory()});
  llvm::cl::AddExtraVersionPrinter([](llvm::raw_ostream &OS) -> void {
    static const char *rev_tbl[][2] = {
#define VERS(NAME, REV) {NAME, REV},
#include "version.inc"
#undef VERS
    };

    for (unsigned i = 0; i < std::size(rev_tbl); ++i)
      OS << llvm::formatv("{0}\t{1}\n", rev_tbl[i][0], rev_tbl[i][1]);
  });
  std::string Desc = (std::string("jove-") + name) + "\n";
  llvm::cl::ParseCommandLineOptions(argc, argv, Desc);

  tool->UpdateVerbosity();

  ::srand(time(NULL));
  ::setlocale(LC_ALL, "C");

#ifndef JOVE_NO_TBB
  jove::tbb_hacks::enable();
#endif

#ifndef NDEBUG
  //
  // In non-debug builds we want to catch any stray crashes by just looping
  // endlessly. Eventually, we will (hopefully) investigate.
  //
  jove::setup_crash_signal_handler();
#endif
  jove::setup_crash_handler();

  const bool smartterm = tool->is_smart_terminal();

  try {
    return tool->Run();
  } catch (const boost::interprocess::bad_alloc &) {
    WithColor::error()
        << "exhausted all available memory for .jv. try removing ~/.jv.* and "
           "setting the JVSIZE environment variable to something larger than "
           "the default (e.g. JVSIZE=8G jove init /path/to/program)\n";
  } catch (const jove::assertion_failure_base &x) {
    auto trace = boost::stacktrace::stacktrace::from_current_exception();

    message = llvm::formatv(
      "==================================================\n"
      "{2}JOVE ASSERTION FAILURE{3} ({4}{0}{5})\n{1}"
      "==================================================\n",
      x.what(),
      boost::stacktrace::to_string(trace),
      smartterm ? __ANSI_BOLD_RED : "",
      smartterm ? __ANSI_NORMAL_COLOR : "",
      smartterm ? __ANSI_YELLOW : "",
      smartterm ? __ANSI_NORMAL_COLOR : "").str();
  } catch (const std::exception &x) {
    auto trace = boost::stacktrace::stacktrace::from_current_exception();

    message = llvm::formatv("{2}{0}{3}\n{1}", x.what(),
                            boost::stacktrace::to_string(trace),
                            smartterm ? __ANSI_BOLD_RED : "",
                            smartterm ? __ANSI_NORMAL_COLOR : "").str();
  } catch (...) {
    auto trace = boost::stacktrace::stacktrace::from_current_exception();

    WithColor::error() << llvm::formatv("exception was thrown!\n{0}",
                                        boost::stacktrace::to_string(trace));
  }

  }

  //
  // if we get here, an exception occurred. some thing may be in an "undefined"
  // state. At this point, behave as though `execve("/usr/bin/false")` occurred.
  //
  llvm::errs() << message;
  llvm::errs().flush();

  for (;;)
    _exit(1);

  __builtin_unreachable();
}

namespace fs = boost::filesystem;

namespace jove {

Tool::Tool()
    : HumanOutputStreamPtr(&llvm::errs()),

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
          llvm::cl::cat(JoveCategory)),

      opt_DumbTerm("dumb-term",
                   llvm::cl::desc("Assume smart terminal does not exist"),
                   llvm::cl::cat(JoveCategory))

{}

Tool::~Tool() {
  cleanup_temp_dir();
}

void Tool::UpdateVerbosity(void) {
  this->SetVerbosity(opt_Verbose, opt_VeryVerbose);
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

void Tool::CURIOSITY(const std::string &message) {
  if (!IsVerbose())
    return;

  HumanOut() << llvm::formatv(
      __ANSI_BOLD_YELLOW "CURIOSITY: {0}" __ANSI_NORMAL_COLOR "\n", message);
}

void Tool::warn(const char *file, int line) {
  HumanOut() << llvm::formatv("WARNING @ {0}:{1}\n", file, line);
}

bool Tool::ShouldSleepOnCrash(void) const {
  const char *const s = std::getenv("JOVE_SLEEP_ON_CRASH");
  return s && s[0] == '1';
}

void Tool::print_command_environment(const char **envp) {
  for (const char **env = envp; *env; ++env) {
    const char *const e = *env;

    if (strncmp(e, "JVPATH=", sizeof("JVPATH=") - 1) != 0)
      continue;

    HumanOut() << e << ' ';
    break;
  }
}

void Tool::print_command(const char **argv) {
  for (const char **argp = argv; *argp; ++argp) {
    HumanOut() << *argp;

    if (*(argp + 1))
      HumanOut() << ' ';
  }

  HumanOut() << '\n';
}

void Tool::on_exec(before_exec_t before_exec, const char **argv, const char **envp) {
  if (IsVerbose()) {
    print_command_environment(envp);
    print_command(argv);
  }

  before_exec(argv, envp);
}

void Tool::on_exec_tool(before_exec_t before_exec, const char **argv, const char **envp) {
  if (IsVerbose()) {
    print_command_environment(envp);
    HumanOut() << path_to_jove() << ' ';
    print_command(argv);
  }

  before_exec(argv, envp);
}

void Tool::persist_tool_options(std::function<void(const std::string &)> Arg) {
  if (opt_DumbTerm)
    Arg("--dumb-term");

  if (IsVeryVerbose())
    Arg("-vv");
  else if (IsVerbose())
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
  if (char *var = getenv("JOVEDIR"))
    return var;

  return home_dir() + "/.jove";
}

std::string Tool::jv_filename;
bool Tool::is_jv_cow_copy = false;

std::string Tool::get_path_to_jv(void) {
  if (char *var = getenv("JVPATH"))
    return var;

  return home_dir() + ("/.jv." TARGET_SHORT_NAME);
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

bool Tool::is_smart_terminal(int fd) {
  if (opt_DumbTerm)
    return false;

  const char *const term = getenv("TERM");
  if (!term)
    return false;

  if (strcmp(term, "dumb") == 0)
    return false;

  return ::isatty(fd);
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
    if (IsVerbose())
      HumanOut() << llvm::formatv(
          "removing temporary directory at {0}{1}\n", _temp_dir,
          IsVeryVerbose() ? " (prevent by passing --no-rm-temp-dir)" : "");

    fs::remove_all(_temp_dir);
  }
}

struct invalid_size_exception {};

template <bool MT, bool MinSize>
std::optional<size_t> BaseJVTool<MT, MinSize>::jvSize(void) {
  if (char *var = getenv("JVSIZE")) {
    try {
      if (!var[0])
        throw invalid_size_exception();

      char *endptr = nullptr;

      errno = 0;
      size_t size = strtoull(var, &endptr, 0);
      if (!size || errno)
        throw invalid_size_exception();
      if (!endptr || endptr[0] == '\0')
        return size;

      size_t res;
      if ((strcmp(endptr, "G") == 0 && !__builtin_mul_overflow(size, GiB, &res)) ||
          (strcmp(endptr, "M") == 0 && !__builtin_mul_overflow(size, MiB, &res)))
        return res;

      throw invalid_size_exception();
    } catch (const invalid_size_exception &) {
      WithColor::error() << "invalid JVSIZE provided: falling back on default\n";
    }
  }

  return std::nullopt;
}

template <bool MT, bool MinSize>
size_t BaseJVTool<MT, MinSize>::jvCreationSize(void) {
  if (auto userProvidedSize = jvSize())
    return *userProvidedSize;
  return jvDefaultInitialSize();
}

template <bool MT, bool MinSize>
std::string BaseJVTool<MT, MinSize>::cow_copy_if_possible(
    const std::string &the_jv_filename) {
  int err;
  scoped_fd src_fd(({
    int res = ::open(the_jv_filename.c_str(), O_RDONLY);
    err = errno;
    res;
  }));
  if (!src_fd)
    throw std::runtime_error("failed to open \"" + the_jv_filename + "\" (" +
                             strerror(err) + '\"');

  std::string cow_filename(the_jv_filename + ".copy.XXXXXX");

  int fd_ = mkstemp(&cow_filename[0]);
  if (fd_ < 0)
    return the_jv_filename; /* we failed to make a CoW copy :( */

  scoped_fd dst_fd(fd_);
  assert(dst_fd);

  if (cp_reflink(src_fd.get(), dst_fd.get()) < 0) {
    WithColor::warning() << "filesystem does not support reflink copy!! XFS or "
                            "btrfs is recommended.\n";
    return the_jv_filename;
  }

  is_jv_cow_copy = true;
  return cow_filename;
}

template struct BaseJVTool<>;

}
