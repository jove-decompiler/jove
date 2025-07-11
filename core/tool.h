#pragma once
#include "jove/jove.h"
#include "util.h"
#include "fd.h"
#include "process.h"
#include "locator.h"
#include "run.h"

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
#include <optional>

#include <boost/interprocess/managed_mapped_file.hpp>
#include <llvm/Support/CommandLine.h>

namespace llvm {
class raw_ostream;
class raw_fd_ostream;
}

namespace jove {

class Tool : public VerboseThing {
  llvm::raw_ostream *HumanOutputStreamPtr;
  std::unique_ptr<llvm::raw_fd_ostream> HumanOutputFileStream;

public:
  llvm::cl::OptionCategory JoveCategory;

private:
  llvm::cl::opt<bool> opt_Verbose;
  llvm::cl::alias opt_VerboseAlias;
  llvm::cl::opt<bool> opt_VeryVerbose;
  llvm::cl::alias opt_VeryVerboseAlias;
  llvm::cl::opt<std::string> opt_TemporaryDir;
  llvm::cl::opt<bool> opt_NoDeleteTemporaryDir;
  llvm::cl::opt<bool> opt_DumbTerm;

  std::mutex _temp_dir_mtx;
  std::string _temp_dir;
  void cleanup_temp_dir(void);

protected:
  static bool is_jv_cow_copy;
  static std::string jv_filename; /* XXX must set this *before* ctor */

  locator_t loc;

  void ConfigureVerbosity(VerboseThing &Thing) {
    Thing.SetVerbosity(this->opt_Verbose, this->opt_VeryVerbose);
  }
public:
  const char *_name = nullptr;

public:
  Tool();
  virtual ~Tool();

  void UpdateVerbosity(void);
  virtual int Run(void) = 0;

protected:
  void HumanOutToFile(const std::string &path);

  [[noreturn]] void die(const std::string &reason);
  void warn(const char *file, int line);

  void CURIOSITY(const std::string &message);

  bool ShouldSleepOnCrash(void) const;
  bool ShouldDeleteTemporaryFiles(void) const {
    return !opt_NoDeleteTemporaryDir;
  }

public:
  llvm::raw_ostream &HumanOut(void) {
    return *HumanOutputStreamPtr;
  }

  std::vector<char *> dashdash_args;
  void set_dashdash_args(const std::vector<char *> dashdash_args) {
    this->dashdash_args = dashdash_args;
  }

  template <typename ComputeArgs>
  pid_t RunExecutable(const std::string &exe_path,
      ComputeArgs compute_args,
      const std::string &stdout_path = std::string(),
      const std::string &stderr_path = std::string(),
      before_exec_t before_exec = [](const char **, const char **) -> void {}) {
    using namespace std::placeholders;

    return jove::RunExecutable(
        exe_path,
        compute_args,
        stdout_path,
        stderr_path,
        std::bind(&Tool::on_exec, this, before_exec, _1, _2));
  }

  template <typename ComputeArgs, typename ComputeEnvs>
  pid_t RunExecutable(const std::string &exe_path,
      ComputeArgs compute_args,
      ComputeEnvs compute_envs,
      const std::string &stdout_path = std::string(),
      const std::string &stderr_path = std::string(),
      before_exec_t before_exec = [](const char **, const char **) -> void {}) {
    using namespace std::placeholders;

    return jove::RunExecutable(
        exe_path,
        compute_args,
        compute_envs,
        stdout_path,
        stderr_path,
        std::bind(&Tool::on_exec, this, before_exec, _1, _2));
  }

  struct RunToolExtraArgs {
    struct {
      bool On;
      bool PreserveEnvironment;
    } sudo;

    RunToolExtraArgs() : sudo({false, false}) {}
    RunToolExtraArgs(bool SudoOn, bool SudoPreserveEnvironment)
        : sudo({SudoOn, SudoPreserveEnvironment}) {}
  };

  template <typename ComputeArgs>
  int RunTool(const char *tool_name,
      ComputeArgs compute_args,
      const std::string &stdout_path = std::string(),
      const std::string &stderr_path = std::string(),
      const RunToolExtraArgs &Extra = RunToolExtraArgs(),
      before_exec_t before_exec = [](const char **, const char **) {}) {
    using namespace std::placeholders;

    if (Extra.sudo.On) {
      std::string sudo_path = locator().sudo();
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
          std::bind(&Tool::on_exec, this, before_exec, _1, _2));
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
        std::bind(&Tool::on_exec_tool, this, before_exec, _1, _2));
  }

  template <typename ComputeArgs, typename ComputeEnvs>
  int RunTool(const char *tool_name,
      ComputeArgs compute_args,
      ComputeEnvs compute_envs,
      const std::string &stdout_path = std::string(),
      const std::string &stderr_path = std::string(),
      const RunToolExtraArgs &Extra = RunToolExtraArgs(),
      before_exec_t before_exec = [](const char **, const char **) {}) {
    using namespace std::placeholders;

    if (Extra.sudo.On) {
      std::string sudo_path = locator().sudo();
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
          std::bind(&Tool::on_exec, this, before_exec, _1, _2));
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
        std::bind(&Tool::on_exec_tool, this, before_exec, _1, _2));
  }

  template <typename... Args>
  int RunExecutableToExit(Args &&...args) {
    pid_t pid = this->RunExecutable(std::forward<Args>(args)...);
    return WaitForProcessToExit(pid);
  }

  template <typename... Args>
  int RunToolToExit(Args &&...args) {
    pid_t pid = RunTool(std::forward<Args>(args)...);
    return WaitForProcessToExit(pid);
  }

  void print_command_environment(const char **envp);
  void print_command(const char** cstr_p);
  void print_tool_command(const char *name,
                          const std::vector<const char *> &_arg_vec) {
    std::vector<const char *> arg_vec(_arg_vec);
    arg_vec.insert(arg_vec.begin(), name);
    arg_vec.push_back(nullptr);
    print_command(&arg_vec[0]);
  }

  static std::string home_dir(void);
  static std::string jove_dir(void);
  static std::string get_path_to_jv(void);
  static std::string path_to_sysroot(const char *exe_path, bool ForeignLibs);
  bool is_smart_terminal(int fd = STDOUT_FILENO);

  const std::string &temporary_dir(void);

  const std::string &path_to_jv(void) {
    return jv_filename;
  }

  locator_t &locator() { return loc; }

private:
  void on_exec(before_exec_t before_exec, const char **argv, const char **envp);
  void on_exec_tool(before_exec_t before_exec, const char **argv, const char **envp);
  void persist_tool_options(std::function<void(const std::string &)> Arg);
  std::string path_to_jove(void);
};

typedef Tool *(*ToolCreationProc)(void);

size_t jvCreationSize(void);

template <bool MT = AreWeMT, bool MinSize = AreWeMinSize>
struct BaseJVTool : public Tool {
  using jv_t = jv_base_t<MT, MinSize>;
  using binary_t = binary_base_t<MT, MinSize>;
  using icfg_t = ip_icfg_base_t<MT>;
  using bb_t = binary_t::bb_t;

  static constexpr bool IsToolMT = MT;
  static constexpr bool IsToolMinSize = MinSize;

  jv_file_t jv_file;
  jv_t &jv;

  template <typename... Args>
  BaseJVTool(Args &&...args)
      : jv_file(std::forward<Args>(args)...),
        jv(*jv_file.find_or_construct<jv_t>("JV")(jv_file)) {
    DoCtorCommon();
  }

  void DoCtorCommon(void) {
    exclude_from_coredumps(jv_file.get_address(), jv_file.get_size());
    assert(!jv_filename.empty());
  }

  static std::optional<size_t> jvSize(void); /* parses $JVSIZE */
  static size_t jvCreationSize(void);
  static std::string cow_copy_if_possible(const std::string &filename);
};

enum class ToolKind { Standard, CopyOnWrite };

constexpr bool IsToolKindCopyOnWrite(ToolKind Kind) {
  return Kind == ToolKind::CopyOnWrite;
}

template <ToolKind Kind> struct JVTool {};

template <>
struct JVTool<ToolKind::Standard> : public BaseJVTool<> {
  JVTool()
      : BaseJVTool(boost::interprocess::open_or_create,
                   (jv_filename = get_path_to_jv()).c_str(), jvCreationSize())
  {}
};

template <>
struct JVTool<ToolKind::CopyOnWrite> : public BaseJVTool<>  {
  JVTool()
      : BaseJVTool(
            boost::interprocess::open_copy_on_write,
            (jv_filename = cow_copy_if_possible(get_path_to_jv())).c_str()) {
    if (is_jv_cow_copy)
      ::unlink(path_to_jv().c_str());
#if 0
    if (char *var = getenv("JVFORCE")) {
      if (var[0] == '1')
        forcefully_unlock(jv);
    }
#endif
  }
};

template <ToolKind Kind,
          typename BinaryStateT,
          typename FunctionStateT,
          typename BBStateT,
          bool MultiThreaded = AreWeMT,
          bool LazyInitialization = true,
          bool Eager = false,
          bool BoundsChecking = true,
          bool SubjectToChange = !IsToolKindCopyOnWrite(Kind)>
struct StatefulJVTool : public JVTool<Kind> {
  static_assert(!(!IsToolKindCopyOnWrite(Kind) && !SubjectToChange),
                "if !CoW then must be subject to change");

  jv_state_t<BinaryStateT, FunctionStateT, BBStateT, MultiThreaded,
             LazyInitialization, Eager, BoundsChecking, SubjectToChange,
             JVTool<Kind>::IsToolMT, JVTool<Kind>::IsToolMinSize>
      state;

  template <typename... Args>
  StatefulJVTool(Args &&...args)
      : JVTool<Kind>(std::forward<Args>(args)...), state(this->jv) {}
};

void RegisterTool(const char *name, ToolCreationProc Create);

#define JOVE_REGISTER_TOOL(name, ToolTy)                                       \
  static struct AutoRegister##ToolTy {                                         \
    AutoRegister##ToolTy() {                                                   \
      RegisterTool(name, [](void) -> Tool * { return new ToolTy; });           \
    }                                                                          \
  } ___register_tool
}
