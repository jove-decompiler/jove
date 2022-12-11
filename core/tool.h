#pragma once
#include "jv.h"
#include "util.h"
#include "fd.h"
#include "process.h"

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <llvm/Support/CommandLine.h>

namespace llvm {
class raw_ostream;
class raw_fd_ostream;
}

namespace jove {

class Tool {
  llvm::raw_ostream *HumanOutputStreamPtr;
  std::unique_ptr<llvm::raw_fd_ostream> HumanOutputFileStream;

public:
  llvm::cl::OptionCategory JoveCategory;

private:
  llvm::cl::opt<bool> opt_Verbose;
  llvm::cl::alias opt_VerboseAlias;
  llvm::cl::opt<std::string> opt_TemporaryDir;
  llvm::cl::opt<bool> opt_NoDeleteTemporaryDir;

  std::mutex _temp_dir_mtx;
  std::string _temp_dir;
  void cleanup_temp_dir(void);
public:
  const char *_name = nullptr;

  jv_t jv;

public:
  Tool();
  virtual ~Tool();

  virtual int Run(void) = 0;

protected:
  void HumanOutToFile(const std::string &path);

public:
  llvm::raw_ostream &HumanOut(void) {
    return *HumanOutputStreamPtr;
  }

  bool IsVerbose(void) {
    return opt_Verbose;
  }

  std::vector<char *> dashdash_args;
  void set_dashdash_args(const std::vector<char *> dashdash_args) {
    this->dashdash_args = dashdash_args;
  }

  pid_t RunExecutable(const char *exe_path,
      compute_args_t compute_args,
      const std::string &stdout_path = std::string(),
      const std::string &stderr_path = std::string());

  pid_t RunExecutable(const char *exe_path,
      compute_args_t compute_args,
      compute_envs_t compute_envs,
      const std::string &stdout_path = std::string(),
      const std::string &stderr_path = std::string());

  struct RunToolExtraArgs {
    struct {
      bool On;
      bool PreserveEnvironment;
    } sudo;

    RunToolExtraArgs() : sudo({false, false}) {}
    RunToolExtraArgs(bool SudoOn, bool SudoPreserveEnvironment)
        : sudo({SudoOn, SudoPreserveEnvironment}) {}
  };

  int RunTool(const char *tool_name,
      compute_args_t compute_args,
      const std::string &stdout_path = std::string(),
      const std::string &stderr_path = std::string(),
      const RunToolExtraArgs &Extra = RunToolExtraArgs());

  template <typename... Args>
  int RunExecutableToExit(Args &&...args) {
    pid_t pid = RunExecutable(std::forward<Args>(args)...);
    return WaitForProcessToExit(pid);
  }

  template <typename... Args>
  int RunToolToExit(Args &&...args) {
    pid_t pid = RunTool(std::forward<Args>(args)...);
    return WaitForProcessToExit(pid);
  }

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
  static std::string path_to_jv(const char *exe_path);
  static std::string path_to_sysroot(const char *exe_path, bool ForeignLibs);

  const std::string &temporary_dir(void);

private:
  void on_exec(const char **argv, const char **envp);
  void on_exec_tool(const char **argv, const char **envp);
  void persist_tool_options(std::function<void(const std::string &)> Arg);
  std::string path_to_jove(void);
};

typedef Tool *(*ToolCreationProc)(void);

template <typename BinaryStateT, typename FunctionStateT = int>
struct TransformerTool : public Tool
{
  jv_state_t<BinaryStateT, FunctionStateT> state;

  TransformerTool() : state(jv) {}
};

void RegisterTool(const char *name, ToolCreationProc Create);

#define JOVE_REGISTER_TOOL(name, ToolTy)                                       \
  static struct AutoRegister##ToolTy {                                         \
    AutoRegister##ToolTy() {                                                   \
      RegisterTool(name, [](void) -> Tool * { return new ToolTy; });           \
    }                                                                          \
  } ___register_tool
}
