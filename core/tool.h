#pragma once
#include "jove/jove.h"
#include "util.h"
#include "fd.h"
#include "process.h"
#include "locator.h"

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <boost/interprocess/managed_mapped_file.hpp>
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
  llvm::cl::opt<bool> opt_VeryVerbose;
  llvm::cl::alias opt_VeryVerboseAlias;
  llvm::cl::opt<std::string> opt_TemporaryDir;
  llvm::cl::opt<bool> opt_NoDeleteTemporaryDir;

  std::mutex _temp_dir_mtx;
  std::string _temp_dir;
  void cleanup_temp_dir(void);

  locator_t loc;
public:
  const char *_name = nullptr;

public:
  Tool();
  virtual ~Tool();

  virtual int Run(void) = 0;

protected:
  void HumanOutToFile(const std::string &path);

  [[noreturn]] void die(const std::string &reason);
  void curiosity(const std::string &message);

  bool ShouldSleepOnCrash(void) const;

public:
  llvm::raw_ostream &HumanOut(void) {
    return *HumanOutputStreamPtr;
  }

  inline bool IsVerbose(void) {
    return unlikely(opt_Verbose || opt_VeryVerbose);
  }

  inline bool IsVeryVerbose(void) {
    return unlikely(opt_VeryVerbose);
  }

  std::vector<char *> dashdash_args;
  void set_dashdash_args(const std::vector<char *> dashdash_args) {
    this->dashdash_args = dashdash_args;
  }

  pid_t RunExecutable(const std::string &exe_path,
      compute_args_t compute_args,
      const std::string &stdout_path = std::string(),
      const std::string &stderr_path = std::string(),
      before_exec_t before_exec = [](const char **, const char **) -> void {});

  pid_t RunExecutable(const std::string &exe_path,
      compute_args_t compute_args,
      compute_envs_t compute_envs,
      const std::string &stdout_path = std::string(),
      const std::string &stderr_path = std::string(),
      before_exec_t before_exec = [](const char **, const char **) -> void {});

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
      const RunToolExtraArgs &Extra = RunToolExtraArgs(),
      before_exec_t before_exec = [](const char **, const char **) {});

  int RunTool(const char *tool_name,
      compute_args_t compute_args,
      compute_envs_t compute_envs,
      const std::string &stdout_path = std::string(),
      const std::string &stderr_path = std::string(),
      const RunToolExtraArgs &Extra = RunToolExtraArgs(),
      before_exec_t before_exec = [](const char **, const char **) {});

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
  static std::string path_to_jv(void);
  static std::string path_to_sysroot(const char *exe_path, bool ForeignLibs);

  const std::string &temporary_dir(void);

  locator_t &locator() { return loc; }

private:
  void on_exec(before_exec_t before_exec, const char **argv, const char **envp);
  void on_exec_tool(before_exec_t before_exec, const char **argv, const char **envp);
  void persist_tool_options(std::function<void(const std::string &)> Arg);
  std::string path_to_jove(void);
};

typedef Tool *(*ToolCreationProc)(void);

size_t jvDefaultInitialSize(void);

struct BaseJVTool : public Tool {
  jv_file_t jv_file;
  ip_void_allocator_t Alloc;

  jv_t &jv;

  template <typename... Args>
  BaseJVTool(Args &&...args)
      : jv_file(std::forward<Args>(args)...),
        Alloc(jv_file.get_segment_manager()),
        jv(*jv_file.find_or_construct<jv_t>("JV")(
            ip_void_allocator_t(jv_file.get_segment_manager()))) {
    /* FIXME */
    for (binary_t &b : jv.Binaries)
      __builtin_memset(&b.Analysis.ICFG.m_property, 0, sizeof(b.Analysis.ICFG.m_property));
  }
};

enum class ToolKind { Standard, CopyOnWrite };

template <ToolKind Kind>
struct JVTool : public BaseJVTool {
};

template <>
struct JVTool<ToolKind::Standard> : public BaseJVTool {
  JVTool()
      : BaseJVTool(boost::interprocess::open_or_create, path_to_jv().c_str(),
                   jvDefaultInitialSize()) {}
};

template <>
struct JVTool<ToolKind::CopyOnWrite> : public BaseJVTool  {
  JVTool()
      : BaseJVTool(boost::interprocess::open_copy_on_write,
                   path_to_jv().c_str()) {}
};

template <ToolKind Kind, typename BinaryStateT>
struct TransformerTool_Bin : public JVTool<Kind>
{
  jv_bin_state_t<BinaryStateT> state;

  template <typename... Args>
  TransformerTool_Bin(Args &&...args)
      : JVTool<Kind>(std::forward<Args>(args)...), state(BaseJVTool::jv) {}
};

template <ToolKind Kind, typename FunctionStateT>
struct TransformerTool_Fn : public JVTool<Kind>
{
  jv_fn_state_t<FunctionStateT> state;

  template <typename... Args>
  TransformerTool_Fn(Args &&...args)
      : JVTool<Kind>(std::forward<Args>(args)...), state(BaseJVTool::jv) {}
};

template <ToolKind Kind, typename BinaryStateT, typename FunctionStateT>
struct TransformerTool_BinFn : public JVTool<Kind>
{
  jv_bin_fn_state_t<BinaryStateT, FunctionStateT> state;

  template <typename... Args>
  TransformerTool_BinFn(Args &&...args)
      : JVTool<Kind>(std::forward<Args>(args)...), state(BaseJVTool::jv) {}
};

template <ToolKind Kind, typename BinaryStateT, typename FunctionStateT, typename BBStateT>
struct TransformerTool_BinFnBB : public JVTool<Kind>
{
  jv_bin_fn_bb_state_t<BinaryStateT, FunctionStateT, BBStateT> state;

  template <typename... Args>
  TransformerTool_BinFnBB(Args &&...args)
      : JVTool<Kind>(std::forward<Args>(args)...), state(BaseJVTool::jv) {}
};

void RegisterTool(const char *name, ToolCreationProc Create);

#define JOVE_REGISTER_TOOL(name, ToolTy)                                       \
  static struct AutoRegister##ToolTy {                                         \
    AutoRegister##ToolTy() {                                                   \
      RegisterTool(name, [](void) -> Tool * { return new ToolTy; });           \
    }                                                                          \
  } ___register_tool
}
