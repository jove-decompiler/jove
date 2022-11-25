#pragma once
#include "jv.h"
#include <llvm/Support/CommandLine.h>
#include <memory>
#include <vector>
#include <sys/wait.h>

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

  std::vector<char *> dashdash_args;
  void set_dashdash_args(const std::vector<char *> dashdash_args) {
    this->dashdash_args = dashdash_args;
  }

  //
  // utlity methods
  //
  int WaitForProcessToExit(pid_t, bool verbose = false);
  void IgnoreCtrlC(void);
  void print_command(const char** cstr_p);
  void exec_tool(const char *name,
                 const std::vector<const char *> &arg_vec,
                 const char **envp = nullptr);

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
  static void read_file_into_vector(const char *path, std::vector<uint8_t> &out);
  static ssize_t robust_read(int fd, void *const buf, const size_t count);
  static ssize_t robust_write(int fd, const void *const buf, const size_t count);
  static uint32_t size_of_file32(const char *path);
  static ssize_t robust_sendfile(int socket, const char *file_path, size_t file_size);
  static ssize_t robust_sendfile_with_size(int socket, const char *file_path);
  static ssize_t robust_receive_file_with_size(int socket, const char *out, unsigned file_perm);

  static unsigned num_cpus(void);
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
