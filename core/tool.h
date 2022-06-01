#pragma once
#include "jove/jove.h"
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
  static int WaitForProcessToExit(pid_t);
  void IgnoreCtrlC(void);
  void print_command(const char** cstr_p);

  static void ReadDecompilationFromFile(const std::string &path,
                                        decompilation_t &);

  static void WriteDecompilationToFile(const std::string &path,
                                       const decompilation_t &);
};

typedef Tool *(*ToolCreationProc)(void);

void RegisterTool(const char *name, ToolCreationProc Create);

#define JOVE_REGISTER_TOOL(name, ToolTy)                                       \
  static struct AutoRegister##ToolTy {                                         \
    AutoRegister##ToolTy() {                                                   \
      RegisterTool(name, [](void) -> Tool * { return new ToolTy; });           \
    }                                                                          \
  } ___register_tool
}
