#include "tool.h"
#include <boost/filesystem.hpp>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

namespace cl = llvm::cl;
namespace fs = boost::filesystem;

using llvm::WithColor;

namespace jove {

class UnstubTool : public Tool {
  struct Cmdline {
    cl::opt<std::string> exe;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : exe(cl::Positional, cl::desc("<executable>"), cl::Required,
              cl::cat(JoveCategory)) {}
  } opts;

public:
  UnstubTool() : opts(JoveCategory) {}

  int Run(void);
};

JOVE_REGISTER_TOOL("unstub", UnstubTool);

int UnstubTool::Run(void) {
  std::vector<char> original_contents;

  {
    std::ifstream ifs(opts.exe);
    if (!ifs.is_open()) {
      WithColor::error() << "failed to open " << opts.exe << '\n';
      return 1;
    }

    ifs.seekg(0, std::ios::end);
    std::streampos file_len = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    unsigned line_no = 1;

    auto consume_line = [&](const std::string &expected) -> void {
      std::string line;

      if (!std::getline(ifs, line))
        throw std::runtime_error("expected line at line " +
                                 std::to_string(line_no));

      if (line != expected)
        throw std::runtime_error("line " + std::to_string(line_no) +
                                 ": expected " + expected + ", got " + line);

      ++line_no;
    };

    auto skip_line = [&](void) -> void {
      std::string line;

      if (!std::getline(ifs, line))
        throw std::runtime_error("expected line at line " +
                                 std::to_string(line_no));

      ++line_no;
    };

    consume_line("#!/bin/sh");
    consume_line("#");
    consume_line("# NOTE: FILE OVERWRITTEN BY 'jove stub'");
    consume_line("# RESTORE VIA 'jove unstub'");
    consume_line("#");
    skip_line();
    consume_line("");
    consume_line("");

    //
    // read rest of file
    //
    unsigned left = file_len - ifs.tellg();
    original_contents.resize(left);
    ifs.read(&original_contents[0], left);
  }

  {
    std::ofstream ofs(opts.exe,
                      std::ofstream::out
                    | std::ofstream::binary
                    | std::ofstream::trunc);

    if (!ofs) {
      WithColor::error() << "failed to overwrite " << opts.exe << '\n';
      return 1;
    }

    ofs.write(&original_contents[0], original_contents.size());
  }

  return 0;
}

}
