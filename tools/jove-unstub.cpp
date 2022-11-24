#include "tool.h"
#include "crypto.h"

#include <boost/filesystem.hpp>

#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

#include <cctype>

namespace cl = llvm::cl;
namespace fs = boost::filesystem;

using llvm::WithColor;

namespace jove {

class UnstubTool : public Tool {
  struct Cmdline {
    cl::opt<std::string> Prog;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Prog(cl::Positional, cl::desc("prog"), cl::Required,
               cl::value_desc("filename"), cl::cat(JoveCategory)) {}
  } opts;

public:
  UnstubTool() : opts(JoveCategory) {}

  int Run(void);
};

JOVE_REGISTER_TOOL("unstub", UnstubTool);

int UnstubTool::Run(void) {
  std::string digest_line;
  std::vector<char> original_contents;

  {
    std::ifstream ifs(opts.Prog);
    if (!ifs.is_open()) {
      WithColor::error() << "failed to open " << opts.Prog << '\n';
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

    auto skip_line = [&](void) -> std::string {
      std::string line;

      if (!std::getline(ifs, line))
        throw std::runtime_error("expected line at line " +
                                 std::to_string(line_no));

      ++line_no;

      return line;
    };

    consume_line("#!/bin/sh");
    consume_line("#");
    consume_line("# NOTE: FILE OVERWRITTEN BY 'jove stub'");
    consume_line("# RESTORE VIA 'jove unstub'");
    consume_line("#");
    (void)skip_line();
    consume_line("");
    digest_line = skip_line();
    consume_line("");

    //
    // read rest of file
    //
    unsigned left = file_len - ifs.tellg();
    original_contents.resize(left);
    ifs.read(&original_contents[0], left);
  }

  if (digest_line.size() < 2 + 32 ||
      digest_line[0] != '#' ||
      digest_line[1] != ' ') {
    WithColor::error() << "invalid digest line. file corruption?\n";
    return 1;
  }

  std::string digest = digest_line.substr(2);
  if (!std::all_of(digest.begin(), digest.end(), ::isxdigit)) {
    WithColor::error() << "invalid digest. file corruption?\n";
    return 1;
  }

  std::string expected_digest =
      crypto::sha3(&original_contents[0], original_contents.size());

  if (digest != expected_digest) {
    WithColor::error() << llvm::formatv("digests do not match; {0} != {1}\n",
                                        digest, expected_digest);
    return 1;
  }

  {
    std::ofstream ofs(opts.Prog,
                      std::ofstream::out
                    | std::ofstream::binary
                    | std::ofstream::trunc);

    if (!ofs) {
      WithColor::error() << "failed to overwrite " << opts.Prog << '\n';
      return 1;
    }

    ofs.write(&original_contents[0], original_contents.size());
  }

  return 0;
}

}
