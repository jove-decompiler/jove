#include "tool.h"
#include "elf.h"
#include "tcg.h"
#include "disas.h"
#include "explore.h"
#include "crypto.h"
#include "util.h"
#include "vdso.h"
#include "symbolizer.h"
#include "locator.h"
#include "jove_macros.h"

#include <boost/filesystem.hpp>

#include <llvm/Support/FormatVariadic.h>

#include <regex>

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

namespace {

struct binary_state_t {
  fnmap_t fnmap;
  bbmap_t bbmap;

  uintptr_t LoadAddr = std::numeric_limits<uintptr_t>::max();
  uintptr_t LoadOffset = std::numeric_limits<uintptr_t>::max();

  std::unique_ptr<llvm::object::Binary> ObjectFile;
};

}

struct ObserveTool : public TransformerTool_Bin<binary_state_t> {
  struct Cmdline {
    cl::opt<std::string> Prog;
    cl::list<std::string> Args;
    cl::list<std::string> Envs;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Prog(cl::Positional, cl::desc("prog"), cl::Required,
               cl::value_desc("filename"), cl::cat(JoveCategory)),

          Args("args", cl::CommaSeparated, cl::ConsumeAfter,
               cl::desc("<program arguments>..."), cl::cat(JoveCategory)),

          Envs("env", cl::CommaSeparated,
               cl::value_desc("KEY_1=VALUE_1,KEY_2=VALUE_2,...,KEY_n=VALUE_n"),
               cl::desc("Extra environment variables"), cl::cat(JoveCategory))
          {}
  } opts;

  tiny_code_generator_t tcg;
  disas_t disas;
  explorer_t E;
  symbolizer_t symbolizer;

public:
  ObserveTool()
      : opts(JoveCategory), E(jv, disas, tcg, false /* opts.VeryVerbose */) {}

  int Run(void) override;
};

JOVE_REGISTER_TOOL("observe", ObserveTool);

int ObserveTool::Run(void) {
  if (fs::exists("perf.data"))
    fs::remove("perf.data");

  const std::string perf_path = locator().perf();
  const std::string prog_path = fs::canonical(opts.Prog).string();
  const std::string stdout_path = temporary_dir() + "/perf.stdout.txt";

  for_each_binary(jv, [&](binary_t &binary) {
    ignore_exception([&]() {
      state.for_binary(binary).ObjectFile = CreateBinary(binary.data());
    });

    construct_fnmap(jv, binary, state.for_binary(binary).fnmap);
    construct_bbmap(jv, binary, state.for_binary(binary).bbmap);
  });

  RunExecutableToExit(
      perf_path,
      [&](auto Arg) {
        Arg(perf_path);

        Arg("record");
        Arg("-e");
        Arg("intel_pt/branch=1,mtc=0,cyc=0,tsc=0,ptw=0/u");

        Arg(opts.Prog);

        for (const std::string &s : opts.Args)
          Arg(s);
      },
      [&](auto Env) {
        InitWithEnviron(Env);

        for (const std::string &s : opts.Envs)
          Env(s);
      });

  RunExecutableToExit(
      perf_path,
      [&](auto Arg) {
        Arg(perf_path);

        Arg("script");
        Arg("--itrace=c");
        Arg("-F");
        Arg("ip,addr,dso,dsoff");
      },
      stdout_path);

  std::ifstream ifs(stdout_path.c_str());

//#define DSOSTR "[/a-zA-Z0-9.]+"
#define DSOSTR ".*?"
#define OFFSTR "[0-9a-f]+"
#define ADDRSTR OFFSTR

/*
     7f65c6213a29 (/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2+0x1ba29) =>     7f65c6212040 (/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2+0x1a040)
*/

  const std::regex line_regex("\\s*"
                              "(" ADDRSTR ")"
                              "\\s+"
                        "\\(" "(" DSOSTR ")\\+0x(" OFFSTR ")" "\\)"
                              "\\s+"
                              "=>"
                              "\\s+"
                              "(" ADDRSTR ")"
                              "\\s+"
                        "\\(" "(" DSOSTR ")\\+0x(" OFFSTR ")" "\\)"
  );

  std::string line;
  while (std::getline(ifs, line)) {
    std::smatch line_match;

    if (!std::regex_match(line, line_match, line_regex))
      continue;
    if (line_match.size() != 7) {
      WithColor::warning() << llvm::formatv(
          "unrecognized perf script output ({1}): \"{0}\"\n", line,
          line_match.size());

      for (unsigned i = 0; i < line_match.size(); ++i) {
        llvm::errs() << "\"" << line_match[i] << "\"\n";
      }
      return 1;
      //continue;
    }

    std::string src_addr_s = line_match[1].str();
    std::string src_dso    = line_match[2].str();
    std::string src_off_s  = line_match[3].str();
    std::string dst_addr_s = line_match[4].str();
    std::string dst_dso    = line_match[5].str();
    std::string dst_off_s  = line_match[6].str();

    llvm::errs() << llvm::formatv("{0} {1} {2} {3} {4} {5}\n",
                                  src_addr_s, src_dso, src_off_s,
                                  dst_addr_s, dst_dso, dst_off_s);

    binary_index_t src_BIdx = jv.Lookup(src_dso.c_str());
    binary_index_t dst_BIdx = jv.Lookup(dst_dso.c_str());

    if (!is_binary_index_valid(src_BIdx))
      continue;
    if (!is_binary_index_valid(dst_BIdx))
      continue;

    binary_t &src = jv.Binaries[src_BIdx];
    binary_t &dst = jv.Binaries[dst_BIdx];

    uint64_t src_off = strtol(src_off_s.c_str(), nullptr, 16);
    uint64_t dst_off = strtol(dst_off_s.c_str(), nullptr, 16);

    E.explore_basic_block(src, *state.for_binary(src).ObjectFile, src_off,
                          state.for_binary(src).fnmap,
                          state.for_binary(src).bbmap);

    E.explore_basic_block(dst, *state.for_binary(dst).ObjectFile, dst_off,
                          state.for_binary(dst).fnmap,
                          state.for_binary(dst).bbmap);
  }

  return 0;
}

}
