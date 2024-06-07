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
        Arg("--itrace=bcr");
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

  const std::regex line_regex_ab("\\s*"
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

  const std::regex line_regex_a("\\s*"
                                "(" ADDRSTR ")"
                                "\\s+"
                          "\\(" "(" DSOSTR ")\\+0x(" OFFSTR ")" "\\)"
                                "\\s+"
                                "=>"
                                "\\s+"
                                "0"
                                "\\s+"
                          "\\(" "\\[unknown\\]" "\\)"
  );

  const std::regex line_regex_b("\\s*"
                                "0"
                                "\\s+"
                          "\\(" "\\[unknown\\]" "\\)"
                                "\\s+"
                                "=>"
                                "\\s+"
                                "(" ADDRSTR ")"
                                "\\s+"
                          "\\(" "(" DSOSTR ")\\+0x(" OFFSTR ")" "\\)"
  );

  std::string line;
  while (std::getline(ifs, line)) {
    std::smatch line_match_ab;
    bool ab = std::regex_match(line, line_match_ab, line_regex_ab);

    std::smatch line_match_a;
    bool a = std::regex_match(line, line_match_a, line_regex_a);

    std::smatch line_match_b;
    bool b = std::regex_match(line, line_match_b, line_regex_b);

    if (!ab && !a && !b) {
      WithColor::warning() << llvm::formatv(
          "unrecognized perf script output: \"{0}\"\n", line);
      return 1;
    }

    bool onlyOneTrue = (a && !b && !ab) || (!a && b && !ab) || (!a && !b && ab);
    assert(onlyOneTrue);

    binary_index_t src_BIdx = invalid_binary_index;
    binary_index_t dst_BIdx = invalid_binary_index;

    std::string src_addr_s;
    std::string dst_addr_s;

    std::string src_dso;
    std::string dst_dso;

    std::string src_off_s;
    std::string dst_off_s;

    uint64_t src_off = UINT64_MAX;
    uint64_t dst_off = UINT64_MAX;

    if (ab) {
      assert(line_match_ab.size() == 7);

      src_addr_s = line_match_ab[1].str();
      src_dso    = line_match_ab[2].str();
      src_off_s  = line_match_ab[3].str();
      dst_addr_s = line_match_ab[4].str();
      dst_dso    = line_match_ab[5].str();
      dst_off_s  = line_match_ab[6].str();
    } else if (a) {
      assert(line_match_a.size() == 4);

      src_addr_s = line_match_a[1].str();
      src_dso    = line_match_a[2].str();
      src_off_s  = line_match_a[3].str();
    } else {
      assert(line_match_b.size() == 4);

      dst_addr_s = line_match_b[1].str();
      dst_dso    = line_match_b[2].str();
      dst_off_s  = line_match_b[3].str();
    }

#if 0
    llvm::errs() << llvm::formatv("src_addr_s={0} src_dso={1} src_off_s={2} dst_addr_s={3} dst_dso={4} dst_off_s{5}\n",
                                  src_addr_s, src_dso, src_off_s,
                                  dst_addr_s, dst_dso, dst_off_s);
#endif

    if (!src_dso.empty() && src_dso[0] == '/') src_BIdx = jv.AddFromPath(E, src_dso.c_str()).first; /* TODO [vdso] */
    if (!dst_dso.empty() && dst_dso[0] == '/') dst_BIdx = jv.AddFromPath(E, dst_dso.c_str()).first; /* TODO [vdso] */

    if (!src_off_s.empty()) src_off = strtol(src_off_s.c_str(), nullptr, 16);
    if (!dst_off_s.empty()) dst_off = strtol(dst_off_s.c_str(), nullptr, 16);

    basic_block_index_t src_BBIdx = invalid_basic_block_index;
    basic_block_index_t dst_BBIdx = invalid_basic_block_index;

    auto src_bin = [&](void) -> binary_t & { return jv.Binaries.at(src_BIdx); };
    auto dst_bin = [&](void) -> binary_t & { return jv.Binaries.at(dst_BIdx); };

    if (is_binary_index_valid(src_BIdx)) src_BBIdx = E.explore_basic_block(src_bin(), *state.for_binary(src_bin()).ObjectFile, src_off);
    if (is_binary_index_valid(dst_BIdx)) dst_BBIdx = E.explore_basic_block(dst_bin(), *state.for_binary(dst_bin()).ObjectFile, dst_off);

    if (!is_basic_block_index_valid(src_BBIdx) ||
        !is_basic_block_index_valid(dst_BBIdx))
      continue;

    auto &src_ICFG = src_bin().Analysis.ICFG;
    auto &dst_ICFG = dst_bin().Analysis.ICFG;

    basic_block_t src = basic_block_of_index(src_BBIdx, src_ICFG);
    basic_block_t dst = basic_block_of_index(dst_BBIdx, dst_ICFG);

    uint64_t TermAddr = src_ICFG[src].Term.Addr;

    switch (src_ICFG[src].Term.Type) {
    case TERMINATOR::RETURN:
      src_ICFG[src].Term._return.Returns = true;
      break;

    case TERMINATOR::INDIRECT_CALL:
      src_ICFG[src].insertDynTarget(std::make_pair(dst_BIdx, dst_BBIdx), jv);
      break;

    case TERMINATOR::INDIRECT_JUMP:
      if (src_ICFG[src].Term._indirect_jump.IsLj)
        break;

      if (IsDefinitelyTailCall(src_ICFG, src) || src_BIdx != dst_BIdx) {
        function_index_t FIdx =
            E.explore_function(dst_bin(), *state.for_binary(dst_bin()).ObjectFile,
                               dst_off);

        if (is_function_index_valid(FIdx)) {
          /* term bb may been split */
          src = basic_block_at_address(TermAddr, src_bin());
          assert(src_ICFG[src].Term.Type == TERMINATOR::INDIRECT_JUMP);

          src_ICFG[src].insertDynTarget({dst_BIdx, FIdx}, jv);
        }
      } else {
        assert(src_BIdx == dst_BIdx);

        boost::add_edge(src, dst, src_ICFG);
      }
      break;

    default:
      break;
    }
  }

  return 0;
}

}
