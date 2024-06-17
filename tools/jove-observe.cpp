#include "tool.h"
#include "B.h"
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

#include <oneapi/tbb/parallel_pipeline.h>

#include <llvm/Support/FormatVariadic.h>

#include <regex>

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

namespace {

struct binary_state_t {
  std::unique_ptr<llvm::object::Binary> Bin;
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

  std::string buffer;
  std::regex line_regex_ab;
  std::regex line_regex_a;
  std::regex line_regex_b;

public:
  ObserveTool()
      : opts(JoveCategory), E(jv, disas, tcg, false /* opts.VeryVerbose */) {}

  int Run(void) override;

  binary_index_t BinaryFromName(const char *name);
  std::string GetLine(int rfd, tbb::flow_control &);
  void ProcessLine(const std::string &line);
  void on_new_binary(binary_t &);
  void init_state_for_binary(binary_t &);
};

JOVE_REGISTER_TOOL("observe", ObserveTool);

void ObserveTool::init_state_for_binary(binary_t &b) {
  binary_state_t &x = state.for_binary(b);

  x.Bin = B::Create(b.data());
}

void ObserveTool::on_new_binary(binary_t &b) {
  state.update();

  b.IsDynamicallyLoaded = true;

  init_state_for_binary(b);

  if (IsVerbose())
    llvm::errs() << llvm::formatv("added {0}\n", b.Name.c_str());
}

binary_index_t ObserveTool::BinaryFromName(const char *name) {
  using namespace std::placeholders;

  auto MaybeBIdxSet = jv.Lookup(name);
  if (MaybeBIdxSet) {
    const ip_binary_index_set &BIdxSet = *MaybeBIdxSet;

    assert(!BIdxSet.empty());

    binary_index_t BIdx = *BIdxSet.rbegin(); /* most recent (XXX?) */
    assert(is_binary_index_valid(BIdx));

    return BIdx;
  }

  bool IsNew;
  binary_index_t BIdx;

  std::tie(BIdx, IsNew) =
      jv.AddFromPath(E, name, invalid_binary_index,
                     std::bind(&ObserveTool::on_new_binary, this, _1));

  return BIdx;
}

int ObserveTool::Run(void) {
  using namespace std::placeholders;

  if (fs::exists("perf.data"))
    fs::remove("perf.data");

  const std::string perf_path = locator().perf();
  const std::string prog_path = fs::canonical(opts.Prog).string();
  const std::string stdout_path = temporary_dir() + "/perf.stdout.txt";

  for_each_binary(std::execution::par_unseq, jv,
                  [&](binary_t &b) { init_state_for_binary(b); });

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

  int pipefd[2];
  if (::pipe(pipefd) < 0) { /* first, create a pipe */
    int err = errno;
    die("pipe(2) failed: " + std::string(strerror(err)));
  }

  int rfd = pipefd[0];
  int wfd = pipefd[1];

  pid_t pid = jove::RunExecutable(
      perf_path,
      [&](auto Arg) {
        Arg(perf_path);

        Arg("script");
        Arg("--itrace=bcr");
        Arg("-F");
        Arg("ip,addr,dso,dsoff");
      }, "", "",
      [&](const char **argv, const char **envp) {
        ::close(rfd);
        ::dup2(wfd, STDOUT_FILENO);
        ::close(wfd);
      });
  ::close(wfd);

//#define DSOSTR "[/a-zA-Z0-9.]+"
#define DSOSTR ".*?"
#define OFFSTR "[0-9a-f]+"
#define ADDRSTR OFFSTR

  line_regex_ab = std::regex(    "\\s*"
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

  line_regex_a = std::regex(    "\\s*"
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

  line_regex_b = std::regex(    "\\s*"
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

  tbb::parallel_pipeline(
      1024, tbb::make_filter<void, std::string>(
                tbb::filter_mode::serial_in_order,
                std::bind(&ObserveTool::GetLine, this, rfd, _1)) &
                tbb::make_filter<std::string, void>(
                    tbb::filter_mode::serial_in_order,
                    std::bind(&ObserveTool::ProcessLine, this, _1)));

  //
  // wait for process to exit
  //
  int ret_val = WaitForProcessToExit(pid);

  ::close(rfd);

  return ret_val;
}

std::string ObserveTool::GetLine(int rfd, tbb::flow_control &fc) {
  //
  // is there already a line ready to process?
  //
  size_t pos;
  while ((pos = buffer.find('\n')) != std::string::npos) {
    std::string line = buffer.substr(0, pos);
    buffer.erase(0, pos + 1);
    return line;
  }

  char temp_buffer[256];
  while (true) {
    ssize_t count = read(rfd, temp_buffer, sizeof(temp_buffer) - 1);
    if (count < 0) {
      int err = errno;
      die("read of pipe failed: " + std::string(strerror(err)));
    }

    if (count == 0) {
      std::string result = buffer;
      buffer.clear();

      llvm::errs() << "STOPPPING\n";
      fc.stop();
      return result;
    } else {
      temp_buffer[count] = '\0';
      buffer.append(temp_buffer, count);

      while ((pos = buffer.find('\n')) != std::string::npos) {
        std::string line = buffer.substr(0, pos);
        buffer.erase(0, pos + 1);
        return line;
      }
    }
  }
}

void ObserveTool::ProcessLine(const std::string &line) {
  if (line.empty())
    return;

  if (IsVeryVerbose())
    llvm::errs() << line << '\n';

/*
     7f65c6213a29 (/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2+0x1ba29) =>     7f65c6212040 (/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2+0x1a040)
*/

  {
    std::smatch line_match_ab;
    bool ab = std::regex_match(line, line_match_ab, line_regex_ab);

    std::smatch line_match_a;
    bool a = std::regex_match(line, line_match_a, line_regex_a);

    std::smatch line_match_b;
    bool b = std::regex_match(line, line_match_b, line_regex_b);

    if (!ab && !a && !b) {
      if (IsVeryVerbose())
        WithColor::warning() << llvm::formatv(
            "unrecognized perf script output: \"{0}\"\n", line);
      return;
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

    uint64_t src_off = 0;
    uint64_t dst_off = 0;

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

    if (!src_off_s.empty()) src_off = strtol(src_off_s.c_str(), nullptr, 16);
    if (!dst_off_s.empty()) dst_off = strtol(dst_off_s.c_str(), nullptr, 16);

    if (!src_dso.empty() && src_off != 0x0 && src_dso[0] == '/') src_BIdx = BinaryFromName(src_dso.c_str());
    if (!dst_dso.empty() && dst_off != 0x0 && dst_dso[0] == '/') dst_BIdx = BinaryFromName(dst_dso.c_str());

    basic_block_index_t src_BBIdx = invalid_basic_block_index;
    basic_block_index_t dst_BBIdx = invalid_basic_block_index;

    auto _src_bin = [&](void) -> binary_t & { return jv.Binaries.at(src_BIdx); };
    auto _dst_bin = [&](void) -> binary_t & { return jv.Binaries.at(dst_BIdx); };

    auto explore = [&](binary_t &b, llvm::object::Binary &Bin, uint64_t off) -> void {
      E.explore_basic_block(b, Bin, B::va_of_offset(Bin, off));
    };

    try {
      if (is_binary_index_valid(src_BIdx)) { binary_t &src_bin = _src_bin(); explore(src_bin, *state.for_binary(src_bin).Bin, src_off); }
      if (is_binary_index_valid(dst_BIdx)) { binary_t &dst_bin = _dst_bin(); explore(dst_bin, *state.for_binary(dst_bin).Bin, dst_off); }
    } catch (const g2h_exception &e) {
      if (IsVeryVerbose()) llvm::errs() << llvm::formatv("invalid address {0}\n", taddr2str(e.pc, false));
      return;
    } catch (const invalid_control_flow_exception &invalid_cf) {
      if (IsVeryVerbose()) llvm::errs() << llvm::formatv("invalid control-flow to {0}\n", taddr2str(invalid_cf.pc, false));
      return;
    }

    if (!is_basic_block_index_valid(src_BBIdx) ||
        !is_basic_block_index_valid(dst_BBIdx))
      return;

    binary_t &src_bin = _src_bin();
    binary_t &dst_bin = _dst_bin();

    auto &src_ICFG = src_bin.Analysis.ICFG;
    auto &dst_ICFG = dst_bin.Analysis.ICFG;

    basic_block_t src = basic_block_of_index(src_BBIdx, src_ICFG);
    basic_block_t dst = basic_block_of_index(dst_BBIdx, dst_ICFG);

    auto bbprop = [&](binary_t &b, basic_block_t bb) -> basic_block_properties_t & {
      icfg_t &ICFG = b.Analysis.ICFG;

      ip_sharable_lock<ip_upgradable_mutex> s_lck(b.bbmap_mtx);

      return ICFG[bb];
    };

    const taddr_t TermAddr = bbprop(src_bin, src).Term.Addr;

    auto handle_indirect_call = [&](void) -> void {
      function_index_t FIdx = E.explore_function(
          dst_bin, *state.for_binary(dst_bin).Bin, dst_off);

      if (!is_function_index_valid(FIdx))
        return;

      ip_upgradable_lock<ip_upgradable_mutex> u_lck(src_bin.bbmap_mtx);

      src = basic_block_at_address(TermAddr, src_bin);
      basic_block_properties_t &src_bbprop = bbprop(src_bin, src);

      ip_scoped_lock<ip_upgradable_mutex> e_lck(boost::move(u_lck));

      src_bbprop.insertDynTarget(std::make_pair(dst_BIdx, FIdx), jv);
    };

    basic_block_properties_t &src_bbprop = bbprop(src_bin, src);

    switch (src_bbprop.Term.Type) {
    case TERMINATOR::RETURN:
      src_bbprop.Term._return.Returns = true;
      break;

    case TERMINATOR::INDIRECT_CALL:
      handle_indirect_call();
      break;

    case TERMINATOR::INDIRECT_JUMP:
      if (src_bbprop.Term._indirect_jump.IsLj)
        break;

      if (IsDefinitelyTailCall(src_ICFG, src) || src_BIdx != dst_BIdx) {
        handle_indirect_call();
      } else {
        assert(src_BIdx == dst_BIdx);

        ip_scoped_lock<ip_upgradable_mutex> e_lck(src_bin.bbmap_mtx);

        boost::add_edge(src, dst, src_ICFG);
      }
      break;

    default:
      break;
    }
  }
}

}
