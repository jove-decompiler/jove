#if defined(__x86_64__) && (defined(TARGET_X86_64) || defined(TARGET_I386))
#include "tool.h"
#include "B.h"
#include "tcg.h"
#include "disas.h"
#include "explore.h"
#include "util.h"
#include "symbolizer.h"
#include "locator.h"
#include "reference_ipt.h"
#include "afl_ipt.h"
#include "wine.h"
#include "perf.h"
#include "sideband.h"
#include "glibc.h"
#include "pipe.h"
#include "hash.h"
#include "objdump.h"
#include "reflink.h"
#include "augmented_raw_syscalls.h"

#include <tbb/flow_graph.h>

#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/unordered/unordered_flat_map.hpp>
#include <boost/unordered/unordered_flat_set.hpp>
#include <boost/scope/defer.hpp>

#include <oneapi/tbb/parallel_pipeline.h>
#include <oneapi/tbb/parallel_for_each.h>

#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

#include <regex>
#include <memory>
#include <mutex>

#include <liburing.h>

#include <intel-pt.h>
#include <libipt-sb.h>
extern "C" {
#include "pevent.h"
}

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

namespace {

struct binary_state_t {
  std::unique_ptr<llvm::object::Binary> Bin;

  binary_state_t(const binary_t &b) { Bin = B::Create(b.data()); }
};

}

typedef boost::interprocess::flat_map<
    addr_intvl, basic_block_index_t, addr_intvl_cmp,
    boost::interprocess::allocator<std::pair<addr_intvl, basic_block_index_t>,
                                   segment_manager_t>>
    addrspace_t;

struct IPTTool : public StatefulJVTool<ToolKind::Standard, binary_state_t, void, void> {
  struct Cmdline {
    cl::opt<std::string> Prog;
    cl::list<std::string> Args;
    cl::list<std::string> Envs;
    cl::opt<bool> UsePerfScript;
    cl::opt<std::string> Decoder;
    cl::opt<bool> Chdir;
    cl::alias ChdirAlias;
    cl::opt<std::string> MMapPages;
    cl::alias MMapPagesAlias;
    cl::opt<std::string> AuxPages;
    cl::alias AuxPagesAlias;
    cl::opt<bool> ExistingPerfData;
    cl::opt<bool> RunPerfWithSudo;
    cl::opt<bool> RunAsUser;
    cl::opt<bool> Cache;
    cl::opt<bool> Objdump;
    cl::opt<bool> Serial;
    cl::alias SerialAlias;
    cl::opt<bool> ExeOnly;
    cl::alias ExeOnlyAlias;
    cl::opt<bool> GatherBins;
    cl::opt<bool> JustGatherBins;
    cl::opt<bool> MT;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Prog(cl::Positional, cl::desc("prog"), cl::Required,
               cl::value_desc("filename"), cl::cat(JoveCategory)),

          Args("args", cl::CommaSeparated, cl::ConsumeAfter,
               cl::desc("<program arguments>..."), cl::cat(JoveCategory)),

          Envs("env", cl::CommaSeparated,
               cl::value_desc("KEY_1=VALUE_1,KEY_2=VALUE_2,...,KEY_n=VALUE_n"),
               cl::desc("Extra environment variables"), cl::cat(JoveCategory)),

          UsePerfScript("use-perf-script",
                        cl::desc("Use 'perf script' to parse trace. Otherwise "
                                 "libipt is used."),
                        cl::init(false), cl::cat(JoveCategory)),

          Decoder("decoder",
                  cl::desc("Select decoder (reference, afl, simple)."),
                  cl::init("reference"), cl::cat(JoveCategory)),

          Chdir("change-dir", cl::desc("chdir(2) into temporary directory."),
                cl::init(true), cl::cat(JoveCategory)),

          ChdirAlias("c", cl::desc("Alias for --change-dir"),
                     cl::aliasopt(Chdir), cl::cat(JoveCategory)),

          MMapPages("mmap-pages",
                    cl::desc("Number of mmap pages for trace data"),
                    cl::init("16M"), cl::cat(JoveCategory)),

          MMapPagesAlias("m", cl::desc("Alias for --mmap-pages"),
                         cl::aliasopt(MMapPages), cl::cat(JoveCategory)),

          AuxPages("mmap-pages-aux",
                   cl::desc("Number of mmap pages for trace data (AUX)"),
                   cl::init("64M"), cl::cat(JoveCategory)),

          AuxPagesAlias("a", cl::desc("Alias for --mmap-pages-aux"),
                        cl::aliasopt(AuxPages), cl::cat(JoveCategory)),

          ExistingPerfData("existing-perf-data",
                           cl::desc("Use perf.data* files already existing in "
                                    "the current directory."),
                           cl::cat(JoveCategory)),

          RunPerfWithSudo("sudo",
                          cl::desc("Execute perf as superuser via sudo -E"),
                          cl::init(true), cl::cat(JoveCategory)),

          RunAsUser("user",
                    cl::desc("Execute app as user running sudo (this option is "
                             "associated with the --sudo option, and "
                             "essentially involves executing sudo twice)"),
                    cl::init(true), cl::cat(JoveCategory)),

          Cache("cache", cl::desc("Cache graph."), cl::init(true),
                cl::cat(JoveCategory)),

          Objdump(
              "objdump",
              cl::desc(
                  "Run objdump and treat output as authoritative."),
              cl::init(true), cl::cat(JoveCategory)),

          Serial(
              "serial",
              cl::desc("Process perf.data serially"),
              cl::cat(JoveCategory)),

          SerialAlias("s", cl::desc("Alias for --serial."),
                       cl::aliasopt(Serial), cl::cat(JoveCategory)),

          ExeOnly("exe-only",
              cl::desc("Only care about exe addresses."),
              cl::cat(JoveCategory), cl::init(true)),

          ExeOnlyAlias("x", cl::desc("Alias for --exe-only."),
                       cl::aliasopt(ExeOnly), cl::cat(JoveCategory)),

          GatherBins("gather-bins",
                     cl::desc("Look ahead in sideband records to add binaries early on."),
                     cl::init(false), cl::cat(JoveCategory)),

          JustGatherBins("just-gather-bins",
                     cl::desc("Only do --gather-bins."),
                     cl::cat(JoveCategory)),

          MT("mt", cl::desc("Operate on multi-threaded jv"), cl::cat(JoveCategory)) {}
  } opts;

  template <typename T>
  using unordered_set = boost::unordered::unordered_flat_set<T>;

  AddOptions_t AddOptions;

  const bool IsCOFF;

  std::string perf_path;

  symbolizer_t symbolizer;

  std::unique_ptr<tiny_code_generator_t> TCG;
  std::unique_ptr<disas_t> Disas;
  std::unique_ptr<explorer_t> Explorer;

  std::string buff;
  std::regex line_regex_ab;
  std::regex line_regex_a;
  std::regex line_regex_b;

  void gather_all_perf_data_files(std::vector<std::string> &out);
  void gather_perf_data_aux_files(std::vector<std::pair<unsigned, std::string>> &out);

  static constexpr const char *sb_filename = "perf.data-sideband.pevent";
  static constexpr const char *opts_filename = "perf.data.opts";

public:
  IPTTool()
      : opts(JoveCategory),
        IsCOFF(B::is_coff(*state.for_binary(jv.Binaries.at(0)).Bin)) {}

  int Run(void) override;

  int UsingPerfScript(void);
  int UsingLibipt(void);

  binary_index_t BinaryFromName(const char *name);
  std::string GetLine(int rfd, tbb::flow_control &);
  void ProcessLine(const std::string &line);

  void on_new_binary(binary_t &);

  void gather_binaries(explorer_t &explorer,
                       const perf::data_reader<false> &sb,
                       const perf::sideband_parser &sb_parser);
};

JOVE_REGISTER_TOOL("ipt", IPTTool);

void IPTTool::on_new_binary(binary_t &b) {
  b.IsDynamicallyLoaded = true;

  if (IsVerbose())
    llvm::errs() << llvm::formatv("added {0}\n", b.Name.c_str());
}

binary_index_t IPTTool::BinaryFromName(const char *name) {
  using namespace std::placeholders;

  binary_index_set BIdxSet;
  if (jv.LookupByName(name, BIdxSet)) {
    assert(!BIdxSet.empty());

    binary_index_t BIdx = *BIdxSet.rbegin(); /* most recent (XXX?) */
    assert(is_binary_index_valid(BIdx));

    return BIdx;
  }

  bool IsNew;
  binary_index_t BIdx;

  std::tie(BIdx, IsNew) =
      jv.AddFromPath(*Explorer, jv_file, name,
                     std::bind(&IPTTool::on_new_binary, this, _1), AddOptions);

  if (IsVeryVerbose() && !is_binary_index_valid(BIdx))
    HumanOut() << llvm::formatv("failed to add \"{0}\"\n", name);

  return BIdx;
}

int IPTTool::Run(void) {
  perf_path = locator().perf();

  if (!opts.ExistingPerfData && opts.Chdir) {
    if (::chdir(temporary_dir().c_str()) < 0) {
      int err = errno;

      throw std::runtime_error(std::string("chdir failed: ") + strerror(err));
    }
  }

  if (opts.ExistingPerfData) {
    if (!fs::exists("perf.data")) {
      WithColor::error() << "perf.data does not exist\n";
      return 1;
    }
  } else if (fs::exists("perf.data")) {
    std::vector<std::string> filenames;
    gather_all_perf_data_files(filenames);

    for (const auto &filename : filenames) {
      if (IsVerbose())
        WithColor::note() << llvm::formatv("removing {0}\n", filename);

      fs::remove(filename);
    }
  }

  TCG = std::make_unique<tiny_code_generator_t>();
  Disas = std::make_unique<disas_t>();
  Explorer = std::make_unique<explorer_t>(*Disas, *TCG, VerbosityLevel());

  const std::string prog_path = fs::canonical(opts.Prog).string();

  std::string sudo_path = locator().sudo();
  const unsigned gid = ::getgid();
  const unsigned uid = ::getuid();

  if (!opts.ExistingPerfData) {
    if (int ret = RunExecutableToExit(
      opts.RunPerfWithSudo ? sudo_path : perf_path,
      [&](auto Arg) {
        if (opts.RunPerfWithSudo) {
          Arg(sudo_path);
          Arg("-E");
        }
        Arg(perf_path);

        Arg("record");
        Arg("-m" + opts.MMapPages);
        Arg("-m," + opts.AuxPages);
        Arg("-o");
        Arg("perf.data");
        Arg("-e");
        Arg("intel_pt/cyc,noretcomp/u");
        if (opts.RunPerfWithSudo) {
          //
          // to trace raw system calls we need to be superuser
          //
          Arg("--jove_syscalls");
        }

        if (opts.RunAsUser) {
          Arg("sudo");

          Arg("-E");
          Arg("-u");
          Arg("#" + std::to_string(uid));
          Arg("-g");
          Arg("#" + std::to_string(gid));
        }

        if (IsCOFF)
          Arg(locator().wine(IsTarget32));

        Arg(opts.Prog);

        for (const std::string &s : opts.Args)
          Arg(s);
      },
      [&](auto Env) {
        InitWithEnviron(Env);

        for (const std::string &s : opts.Envs)
          Env(s);

        SetupEnvironForRun(Env);

#if 0
        //
        // wine sometimes read(2)'s binaries into memory rather than mmap(2)'ing
        // them. this causes trouble- we need to use WINEDEBUG=+loaddll,+process
        // module to get wine to tell us the load addresses of sections of
        // binaries so we can make sense of the addresses we get back from the
        // trace.
        //
        if (IsCOFF)
          Env("WINEDEBUG=+loaddll,+process");
#endif
      })) {
      WithColor::error() << "perf failed\n";
      return ret;
    }
  }

  //
  // if we ran perf as root, perf.data will be unusable unless we chown it
  //
  if (opts.RunPerfWithSudo)
  RunExecutableToExit(
      sudo_path,
      [&](auto Arg) {
        Arg(sudo_path);

        Arg("chown");
        Arg(std::to_string(uid) + ":" + std::to_string(gid));
        Arg("perf.data");
    });

  if (opts.UsePerfScript)
    return UsingPerfScript();
  else
    return UsingLibipt();
}

int IPTTool::UsingPerfScript(void) {
#if 0
  if (int ret = ProcessAppStderr())
    return ret;
#endif

  using namespace std::placeholders;

  int pipefd[2];
  if (::pipe(pipefd) < 0) { /* first, create a pipe */
    int err = errno;
    die("pipe(2) failed: " + std::string(strerror(err)));
  }

  auto rfd = std::make_unique<scoped_fd>(pipefd[0]);
  auto wfd = std::make_unique<scoped_fd>(pipefd[1]);

  pid_t pid = RunExecutable(
      perf_path,
      [&](auto Arg) {
        Arg(perf_path);

        Arg("script");
        Arg("--itrace=bcr");
        Arg("-F");
        Arg("ip,addr,dso,dsoff");
      }, "", "",
      [&](const char **argv, const char **envp) {
        rfd.reset();
        ::dup2(wfd->get(), STDOUT_FILENO);
        wfd.reset();
      });
  wfd.reset();

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
                std::bind(&IPTTool::GetLine, this, rfd->get(), _1)) &
                tbb::make_filter<std::string, void>(
                    tbb::filter_mode::serial_in_order,
                    std::bind(&IPTTool::ProcessLine, this, _1)));

  //
  // wait for process to exit
  //
  int ret_val = WaitForProcessToExit(pid);

  rfd.reset();

  return ret_val;
}

std::string IPTTool::GetLine(int rfd, tbb::flow_control &fc) {
  char tmp_buff[4096];

  std::string res;
  for (;;) {
    // do we have a line ready to go?
    ssize_t pos;
    if ((pos = buff.find('\n')) != std::string::npos) {
      res = buff.substr(0, pos);
      buff.erase(0, pos + 1);
      break;
    }

    ssize_t ret;
    do
      ret = ::read(rfd, tmp_buff, sizeof(tmp_buff));
    while (ret < 0 && errno == EINTR);

    if (ret < 0)
      die("failed to read pipe: " + std::string(strerror(errno)));

    if (ret == 0) {
      fc.stop();
      break;
    }

    buff.append(tmp_buff, ret);
  }

  return res;
}

void IPTTool::ProcessLine(const std::string &line) {
  if (line.empty())
    return;

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

    if (!src_off_s.empty()) src_off = strtoul(src_off_s.c_str(), nullptr, 16);
    if (!dst_off_s.empty()) dst_off = strtoul(dst_off_s.c_str(), nullptr, 16);

    if (!src_dso.empty() && src_off != 0x0 && src_dso[0] == '/') src_BIdx = BinaryFromName(src_dso.c_str());
    if (!dst_dso.empty() && dst_off != 0x0 && dst_dso[0] == '/') dst_BIdx = BinaryFromName(dst_dso.c_str());

    basic_block_index_t src_BBIdx = invalid_basic_block_index;
    basic_block_index_t dst_BBIdx = invalid_basic_block_index;

    auto _src_bin = [&](void) -> binary_t & { return jv.Binaries.at(src_BIdx); };
    auto _dst_bin = [&](void) -> binary_t & { return jv.Binaries.at(dst_BIdx); };

    taddr_t dst_va, src_va;
    try {
      /* we know dst is the start of a block */
      if (is_binary_index_valid(dst_BIdx)) {
        binary_t &dst_bin = _dst_bin();
        auto &Bin = *state.for_binary(dst_bin).Bin;
        dst_va = B::va_of_offset(Bin, dst_off);

        Explorer->explore_basic_block(dst_bin, Bin, dst_va);
      }

      /* if there isn't a block at src we'll start one. */
      if (is_binary_index_valid(src_BIdx)) {
        binary_t &src_bin = _src_bin();
        auto &Bin = *state.for_binary(src_bin).Bin;
        src_va = B::va_of_offset(Bin, src_off);

        bool ExistsBlock = ({
          auto s_lck = src_bin.BBMap.shared_access();

          exists_basic_block_at_address(src_va, src_bin);
        });

        if (!ExistsBlock)
          Explorer->explore_basic_block(src_bin, Bin, src_va);
      }
    } catch (const invalid_control_flow_exception &invalid_cf) {
      if (IsVerbose())
        llvm::errs() << llvm::formatv("invalid control-flow to {0} in \"{1}\"\n",
                                      taddr2str(invalid_cf.pc, false),
                                      invalid_cf.name_of_binary);
      return;
    } catch (const std::exception &e) {
      if (IsVerbose())
        llvm::errs() << llvm::formatv("exception! {0}\n", e.what());
      return;
    }

    if (!is_basic_block_index_valid(src_BBIdx) ||
        !is_basic_block_index_valid(dst_BBIdx))
      return;

    binary_t &src_bin = _src_bin();
    binary_t &dst_bin = _dst_bin();

    auto &src_ICFG = src_bin.Analysis.ICFG;
    auto &dst_ICFG = dst_bin.Analysis.ICFG;

    basic_block_t dst = basic_block_of_index(dst_BBIdx, dst_ICFG);

    const auto Term = ({
      auto s_lck = src_bin.BBMap.shared_access();

      src_ICFG[basic_block_at_address(src_va, src_bin)].Term;
    });

    auto handle_indirect_call = [&](void) -> void {
      function_index_t FIdx;
      try {
        FIdx = Explorer->explore_function(
            dst_bin, *state.for_binary(dst_bin).Bin, dst_off);
      } catch (const invalid_control_flow_exception &invalid_cf) {
        if (IsVerbose())
          llvm::errs() << llvm::formatv("invalid control-flow to {0} in \"{1}\"\n",
                                        taddr2str(invalid_cf.pc, false),
                                        invalid_cf.name_of_binary);
        return;
      }

      if (!is_function_index_valid(FIdx))
        return;

      auto s_lck = src_bin.BBMap.shared_access();

      basic_block_t src = basic_block_at_address(Term.Addr, src_bin);
      basic_block_properties_t &src_bbprop = src_ICFG[src];

      src_bbprop.insertDynTarget(src_BIdx, std::make_pair(dst_BIdx, FIdx),
                                 jv_file, jv);
    };

    switch (Term.Type) {
    case TERMINATOR::RETURN: {
      {
        auto s_lck = src_bin.BBMap.shared_access();

        src_ICFG[basic_block_at_address(src_va, src_bin)].Term._return.Returns = true;
      }

      const taddr_t before_pc = dst_va - 1 - IsMIPSTarget * 4;

      auto s_lck = dst_bin.BBMap.shared_access();

      basic_block_t before_bb = basic_block_at_address(before_pc, dst_bin);
      basic_block_properties_t &before_bbprop = dst_ICFG[before_bb];
      auto &before_Term = before_bbprop.Term;

      bool isCall = before_Term.Type == TERMINATOR::CALL;
      bool isIndirectCall = before_Term.Type == TERMINATOR::INDIRECT_CALL;
      if (isCall || isIndirectCall) {
        assert(dst_ICFG.out_degree(before_bb) <= 1);

        if (isCall) {
          if (likely(is_function_index_valid(before_Term._call.Target)))
            dst_bin.Analysis.Functions.at(before_Term._call.Target).Returns = true;
        }

        dst_ICFG.add_edge(before_bb, dst); /* connect */
      }

      break;
    }

    case TERMINATOR::INDIRECT_CALL:
      handle_indirect_call();
      break;

    case TERMINATOR::INDIRECT_JUMP: {
      if (Term._indirect_jump.IsLj)
        break;

      const bool TailCall = ({
        auto s_lck = src_bin.BBMap.shared_access();

        IsDefinitelyTailCall(src_ICFG, basic_block_at_address(src_va, src_bin));
      });

      if (TailCall || src_BIdx != dst_BIdx) {
        handle_indirect_call();
      } else {
        assert(src_BIdx == dst_BIdx);

        auto e_lck = src_bin.BBMap.exclusive_access();

        src_ICFG.add_edge(basic_block_at_address(src_va, src_bin), dst);
      }
      break;
    }

    default:
      break;
    }
  }
}

int IPTTool::UsingLibipt(void) {
  fs::path libipt_scripts_dir = locator().libipt_scripts();

  bool Failed = false;

  if (!opts.ExistingPerfData) {
    perf::data_reader<true> perf_data("perf.data");

#define OUR_IOURING_INIT(ringp)                                                \
  do {                                                                         \
    if (io_uring_queue_init(1024, ringp, 0) < 0) {                             \
      int err = errno;                                                         \
      WithColor::error() << llvm::formatv(                                     \
          "io_uring_queue_init() failed: {0}\n", strerror(errno));             \
      WeFailed = true;                                                         \
      return;                                                                  \
    }                                                                          \
  } while (false)

#define OUR_IOURING_QUEUE_WRITE(ringp, fd, buf, nbytes, offset)                \
  ({                                                                           \
    int submitted = 0;                                                         \
    bool TriedAgain = false;                                                   \
    struct io_uring_sqe *sqe;                                                  \
    for (;;) {                                                                 \
      sqe = io_uring_get_sqe(ringp);                                           \
      if (sqe)                                                                 \
        break; /* success */                                                   \
      if (!TriedAgain) {                                                       \
        TriedAgain = true;                                                     \
                                                                               \
        submitted = io_uring_submit(ringp);                                    \
        if (submitted < 0) {                                                   \
          WithColor::error() << llvm::formatv(                                 \
              "io_uring_submit() failed: {0}\n", strerror(-submitted));        \
          return false;                                                        \
        }                                                                      \
        continue;                                                              \
      }                                                                        \
      WithColor::error() << "Could not get submission queue entry\n";          \
      return false;                                                            \
    }                                                                          \
    io_uring_prep_write(sqe, fd, buf, nbytes, offset);                         \
    submitted;                                                                 \
  })

#define OUR_IOURING_SUBMIT_AND_WAIT(ringp, num)                                \
  do {                                                                         \
    assert(num >= 0);                                                          \
    int ret = io_uring_submit(ringp);                                          \
    if (ret < 0) {                                                             \
      WithColor::error() << llvm::formatv("io_uring_submit() failed: {0}\n",   \
                                          strerror(-ret));                     \
      WeFailed = true;                                                         \
      return;                                                                  \
    }                                                                          \
                                                                               \
    for (size_t i = 0; i < num; ++i) {                                         \
      struct io_uring_cqe *cqe;                                                \
      int ret = io_uring_wait_cqe(&ring, &cqe);                                \
      if (ret < 0) {                                                           \
        WithColor::error() << llvm::formatv(                                   \
            "io_uring_wait_cqe() failed: {0}\n", strerror(-ret));              \
        WeFailed = true;                                                       \
        return;                                                                \
      }                                                                        \
                                                                               \
      if (cqe->res < 0) {                                                      \
        WithColor::error() << llvm::formatv("async write failed: {0}\n",       \
                                            strerror(-cqe->res));              \
        WeFailed = true;                                                       \
        return;                                                                \
      }                                                                        \
                                                                               \
      io_uring_cqe_seen(&ring, cqe);                                           \
    }                                                                          \
  } while (false)

    oneapi::tbb::parallel_invoke(
        [&](void) -> void {
          //
          // perf-get-opts (originally written for ptdump and ptxed)
          //
          fs::path path_to_get_opts = libipt_scripts_dir / "perf-get-opts.bash";
          if (RunExecutableToExit(
                  path_to_get_opts.string(),
                  [&](auto Arg) { Arg(path_to_get_opts.string()); },
                  std::string(opts_filename))) {
            WithColor::error() << "failed to run libipt/script/perf-get-opts.bash\n";
            Failed = true;
            return;
          }
        },
        [&](void) -> void {
          bool WeFailed = false;
          BOOST_SCOPE_DEFER [&] {
            if (WeFailed) {
              Failed = true;
              WithColor::error() << "failed to write sideband file.\n";
            } else {
              if (IsVerbose())
                llvm::errs() << "wrote sideband files.\n";
            }
          };

          scoped_fd ofd(::open(sb_filename, O_WRONLY | O_CREAT | O_LARGEFILE, 0666));
          if (!ofd) {
            int err = errno;
            WithColor::error() << llvm::formatv("failed to open {0}: {1}\n",
                                                sb_filename, strerror(err));
            WeFailed = true;
            return;
          }

          int pipefd[2];
          if (::pipe(pipefd) < 0) { /* first, create a pipe */
            int err = errno;
            die("pipe(2) failed: " + std::string(strerror(err)));
          }

          auto rfd = std::make_unique<scoped_fd>(pipefd[0]);
          auto wfd = std::make_unique<scoped_fd>(pipefd[1]);

          fs::path path_to_read_sideband =
              libipt_scripts_dir / "perf-read-sideband.bash";

          pid_t pid = Tool::RunExecutable(
              path_to_read_sideband.string(),
              [&](auto Arg) {
                Arg(path_to_read_sideband.string());
                Arg("-d");
              },
              "", "",
              [&](const char **argv, const char **envp) {
                rfd.reset();
                ::dup2(wfd->get(), STDOUT_FILENO);
                wfd.reset();
              });
          wfd.reset();

          pipe_line_reader pipe;

          using namespace std::placeholders;

          std::string in_filename;
          std::string out_filename;

          std::ofstream dst(sb_filename);

          unsigned num_req = 0;
          uint64_t offset = 0;

          struct io_uring ring;
          OUR_IOURING_INIT(&ring);

          BOOST_SCOPE_DEFER [&ring] { io_uring_queue_exit(&ring); };

          auto process_line = [&](const std::string &line) -> bool {
            in_filename.resize(4097);
            out_filename.resize(4097);

            uint64_t skip, count;

            sscanf(line.c_str(),
                   "dd if=%4096s of=%4096s conv=notrunc oflag=append "
                   "ibs=1 skip=%" PRIu64 " count=%" PRIu64 " status=none",
                   &in_filename[0], &out_filename[0], &skip, &count);

            in_filename.resize(strlen(in_filename.c_str()));
            out_filename.resize(strlen(out_filename.c_str()));

            assert(in_filename == "perf.data");

            OUR_IOURING_QUEUE_WRITE(
                &ring, ofd.get(),
                reinterpret_cast<const char *>(perf_data.contents.mmap->ptr) +
                    skip,
                count, offset);

            offset += count;
            ++num_req;
            return true;
          };

          if (IsVerbose())
            llvm::errs() << "writing sideband files...\n";

          while (auto o = pipe.get_line(rfd->get())) {
            if (unlikely(!process_line(*o))) {
              WeFailed = true;
              return;
            }
          }

          if (WaitForProcessToExit(pid)) {
            WithColor::error() << "failed to run perf-read-sideband.bash\n";
            WeFailed = true;
            return;
          }

          OUR_IOURING_SUBMIT_AND_WAIT(&ring, num_req);
        },
        [&](void) -> void {
          bool WeFailed = false;
          BOOST_SCOPE_DEFER [&] {
            if (WeFailed) {
              Failed = true;
              WithColor::error() << "failed to write aux files.\n";
            } else {
              if (IsVerbose())
                llvm::errs() << "wrote aux files.\n";
            }
          };

          unsigned num_req = 0;

          struct io_uring ring;
          OUR_IOURING_INIT(&ring);

          BOOST_SCOPE_DEFER [&ring] { io_uring_queue_exit(&ring); };

          std::vector<std::pair<std::unique_ptr<scoped_fd>, uint64_t>> aux_ofdv;

          if (IsVerbose())
            llvm::errs() << "writing aux files...\n";

          bool success = perf_data.for_each_auxtrace(
              [&](const struct perf::auxtrace_event &aux) -> bool {
                if (unlikely(aux.cpu >= aux_ofdv.size()))
                  aux_ofdv.resize(aux.cpu + 1);

                auto &pair = aux_ofdv.at(aux.cpu);

                std::unique_ptr<scoped_fd> &aux_ofd = pair.first;
                uint64_t &offset = pair.second;

                if (!aux_ofd) {
                  std::string aux_ofname =
                      "perf.data-aux-idx" + std::to_string(aux.cpu) + ".bin";
                  aux_ofd = std::make_unique<scoped_fd>(
                      ::open(aux_ofname.c_str(),
                             O_WRONLY | O_CREAT | O_LARGEFILE, 0666));
                  offset = 0;
                }

                const auto size = aux.size;

                OUR_IOURING_QUEUE_WRITE(
                    &ring, aux_ofd->get(),
                    reinterpret_cast<const uint8_t *>(&aux) + aux.header.size,
                    size, offset);

                offset += size;
                ++num_req;
                return true;
              });

          if (!success) {
            WeFailed = true;
            return;
          }

          OUR_IOURING_SUBMIT_AND_WAIT(&ring, num_req);
        });

#undef OUR_IOURING_INIT
#undef OUR_IOURING_QUEUE_WRITE
#undef OUR_IOURING_SUBMIT_AND_WAIT

    if (Failed)
      return 1;
  }

  if (!fs::exists(opts_filename)) {
    WithColor::error() << llvm::formatv("could not find {0}\n", opts_filename);
    return 1;
  }

  std::string opts_str = read_file_into_string(opts_filename);
  boost::algorithm::trim(opts_str);

  if (IsVerbose())
    llvm::errs() << llvm::formatv("ptdump {0}\n", opts_str);

  std::vector<std::string> ptdump_args;

  boost::algorithm::split(ptdump_args, opts_str, boost::is_any_of(" "),
                          boost::token_compress_on);

  if (!fs::exists(sb_filename)) {
    WithColor::error() << llvm::formatv("could not find {0}\n", sb_filename);
    return 1;
  }

  perf::data_reader<false> sb(sb_filename);
  perf::sideband_parser sb_parser(ptdump_args);
  if (opts.GatherBins) {
    if (IsVeryVerbose())
      HumanOut() << "gathering binaries...\n";

    gather_binaries(*Explorer, sb, sb_parser);

    if (IsVeryVerbose())
      HumanOut() << "gathered binaries.\n";

#if 0
    if (opts.Objdump)
      for_each_binary(std::execution::par_unseq, jv, [&](binary_t &b) {
        if (!b.Analysis.objdump.empty())
          return;

        catch_exception([&]() {
          auto e_lck = b.Analysis.objdump.exclusive_access();

          if (b.Analysis.objdump.empty_unlocked())
            binary_t::Analysis_t::objdump_output_type::generate(
                b.Analysis.objdump, b.is_file() ? b.Name.c_str() : nullptr,
                *state.for_binary(b).Bin);
        });
      });
#endif
    if (opts.JustGatherBins)
      return 0;
  }

  //HumanOut() << "cap=" << jv.hash_to_binary.bucket_count() << '\n';

  std::vector<std::pair<unsigned, std::string>> aux_filenames;
  gather_perf_data_aux_files(aux_filenames);

  if (aux_filenames.empty()) {
    WithColor::warning() << "no aux files found!\n";
    return 1;
  }

  std::sort(aux_filenames.begin(), aux_filenames.end());

#if 0
  const bool WillFork = !opts.MT && !opts.Serial;

  if (WillFork && msync(jv_file.get_address(), jv_file.get_size(), MS_SYNC) < 0) {
    int err = errno;
    WithColor::error() << llvm::formatv("msync failed: {0}\n", strerror(err));
    return 1;
  }
#endif

  const unsigned N = jv.Binaries.size();

  std::unique_ptr<jv_file_t> jv_file2;
  jv_base_t<false> *jv2 = nullptr;

  if (!opts.MT) {
    const int jvfd = jv_file.m_mfile.get_device().m_handle;
    assert(jvfd >= 0);

    const char *jv_filename2 = nullptr;
    std::string tmpjv_filename(temporary_dir() + "/.jv");
    if (cp_reflink_to(jvfd, tmpjv_filename.c_str(), jv_file.get_size()) < 0) {
      if (IsVerbose())
        WithColor::warning()
            << llvm::formatv("reflink failed: {0}\n", strerror(errno));
      jv_filename2 = path_to_jv().c_str();
      tmpjv_filename.clear();
    } else {
      jv_filename2 = tmpjv_filename.c_str();
    }
    assert(jv_filename2);

    jv_file2 = std::make_unique<jv_file_t>(
        boost::interprocess::open_copy_on_write, jv_filename2);

    if (!tmpjv_filename.empty()) {
      if (::unlink(tmpjv_filename.c_str()) < 0) {
        if (IsVerbose())
          WithColor::warning()
              << llvm::formatv("unlink failed: {0}\n", strerror(errno));
      }
    }

    jv_t &_jv = *jv_file2->find<jv_t>("JV").first;

    if (IsVeryVerbose())
      llvm::errs() << "move constructing jv2...\n";

    jv2 = jv_file2->construct<jv_base_t<false>>("JV_tmp")(std::move(_jv), *jv_file2);
    assert(jv2);

    if (IsVeryVerbose())
      llvm::errs() << "move constructed jv2.\n";
  }

  std::vector<char *> ptdump_argv;
  ptdump_argv.reserve(ptdump_args.size());
  ptdump_argv.push_back(const_cast<char *>("ptdump"));
  for (std::string &x : ptdump_args)
    ptdump_argv.push_back(const_cast<char *>(x.c_str()));
  ptdump_argv.push_back(nullptr);

  auto run = [&](const auto &pair) -> void {
        const std::string &aux_filename = pair.second;
        if (!fs::exists(pair.second)) {
          WithColor::warning() << llvm::formatv("\"{0}\" disappeared!\n", pair.second);
          return;
        }

        perf::data_reader<false> aux(aux_filename.c_str());

        const unsigned cpu = pair.first;

        if (IsVerbose())
          WithColor::note() << llvm::formatv("size of {0}: {1}\n", aux_filename,
                                             aux.contents.mmap->len);

        bool Ran = false;

#define simple_ipt_t reference_ipt_t /* FIXME */

        auto run = [&]<IPT_PARAMETERS_DCL>(void) {
          try {
#define SELECT_DECODER_AND_EXPLORE(...)                                        \
  do {                                                                         \
    if (opts.Decoder == "reference") {                                         \
      reference_ipt_t<IPT_PARAMETERS_DEF> ipt(__VA_ARGS__);                    \
      Ran = true;                                                              \
      ipt.explore();                                                           \
    } else if (opts.Decoder == "afl") {                                        \
      afl_ipt_t<IPT_PARAMETERS_DEF> ipt(__VA_ARGS__);                          \
      Ran = true;                                                              \
      ipt.explore();                                                           \
    } else if (opts.Decoder == "simple") {                                     \
      simple_ipt_t<IPT_PARAMETERS_DEF> ipt(__VA_ARGS__);                       \
      Ran = true;                                                              \
      ipt.explore();                                                           \
    } else {                                                                   \
      WithColor::error() << llvm::formatv("unknown decoder \"{0}\"\n",         \
                                          opts.Decoder);                       \
      exit(1);                                                                 \
    }                                                                          \
  } while (false)

#define THE_IPT_ARGS(__jv, __jv_file) \
                  ptdump_argv.size() - 1, ptdump_argv.data(), \
                   __jv, *Explorer, \
                  __jv_file, cpu, sb, sb_parser, \
                  const_cast<uint8_t *>(aux.data_begin()), \
                  const_cast<uint8_t *>(aux.data_end()), \
                  sb_filename, \
                  IsVeryVerbose() ? 2 : (IsVerbose() ? 1 : 0), \
                  true

            if constexpr (MT) {
              SELECT_DECODER_AND_EXPLORE(THE_IPT_ARGS(jv, jv_file));
            } else {
              SELECT_DECODER_AND_EXPLORE(THE_IPT_ARGS(*jv2, *jv_file2));
            }

#undef THE_IPT_ARGS
#undef SELECT_DECODER_AND_EXPLORE
          } catch (const truncated_aux_exception &) {
            if (IsVerbose())
              WithColor::warning()
                  << llvm::formatv("truncated aux (cpu {0})\n", cpu);
          }
        };

        const unsigned VerbLevel = VerbosityLevel();

#define __opts_Verbosity VerbLevel
#define __opts_Caching opts.Cache
#define __opts_Objdump opts.Objdump
#define __opts_ExeOnly opts.ExeOnly
#define __opts_MT      opts.MT

#define IPT_EXTRACT_VALUES(s, data, elem)                                      \
  BOOST_PP_TUPLE_ELEM(3, 2, elem)

#define IPT_ALL_OPTIONS                                                        \
  BOOST_PP_SEQ_TRANSFORM(IPT_EXTRACT_VALUES, void, IPT_PARAMETERS)

#define IPT_GENERATE_COMPARISON(r, product, i, elem)                           \
  BOOST_PP_IF(i, &&, )                                                         \
  (BOOST_PP_CAT(__opts_,BOOST_PP_TUPLE_ELEM(3, 1, elem)) == BOOST_PP_SEQ_ELEM(i, product))

#define IPT_GENERATE_TEMPLATE_ARG(r, product, i, elem)                         \
  BOOST_PP_COMMA_IF(i) BOOST_PP_SEQ_ELEM(i, product)

#define GENERATE_RUN(r, product)                                               \
  if (BOOST_PP_SEQ_FOR_EACH_I(IPT_GENERATE_COMPARISON, product,                \
                              IPT_PARAMETERS))                            \
    run.template operator()<                                                   \
        BOOST_PP_SEQ_FOR_EACH_I(IPT_GENERATE_TEMPLATE_ARG, product,            \
                                IPT_PARAMETERS)>();

BOOST_PP_SEQ_FOR_EACH_PRODUCT(GENERATE_RUN, IPT_ALL_OPTIONS);

#undef GENERATE_RUN

        assert(Ran);
      };

  if (opts.MT) {
    if (opts.Serial)
      std::for_each(aux_filenames.begin(),
                    aux_filenames.end(), run);
    else
      std::for_each(std::execution::par_unseq,
                    aux_filenames.begin(),
                    aux_filenames.end(), run);
  } else {
    auto integrate_jv = [&](void) -> void {
      for (binary_index_t BIdx = 0; BIdx < N; ++BIdx) {
        const auto &b2 = jv2->Binaries.at(BIdx);
        auto &b1 = jv.Binaries.at(BIdx);

        for (const auto &pair : b2.bbbmap) {
          Explorer->explore_basic_block(b1, *state.for_binary(b1).Bin, pair.first);
        }
      }
    };

    std::vector<pid_t> pidvec;
    for (const auto &pair : aux_filenames) {
      if (!opts.Serial) {
        pid_t pid = ::fork();
        if (pid) {
          pidvec.push_back(pid);
          continue;
        }
      }

      run(pair);
      integrate_jv();

      if (!opts.Serial)
        return 0;
    }

    if (!opts.Serial) {
      assert(!pidvec.empty());
      for (pid_t pid : pidvec) {
        WaitForProcessToExit(pid);
      }
    }
  }

  return 0;
}

void IPTTool::gather_all_perf_data_files(std::vector<std::string> &out) {
  std::regex filename_pattern(R"(perf\.data.*)");

  fs::path dir = fs::canonical(".");
  assert(fs::exists(dir) && fs::is_directory(dir));

  for (const auto &entry : fs::directory_iterator(dir)) {
    if (!fs::is_regular_file(entry))
      continue;

    std::string filename = entry.path().filename().string();
    std::smatch match;
    if (std::regex_match(filename, match, filename_pattern)) {
      out.push_back(std::move(filename));
    }
  }
}

void IPTTool::gather_perf_data_aux_files(std::vector<std::pair<unsigned, std::string>> &out) {
  std::regex aux_filename_pattern(R"(perf\.data-aux-idx(\d+)\.bin)");

  fs::path dir = fs::canonical(".");
  assert(fs::exists(dir) && fs::is_directory(dir));

  for (const auto &entry : fs::directory_iterator(dir)) {
    if (!fs::is_regular_file(entry))
      continue;

    std::string filename = entry.path().filename().string();
    std::smatch match;
    if (std::regex_match(filename, match, aux_filename_pattern)) {
      std::string cpu_s = match[1].str();

      if (IsVerbose())
        llvm::errs() << llvm::formatv("Found \"{0}\" (cpu: {1})\n", filename, cpu_s);

      out.emplace_back(strtoul(cpu_s.c_str(), nullptr, 10), filename);
    }
  }
}

void IPTTool::gather_binaries(explorer_t &explorer,
                              const perf::data_reader<false> &sb,
                              const perf::sideband_parser &sb_parser) {
  tbb::flow::graph g;

  AddOptions_t Options;
  Options.Objdump = opts.Objdump;

  tbb::flow::function_node<const char *> process_node(
      g, tbb::flow::unlimited, [&](const char *filename) -> void {
        assert(Options.Objdump);
        jv.AddFromPath(
            explorer, jv_file, filename,
            [&](binary_t &b) -> void {
              if (IsVerbose())
                HumanOut() << llvm::formatv("gathered \"{0}\"\n", filename);
            },
            Options);
      });

  BOOST_SCOPE_DEFER [&] {
    g.wait_for_all();
  };

  std::for_each(sb.begin(),
                sb.end(),
                [&](const struct perf_event_header &hdr) {
    struct pev_event e;
    sb_parser.load(e, hdr);

    switch (e.type) {
    case PERF_RECORD_MMAP:
      process_node.try_put(e.record.mmap->filename);
      break;
    case PERF_RECORD_MMAP2:
      process_node.try_put(e.record.mmap2->filename);
      break;
    case PERF_RECORD_SAMPLE: {
      if (strcmp(e.name, "__jove_augmented_syscalls__") != 0)
        return;

      auto on_syscall = [&]<typename T>(const T *payload) -> void {
        const auto &hdr = payload->hdr;

        auto nr = hdr.syscall_nr;
        auto ret = hdr.ret;

#define nr_for(sysnm)                                                          \
  (std::is_same_v<T, struct augmented_syscall_payload64> ? nr64_##sysnm        \
                                                         : nr32_##sysnm)

        //
        // we can assume that the syscall successfully completed (XXX except exec)
        //
        switch (nr) {
        case nr_for(openat):
        case nr_for(open): {
#if 0
          binary_index_t BIdx;
          bool IsNew;
          std::tie(BIdx, IsNew) = jv.AddFromPath(*Explorer, jv_file, payload->str);
#endif
          process_node.try_put(payload->str);
          break;
        }

        default:
          break;
        }
      };

      const struct pev_record_raw *const raw = e.record.raw;
      assert(raw);

#if 0
      if (sample.time)
        fprintf(stderr, "sb.tsc=%" PRIx64 "\n", *sample.time);
#endif

      unsigned bytes_size = raw->size;
      const uint8_t *const bytes = (const uint8_t *)raw->data;

      const bool was32 = !!(bytes[MAGIC_LEN] & 1u);

#if 0
      const unsigned size_of_struct =
          was32 ? sizeof(struct augmented_syscall_payload32)
                : sizeof(struct augmented_syscall_payload64);

      bool bad = false;
      if (!(bytes[0] == 'J' &&
            bytes[1] == 'O' &&
            bytes[2] == 'V' &&
            bytes[3] == 'E')) {
        fprintf(stderr, "offset at %" PRIu64 " does not start with magic1! bytes_size=%u sizeof(struct)=%u\n", offset, bytes_size, size_of_struct);
        bad = true;
      }

      if (!(bytes[bytes_size - 1] == 'E' &&
            bytes[bytes_size - 2] == 'V' &&
            bytes[bytes_size - 3] == 'O' &&
            bytes[bytes_size - 4] == 'J')) {
        fprintf(stderr, "offset at %" PRIu64 " does not end with magic2! bytes_size=%u sizeof(struct)=%u\n", offset, bytes_size, size_of_struct);
        bad = true;
      }

      if (bad) {
        fprintf(stderr, "\n");
        hexdump(stderr, bytes, bytes_size);
        fprintf(stderr, "\n");
      }
#endif

      if (was32) {
        if (IsTarget32)
          on_syscall.template operator()<struct augmented_syscall_payload32>(reinterpret_cast<const struct augmented_syscall_payload32 *>(bytes));
      } else {
        if (IsTarget64)
          on_syscall.template operator()<struct augmented_syscall_payload64>(reinterpret_cast<const struct augmented_syscall_payload64 *>(bytes));
      }
      break;
    }

    default:
      return;
    }
  });
}
}

#endif /* x86 */
