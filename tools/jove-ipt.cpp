#if (defined(__x86_64__) || defined(__i386__)) &&                              \
    (defined(TARGET_X86_64) || defined(TARGET_I386))
#include "tool.h"
#include "B.h"
#include "tcg.h"
#include "disas.h"
#include "explore.h"
#include "util.h"
#include "symbolizer.h"
#include "locator.h"
#include "ipt.h"
#include "fastipt.h"
#include "wine.h"
#include "perf.h"
#include "glibc.h"
#include "pipe.h"
#include "hash.h"

#include "syscall_nrs.hpp"

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
    cl::opt<std::string> Threaded;
    cl::opt<bool> ExeOnly;

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
                        cl::init(true /* TODO */), cl::cat(JoveCategory)),

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

          Threaded(
              "threaded",
              cl::value_desc("(multi)|(single)"),
              cl::desc("Use multiple threads"), cl::init("multi"),
              cl::cat(JoveCategory)),

          ExeOnly("exe-only", cl::desc("Only care about exe addresses."),
                cl::cat(JoveCategory)) {}
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

  int ProcessAppStderr(void);

  static constexpr const char *path_to_stdout = "perf.data.stdout";
  static constexpr const char *path_to_stderr = "perf.data.stderr";
  static constexpr const char *sb_filename = "perf.data-sideband.pevent";

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

  void gather_binary_paths(std::vector<std::string> &out,
                           const sb_info_t &sb_info,
                           const struct perf_event_header *const sb_beg,
                           const struct perf_event_header *const sb_end);
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
      jv.AddFromPath(*Explorer, name,
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

  AddOptions.Objdump = opts.Objdump;

  TCG = std::make_unique<tiny_code_generator_t>();
  Disas = std::make_unique<disas_t>();
  Explorer = std::make_unique<explorer_t>(jv, *Disas, *TCG, false /* IsVeryVerbose() */);

  const std::string prog_path = fs::canonical(opts.Prog).string();

  std::string sudo_path = locator().sudo();
  const unsigned gid = ::getgid();
  const unsigned uid = ::getuid();

  if (!opts.ExistingPerfData) {
  RunExecutableToExit(
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

        Arg(opts.Prog);

        for (const std::string &s : opts.Args)
          Arg(s);
      },
      [&](auto Env) {
        InitWithEnviron(Env);

        for (const std::string &s : opts.Envs)
          Env(s);

        SetupEnvironForRun(Env);

        //
        // wine sometimes read(2)'s binaries into memory rather than mmap(2)'ing
        // them. this causes trouble- we need to use WINEDEBUG=+loaddll,+process
        // module to get wine to tell us the load addresses of sections of
        // binaries so we can make sense of the addresses we get back from the
        // trace.
        //
        if (IsCOFF)
          Env("WINEDEBUG=+loaddll,+process");
      }, path_to_stdout, path_to_stderr);
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
        Arg(path_to_stdout);
        Arg(path_to_stderr);
        Arg("perf.data");
    });

  if (opts.UsePerfScript)
    return UsingPerfScript();
  else
    return UsingLibipt();
}

int IPTTool::ProcessAppStderr(void) {
  if (IsCOFF) {
    //
    // parse stderr to make sense of the program counters
    //
    std::string stderr_contents;
    read_file_into_thing(path_to_stderr, stderr_contents);

    wine::stderr_parser parser(stderr_contents);

    long tid = parser.tid_of_NtCreateUserProcess(jv.Binaries.at(0).Name.c_str());
    if (tid < 0) {
      tid = parser.tid_of_loaddll_exe(jv.Binaries.at(0).Name.c_str());

      if (tid < 0) {
        WithColor::error() << "could not determine thread ID of program\n";
        return 1;
      }
    }

    if (IsVerbose())
      llvm::errs() << "tid=" << tid << '\n';

    std::vector<std::pair<std::string, uint64_t>> loaded_list;
    parser.loaddll_loaded_for_tid(tid, loaded_list);

    std::vector<std::string> binary_paths;
    for (const auto &pair : loaded_list) {
      insertSortedVec(binary_paths, pair.first);
    }

    //
    // add binaries
    //
    std::for_each(
        std::execution::par_unseq,
        binary_paths.begin(),
        binary_paths.end(),
        [&](const std::string &path) {
          bool IsNew;
          binary_index_t BIdx;

          std::tie(BIdx, IsNew) = jv.AddFromPath(
              *Explorer, path.c_str(),
              std::bind(&IPTTool::on_new_binary, this, std::placeholders::_1),
              AddOptions);

          assert(is_binary_index_valid(BIdx));
        });
  }

  return 0;
}

int IPTTool::UsingPerfScript(void) {
  if (int ret = ProcessAppStderr())
    return ret;

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
          ip_sharable_lock<ip_sharable_mutex> s_lck(src_bin.bbmap_mtx);

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
      ip_sharable_lock<ip_sharable_mutex> s_lck(src_bin.bbmap_mtx);

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

      ip_sharable_lock<ip_sharable_mutex> s_lck(src_bin.bbmap_mtx);

      basic_block_t src = basic_block_at_address(Term.Addr, src_bin);
      basic_block_properties_t &src_bbprop = src_ICFG[src];

      src_bbprop.insertDynTarget(src_BIdx, std::make_pair(dst_BIdx, FIdx), jv);
    };

    switch (Term.Type) {
    case TERMINATOR::RETURN: {
      {
        ip_sharable_lock<ip_sharable_mutex> s_lck(src_bin.bbmap_mtx);

        src_ICFG[basic_block_at_address(src_va, src_bin)].Term._return.Returns = true;
      }

      const taddr_t before_pc = dst_va - 1 - IsMIPSTarget * 4;

      ip_sharable_lock<ip_sharable_mutex> s_lck(dst_bin.bbmap_mtx);

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
        ip_sharable_lock<ip_sharable_mutex> s_lck(src_bin.bbmap_mtx);

        IsDefinitelyTailCall(src_ICFG, basic_block_at_address(src_va, src_bin));
      });

      if (TailCall || src_BIdx != dst_BIdx) {
        handle_indirect_call();
      } else {
        assert(src_BIdx == dst_BIdx);

        ip_scoped_lock<ip_sharable_mutex> e_lck(src_bin.bbmap_mtx);

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

  std::vector<std::string> ptdump_args;
  std::vector<char *> ptdump_argv;
  auto get_opts = [&](void) -> void {
    //
    // perf-get-opts (originally written for ptdump and ptxed)
    //
    fs::path path_to_opts = fs::path(temporary_dir()) / "get-opts.txt";

    fs::path path_to_get_opts = libipt_scripts_dir / "perf-get-opts.bash";
    if (RunExecutableToExit(
            path_to_get_opts.string(),
            [&](auto Arg) { Arg(path_to_get_opts.string()); },
            path_to_opts.c_str())) {
      WithColor::error() << "failed to run libipt/script/perf-get-opts.bash\n";
      Failed = true;
      return;
    }

    std::string opts_str = read_file_into_string(path_to_opts.c_str());
    boost::algorithm::trim(opts_str);

    if (IsVerbose())
      llvm::errs() << llvm::formatv("ptdump {0}\n", opts_str);

    boost::algorithm::split(ptdump_args, opts_str, boost::is_any_of(" "),
                            boost::token_compress_on);

    ptdump_argv.push_back(const_cast<char *>("ptdump"));
    for (std::string &argstr : ptdump_args)
      ptdump_argv.push_back(const_cast<char *>(argstr.c_str()));
    ptdump_argv.push_back(nullptr);
  };

  if (opts.ExistingPerfData) {
    get_opts();
  } else {
    perf::data_reader perf_data("perf.data");

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
        get_opts,
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

  if (!fs::exists(sb_filename)) {
    WithColor::error() << llvm::formatv("could not find {0}\n", sb_filename);
    return 1;
  }

  auto sb_len = fs::file_size(sb_filename);

  scoped_fd sb_fd(::open(sb_filename, O_RDONLY));
  if (!sb_fd) {
    WithColor::error() << llvm::formatv("could not open {0}\n", sb_filename);
    return 1;
  }

  scoped_mmap sb_mmap(nullptr, sb_len, PROT_READ, MAP_PRIVATE, sb_fd.get(), 0);


  if (!sb_mmap) {
    WithColor::error() << llvm::formatv("failed to mmap {0}\n", sb_filename);
    return 1;
  }

  if (::madvise(sb_mmap.ptr, sb_mmap.len, MADV_SEQUENTIAL) < 0)
    WithColor::warning() << llvm::formatv("madvise failed: {0}\n",
                                          strerror(errno));

  const struct perf_event_header *sb_beg =
      static_cast<const struct perf_event_header *>(sb_mmap.ptr);
  const struct perf_event_header *sb_end =
      reinterpret_cast<const struct perf_event_header *>(
          reinterpret_cast<const uint8_t *>(sb_beg) + sb_len);

  sb_info_t sb_info;
  for (unsigned idx = 0; idx < ptdump_args.size(); ++idx) {
    const std::string &arg = ptdump_args.at(idx++);
    const std::string &arga = ptdump_args.at(idx);

    //HumanOut() << "arg is " << arg << '\n';
    if (arg == "--pevent:sample-config") {
      std::vector<std::string> x;
      boost::algorithm::split(x, arga, boost::is_any_of(":"),
                              boost::token_compress_on);

      uint64_t id = std::stoull(x.at(0), nullptr, 0);
      uint64_t sample_type = std::stoull(x.at(1), nullptr, 0);
      std::string &name = x.at(2);

      if (id >= sb_info.stypes.size())
        sb_info.stypes.resize(id + 1);

      sb_sample_type_t &st = sb_info.stypes.at(id);
      st.identifier = id;
      st.sample_type = sample_type;
      st.name = std::move(name);

      if (IsVerbose())
        HumanOut() << llvm::formatv("sample-config({0}, {1:x}, \"{2}\")\n",
                                    st.identifier, st.sample_type, st.name);

      sb_info.sample_type = sample_type;
    } else {
      continue;
    }
  }

  {
    std::vector<std::string> pathvec;
    gather_binary_paths(pathvec, sb_info, sb_beg, sb_end);

    std::for_each(
        std::execution::par_unseq,
        pathvec.begin(),
        pathvec.end(),
        [&](const std::string &path_s) {
          std::string path_str;
          try {
            path_str = fs::canonical(path_s.c_str()).string();
          } catch (...) {
            return;
          }

          binary_t *pb = new binary_t(jv.get_allocator());
          binary_t &b = *pb;
          read_file_into_thing(path_s.c_str(), b.Data);

          std::unique_ptr<llvm::object::Binary> Bin;
          try {
            Bin = B::Create(b.data());
          } catch (...) {
            return;
          }

          hash_t h = hash_data(b.data());
          auto ByHash = jv.LookupByHash(h);
          if (ByHash)
            return;
          b.Hash = h;
          to_ips(b.Name, path_str);

          AddOptions_t Options;
          jv.DoAdd(b, *Explorer, *Bin, Options);

          jv.Add(std::move(b), [&](binary_t &b) -> void {
            if (IsVerbose())
              HumanOut() << llvm::formatv("\"{0}\"\n", b.Name.c_str());
          });
        });
  }

  //HumanOut() << "cap=" << jv.hash_to_binary.bucket_count() << '\n';

  std::vector<std::pair<unsigned, std::string>> aux_filenames;
  gather_perf_data_aux_files(aux_filenames);

  if (aux_filenames.empty()) {
    WithColor::warning() << "no aux files found!\n";
    return 1;
  }

  bool Multi = opts.Threaded == "multi";
  auto run = [&](const auto &pair) -> void {
        const std::string &aux_filename = pair.second;
        if (!fs::exists(pair.second)) {
          WithColor::warning() << llvm::formatv("\"{0}\" disappeared!\n", pair.second);
          return;
        }

        auto len = fs::file_size(aux_filename);

        unsigned cpu = pair.first;
        if (IsVerbose())
          WithColor::note()
              << llvm::formatv("size of {0}: {1}\n", aux_filename, len);

        scoped_fd aux_fd(::open(aux_filename.c_str(), O_RDONLY));
        if (!aux_fd)
          die(std::string("failed to open \"") + aux_filename + "\"");

        scoped_mmap mmap(nullptr, len, PROT_READ, MAP_PRIVATE, aux_fd.get(), 0);

        if (!mmap)
          die(std::string("failed to mmap \"") + aux_filename + "\"");

        if (::madvise(mmap.ptr, mmap.len, MADV_SEQUENTIAL) < 0)
          WithColor::warning()
              << llvm::formatv("madvise failed: {0}\n", strerror(errno));

        bool Ran = false;

        auto run = [&]<IPT_PARAMETERS_DCL>(void) {
          IntelPT<IPT_PARAMETERS_DEF> ipt(
              ptdump_argv.size() - 1, ptdump_argv.data(), jv, *Explorer, cpu,
              mmap.ptr,
              reinterpret_cast<uint8_t *>(mmap.ptr) + len, sb_filename,
              IsVeryVerbose() ? 2 : (IsVerbose() ? 1 : 0));

          try {
            Ran = true;

            ipt.explore();
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

  if (Multi)
    std::for_each(std::execution::par_unseq,
                  aux_filenames.begin(),
                  aux_filenames.end(), run);
  else
    std::for_each(aux_filenames.begin(),
                  aux_filenames.end(), run);

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

static int pev_strlen(const char *begin, const void *end_arg) {
  const char *pos, *end;

  end = (const char *)end_arg;
  assert(end >= begin);

  for (pos = begin; pos < end; ++pos) {
    if (!pos[0])
      return (int)(pos - begin) + 1;
  }

  return -1;
}

void IPTTool::gather_binary_paths(
    std::vector<std::string> &out, const sb_info_t &sb_info,
    const struct perf_event_header *const sb_beg,
    const struct perf_event_header *const sb_end) {
  auto cstrless = [](const char *s1, const char *s2) {
    return strcmp(s1, s2) < 0;
  };

  for (const struct perf_event_header *sb = sb_beg; sb != sb_end;
       sb = reinterpret_cast<const struct perf_event_header *>(
           reinterpret_cast<const uint8_t *>(sb) + sb->size)) {
    assert(sb < sb_end);

    const struct perf_event_header &hdr = *sb;
    const uint8_t *const end = reinterpret_cast<const uint8_t *>(sb) + hdr.size;

    struct {
      /* The sampled pid and tid. */
      const uint32_t *pid = nullptr;
      const uint32_t *tid = nullptr;

      /* The sampled time in perf_event format. */
      const uint64_t *time = nullptr;

      /* The sampled time in TSC format - if @time is not NULL. */
      uint64_t tsc = 0;

      /* The sampled id. */
      const uint64_t *id = nullptr;

      /* The sampled stream id. */
      const uint64_t *stream_id = nullptr;

      /* The sampled cpu. */
      const uint32_t *cpu = nullptr;

      /* The sample identifier. */
      const uint64_t *identifier = nullptr;

      /* The instruction pointer. */
      const uint64_t *ip = nullptr;

      const struct pev_record_raw *raw = nullptr;
    } sample;

    auto read_samples = [&](const uint8_t *const begin) -> unsigned {
      const uint64_t *pidentifier = nullptr;
      const uint8_t *pos = (end - sizeof(*pidentifier));

      if (begin <= pos)
        pidentifier = reinterpret_cast<const uint64_t *>(pos);

      assert(pidentifier);
      //HumanOut() << "id=" << *pidentifier << '\n';
      const uint64_t id = *pidentifier;
      const sb_sample_type_t &the_sample_type = sb_info.stypes.at(id);
      const uint64_t sample_type = the_sample_type.identifier == id
                                       ? the_sample_type.sample_type
                                       : sb_info.sample_type;

      pos = begin;

      if (sample_type & PERF_SAMPLE_TID) {
        sample.pid = reinterpret_cast<const uint32_t *>(&pos[0]);
        sample.tid = reinterpret_cast<const uint32_t *>(&pos[4]);
        pos += 8;
      }

      if (sample_type & PERF_SAMPLE_TIME) {
        sample.time = reinterpret_cast<const uint64_t *>(pos);
        pos += 8;
      }

      if (sample_type & PERF_SAMPLE_ID) {
        sample.id = reinterpret_cast<const uint64_t *>(pos);
        pos += 8;
      }

      if (sample_type & PERF_SAMPLE_STREAM_ID) {
        sample.stream_id = reinterpret_cast<const uint64_t *>(pos);
        pos += 8;
      }

      if (sample_type & PERF_SAMPLE_CPU) {
        sample.cpu = reinterpret_cast<const uint32_t *>(pos);
        pos += 8;
      }

      if (sample_type & PERF_SAMPLE_IDENTIFIER) {
        sample.identifier = reinterpret_cast<const uint64_t *>(pos);
        pos += 8;
      }

      return pos - begin;
    };

    auto read_sample_samples = [&](const uint8_t *const begin,
                                   const char *&name) -> unsigned {
      const uint64_t *const pidentifier =
          (const uint64_t *)begin; /* XXX assumes PERF_SAMPLE_IDENTIFIER */

      const uint64_t id = *pidentifier;
      const sb_sample_type_t &the_sample_type = sb_info.stypes.at(id);
      if (id != the_sample_type.identifier)
        throw std::runtime_error("bad sample type");

      const uint64_t sample_type = the_sample_type.sample_type;
      name = the_sample_type.name.c_str();

      const uint8_t *pos = begin;

      if (sample_type & PERF_SAMPLE_IDENTIFIER) {
        sample.identifier = (const uint64_t *)pos;
        pos += 8;
      } else {
        throw std::runtime_error("bad sample");
      }

      if (sample_type & PERF_SAMPLE_IP) {
        sample.ip = (const uint64_t *)pos;
        pos += 8; /* skip */
      }

      if (sample_type & PERF_SAMPLE_TID) {
        sample.pid = (const uint32_t *)&pos[0];
        sample.tid = (const uint32_t *)&pos[4];
        pos += 8;
      }

      if (sample_type & PERF_SAMPLE_TIME) {
        sample.time = (const uint64_t *)pos;
        pos += 8;
      }

      if (sample_type & PERF_SAMPLE_ADDR) {
        pos += 8; /* skip */
      }

      if (sample_type & PERF_SAMPLE_ID) {
        sample.id = (const uint64_t *)pos;
        pos += 8;
      }

      if (sample_type & PERF_SAMPLE_STREAM_ID) {
        sample.stream_id = (const uint64_t *)pos;
        pos += 8;
      }

      if (sample_type & PERF_SAMPLE_CPU) {
        sample.cpu = (const uint32_t *)pos;
        pos += 8;
      }

      if (sample_type & PERF_SAMPLE_PERIOD) {
        pos += 8; /* skip */
      }

      if (sample_type & PERF_SAMPLE_READ) {
        throw std::runtime_error(
            "read_sample_samples: unimplemented (PERF_SAMPLE_READ)");
      }

      if (sample_type & PERF_SAMPLE_CALLCHAIN) {
        pos += (*((const uint64_t *)pos) * 8); /* skip */
      }

      if (sample_type & PERF_SAMPLE_RAW) {
        sample.raw = (const struct pev_record_raw *)pos;
        pos += 4;
        pos += sample.raw->size;
      }

      return pos - begin;
    };

    const uint8_t *const begin = reinterpret_cast<const uint8_t *>(sb);
    const uint8_t *pos = begin + sizeof(struct perf_event_header);

    switch (hdr.type) {
    case PERF_RECORD_MMAP: {
      const auto &rec = *reinterpret_cast<const struct pev_record_mmap *>(pos);

      int slen = pev_strlen(rec.filename, end);
      if (slen < 0)
        continue;

      std::string filename_str(rec.filename, slen-1);
      //HumanOut() << llvm::formatv("mmap fn=\"{0}\"\n", filename_str.c_str());
      insertSortedVec<std::string>(out, filename_str);

      slen = (slen + 7) & ~7;

      pos += sizeof(struct pev_record_mmap);
      pos += slen;
      pos += read_samples(pos);
      break;
    }
    case PERF_RECORD_MMAP2: {
      const auto &rec = *reinterpret_cast<const struct pev_record_mmap2 *>(pos);

      int slen = pev_strlen(rec.filename, end);
      if (slen < 0)
        continue;

      std::string filename_str(rec.filename, slen-1);
      //HumanOut() << llvm::formatv("mmap2 \"{0}\"\n", filename_str.c_str());
      insertSortedVec<std::string>(out, filename_str);

      slen = (slen + 7) & ~7;

      pos += sizeof(struct pev_record_mmap2);
      pos += slen;
      pos += read_samples(pos);
      break;
    }
    case PERF_RECORD_SAMPLE: {
      const char *name = nullptr;
      pos += read_sample_samples(pos, name);

      //HumanOut() << llvm::formatv("sample \"{0}\"\n", name);
      break;
    }

    default:
      continue;
    }

    if (pos - begin != hdr.size)
      throw std::runtime_error("invalid sideband");
  }
}
}

#endif /* x86 */
