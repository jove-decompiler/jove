#if defined(__x86_64__) || defined(__i386__) /* x86 only */
#include "tool.h"
#include "B.h"
#include "tcg.h"
#include "disas.h"
#include "explore.h"
#include "util.h"
#include "symbolizer.h"
#include "locator.h"
#include "ipt.h"
#include "wine.h"
#include "perf.h"

#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>

#include <oneapi/tbb/parallel_pipeline.h>
#include <oneapi/tbb/parallel_for_each.h>

#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

#include <regex>
#include <memory>
#include <mutex>

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

namespace {

struct binary_state_t {
  std::unique_ptr<llvm::object::Binary> Bin;

  taddr_t LoadAddr = std::numeric_limits<taddr_t>::max();
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
    cl::opt<bool> WriteAuxFiles;

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
                    cl::init("8M"), cl::cat(JoveCategory)),

          MMapPagesAlias("m", cl::desc("Alias for --mmap-pages"),
                         cl::aliasopt(MMapPages), cl::cat(JoveCategory)),

          AuxPages("mmap-pages-aux",
                   cl::desc("Number of mmap pages for trace data (AUX)"),
                   cl::init("64M"), cl::cat(JoveCategory)),

          AuxPagesAlias("a", cl::desc("Alias for --mmap-pages-aux"),
                        cl::aliasopt(AuxPages), cl::cat(JoveCategory)),

          WriteAuxFiles("write-aux-files",
                        cl::desc("Write aux files to disk; can be used with ptdump/ptxed."),
                        cl::cat(JoveCategory)) {}

  } opts;

  std::string perf_path;

  symbolizer_t symbolizer;

  std::unique_ptr<tiny_code_generator_t> TCG;
  std::unique_ptr<disas_t> Disas;
  std::unique_ptr<explorer_t> E;

  std::unordered_map<std::string, taddr_t> binary_loadaddr_map;
  address_space_t AddressSpace;

  std::string buff;
  std::regex line_regex_ab;
  std::regex line_regex_a;
  std::regex line_regex_b;

  void parse_stderr(const char *path_to_stderr,
                    std::vector<std::string> &binary_paths);

public:
  IPTTool() : opts(JoveCategory) {}

  int Run(void) override;

  int UsingPerfScript(void);
  int UsingLibipt(void);

  binary_index_t BinaryFromName(const char *name);
  std::string GetLine(int rfd, tbb::flow_control &);
  void ProcessLine(const std::string &line);

  void init_state_for_binary(binary_t &);
  void on_new_binary(binary_t &);

  std::string convert_to_linux_path(std::string path);
};

JOVE_REGISTER_TOOL("ipt", IPTTool);

void IPTTool::init_state_for_binary(binary_t &b) {
  binary_state_t &x = state.for_binary(b);

  x.Bin = B::Create(b.data());
}

void IPTTool::on_new_binary(binary_t &b) {
  state.update();

  b.IsDynamicallyLoaded = true;

  init_state_for_binary(b);

  if (IsVerbose())
    llvm::errs() << llvm::formatv("added {0}\n", b.Name.c_str());
}

binary_index_t IPTTool::BinaryFromName(const char *name) {
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
      jv.AddFromPath(*E, name, invalid_binary_index,
                     std::bind(&IPTTool::on_new_binary, this, _1));

  if (IsVeryVerbose() && !is_binary_index_valid(BIdx))
    HumanOut() << llvm::formatv("failed to add \"{0}\"\n", name);

  return BIdx;
}

int IPTTool::Run(void) {
  perf_path = locator().perf();

  if (opts.Chdir) {
    if (::chdir(temporary_dir().c_str()) < 0) {
      int err = errno;

      throw std::runtime_error(std::string("chdir failed: ") + strerror(err));
    }
  }

  if (fs::exists("perf.data"))
    fs::remove("perf.data");

  TCG = std::make_unique<tiny_code_generator_t>();
  Disas = std::make_unique<disas_t>();
  E = std::make_unique<explorer_t>(jv, *Disas, *TCG, IsVeryVerbose());

  for_each_binary(std::execution::par_unseq, jv,
                  [&](binary_t &b) { init_state_for_binary(b); });

  const std::string prog_path = fs::canonical(opts.Prog).string();

  bool HasCOFF = std::any_of(
      jv.Binaries.begin(),
      jv.Binaries.end(), [&](binary_t &b) -> bool {
        return B::is_coff(*state.for_binary(jv.Binaries.at(0)).Bin);
      });

  fs::path path_to_stderr = fs::path(temporary_dir()) / "stderr";

  RunExecutableToExit(
      perf_path,
      [&](auto Arg) {
        Arg(perf_path);

        Arg("record");
        Arg("-m" + opts.MMapPages);
        Arg("-m," + opts.AuxPages);
        Arg("-o");
        Arg("perf.data");
        Arg("-e");
        Arg("intel_pt/cyc,noretcomp/u");

        Arg(opts.Prog);

        for (const std::string &s : opts.Args)
          Arg(s);
      },
      [&](auto Env) {
        InitWithEnviron(Env);

        for (const std::string &s : opts.Envs)
          Env(s);

        //
        // wine sometimes read(2)'s binaries into memory rather than mmap(2)'ing
        // them. this causes trouble- we need to use WINEDEBUG=+loaddll,+process
        // module to get wine to tell us the load addresses of sections of
        // binaries so we can make sense of the addresses we get back from the
        // trace.
        //
        if (HasCOFF)
          Env("WINEDEBUG=+loaddll,+process");
      }, "", path_to_stderr.string());

#if 0
  llvm::errs() << "attach to me! " << gettid() << '\n';
  char buff;
  while (read(STDIN_FILENO, &buff, 1) > 0 && buff != '\n');
#endif

  if (HasCOFF) {
    //
    // parse stderr to make sense of the program counters
    //
    std::string stderr_contents;
    read_file_into_thing(path_to_stderr.c_str(), stderr_contents);

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
      binary_loadaddr_map[pair.first] = pair.second;
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
              *E, path.c_str(), invalid_binary_index,
              std::bind(&IPTTool::on_new_binary, this, std::placeholders::_1));

          assert(is_binary_index_valid(BIdx));

          binary_t &b = jv.Binaries.at(BIdx);
          state.for_binary(b).LoadAddr = binary_loadaddr_map.at(path);
        });

    for_each_binary(jv, [&](binary_t &b) {
      binary_state_t &x = state.for_binary(b);

      if (~x.LoadAddr == 0) {
        if (IsVeryVerbose())
          llvm::errs() << llvm::formatv("no load address for \"{0}\"\n",
                                        b.Name.c_str());
        return;
      }

      uint64_t SectsStartAddr, SectsEndAddr;
      std::tie(SectsStartAddr, SectsEndAddr) = B::bounds_of_binary(*x.Bin);

      addr_intvl intvl(x.LoadAddr, SectsEndAddr - SectsStartAddr);

      {
        auto it = intvl_map_find(AddressSpace, intvl);
        if (it != AddressSpace.end()) {
          if (is_binary_index_valid((*it).second)) {
            binary_t &b_already_there = jv.Binaries.at((*it).second);

            WithColor::warning() << llvm::formatv(
                "ambiguity detected: \"{0}\" @ {1} but \"{2}\" @ {3} so \"{2}\" "
                "was probably unloaded\n",
                b.Name.c_str(),
                addr_intvl2str(intvl),
                b_already_there.Name.c_str(),
                addr_intvl2str((*it).first));
          }

          addr_intvl h = addr_intvl_hull(intvl, (*it).first);
          AddressSpace.erase(it);
          intvl_map_add(AddressSpace, h, invalid_binary_index);
          return;
        }
      }

      llvm::errs() << llvm::formatv("{0} @ {1}\n", b.Name.c_str(),
                                    addr_intvl2str(intvl));

      intvl_map_add(AddressSpace, intvl, index_of_binary(b, jv));
    });
  }

  if (opts.UsePerfScript)
    return UsingPerfScript();
  else
    return UsingLibipt();
}

int IPTTool::UsingPerfScript(void) {
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

        E->explore_basic_block(dst_bin, Bin, dst_va);
      }

      /* if there isn't a block at src we'll start one. */
      if (is_binary_index_valid(src_BIdx)) {
        binary_t &src_bin = _src_bin();
        auto &Bin = *state.for_binary(src_bin).Bin;
        src_va = B::va_of_offset(Bin, src_off);

        bool ExistsBlock = ({
          ip_sharable_lock<ip_upgradable_mutex> s_lck(src_bin.bbmap_mtx);

          exists_basic_block_at_address(src_va, src_bin);
        });

        if (!ExistsBlock)
          E->explore_basic_block(src_bin, Bin, src_va);
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
      ip_sharable_lock<ip_upgradable_mutex> s_lck(src_bin.bbmap_mtx);

      src_ICFG[basic_block_at_address(src_va, src_bin)].Term;
    });

    auto handle_indirect_call = [&](void) -> void {
      function_index_t FIdx;
      try {
        FIdx = E->explore_function(dst_bin, *state.for_binary(dst_bin).Bin,
                                   dst_off);
      } catch (const invalid_control_flow_exception &invalid_cf) {
        if (IsVerbose())
          llvm::errs() << llvm::formatv("invalid control-flow to {0} in \"{1}\"\n",
                                        taddr2str(invalid_cf.pc, false),
                                        invalid_cf.name_of_binary);
        return;
      }

      if (!is_function_index_valid(FIdx))
        return;

      ip_upgradable_lock<ip_upgradable_mutex> u_lck(src_bin.bbmap_mtx);

      basic_block_t src = basic_block_at_address(Term.Addr, src_bin);
      basic_block_properties_t &src_bbprop = src_ICFG[src];

      ip_scoped_lock<ip_upgradable_mutex> e_lck(boost::move(u_lck));

      src_bbprop.insertDynTarget(src_BIdx, std::make_pair(dst_BIdx, FIdx), jv);
    };

    switch (Term.Type) {
    case TERMINATOR::RETURN: {
      {
        ip_sharable_lock<ip_upgradable_mutex> s_lck(src_bin.bbmap_mtx);

        src_ICFG[basic_block_at_address(src_va, src_bin)].Term._return.Returns = true;
      }

      const taddr_t before_pc = dst_va - 1 - IsMIPSTarget * 4;

      ip_upgradable_lock<ip_upgradable_mutex> u_lck(dst_bin.bbmap_mtx);

      basic_block_t before_bb = basic_block_at_address(before_pc, dst_bin);
      basic_block_properties_t &before_bbprop = dst_ICFG[before_bb];
      auto &before_Term = before_bbprop.Term;

      bool isCall = before_Term.Type == TERMINATOR::CALL;
      bool isIndirectCall = before_Term.Type == TERMINATOR::INDIRECT_CALL;
      if (isCall || isIndirectCall) {
        assert(boost::out_degree(before_bb, dst_ICFG) <= 1);

        if (isCall) {
          if (likely(is_function_index_valid(before_Term._call.Target)))
            dst_bin.Analysis.Functions.at(before_Term._call.Target).Returns = true;
        }

        ip_scoped_lock<ip_upgradable_mutex> e_lck(boost::move(u_lck));

        boost::add_edge(before_bb, dst, dst_ICFG); /* connect */
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
        ip_sharable_lock<ip_upgradable_mutex> s_lck(src_bin.bbmap_mtx);

        IsDefinitelyTailCall(src_ICFG, basic_block_at_address(src_va, src_bin));
      });

      if (TailCall || src_BIdx != dst_BIdx) {
        handle_indirect_call();
      } else {
        assert(src_BIdx == dst_BIdx);

        ip_scoped_lock<ip_upgradable_mutex> e_lck(src_bin.bbmap_mtx);

        boost::add_edge(basic_block_at_address(src_va, src_bin), dst, src_ICFG);
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

  unsigned aux_nr_cpu = 0;

  {
    bool Failed = false;

    perf::data_reader perf_data("perf.data");

    oneapi::tbb::parallel_invoke(
        [&](void) -> void {
          if (IsVerbose())
            llvm::errs() << "gathering sideband files...\n";

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

          std::unique_ptr<scoped_fd> glbl_sb_ofd;
          std::vector<std::unique_ptr<scoped_fd>> sb_ofdv;

          static const std::string glbl_filename_suffix = "-sideband.pevent";

          using namespace std::placeholders;

          tbb::parallel_pipeline(
              1024,
              tbb::make_filter<void, std::string>(
                  tbb::filter_mode::serial_in_order,
                  std::bind(&IPTTool::GetLine, this, rfd->get(), _1)) &
                  tbb::make_filter<std::string, void>(
                      tbb::filter_mode::serial_in_order,
                      [&](const std::string &line) -> void {
                        char in_filename[4097];
                        char out_filename[4097];
                        uint64_t skip, count;

                        sscanf(
                            line.c_str(),
                            "dd if=%4096s of=%4096s conv=notrunc oflag=append "
                            "ibs=1 skip=%" PRIu64 " count=%" PRIu64
                            " status=none",
                            &in_filename[0], &out_filename[0], &skip, &count);

                        assert(strcmp(in_filename, "perf.data") == 0);

                        bool glbl = boost::algorithm::ends_with(
                            out_filename, glbl_filename_suffix);
                        int fd = -1;
                        if (glbl) {
                          std::unique_ptr<scoped_fd> &ofd = glbl_sb_ofd;
                          if (!ofd)
                            ofd = std::make_unique<scoped_fd>(
                                ::open("perf.data-sideband.pevent",
                                       O_WRONLY | O_CREAT | O_LARGEFILE, 0666));
                          fd = ofd->get();
                        } else {
                          unsigned cpu;
                          sscanf(out_filename,
                                 "perf.data-sideband-cpu%u.pevent", &cpu);
                          if (cpu >= sb_ofdv.size())
                            sb_ofdv.resize(cpu + 1);
                          std::unique_ptr<scoped_fd> &ofd = sb_ofdv.at(cpu);
                          if (!ofd)
                            ofd = std::make_unique<scoped_fd>(
                                ::open(out_filename,
                                       O_WRONLY | O_CREAT | O_LARGEFILE, 0666));
                          fd = ofd->get();
                        }

                        off_t the_off = skip;
                        if (robust_sendfile_from_fd(
                                fd, perf_data.contents.fd->get(), &the_off,
                                count) < 0)
                          WithColor::error() << llvm::formatv(
                              "sendfile failed: {0}\n", strerror(errno));
                      }));

          if (int ret = WaitForProcessToExit(pid)) {
            WithColor::error()
                << "failed to run libipt/script/perf-read-sideband.bash\n";
            Failed = true;
          } else {

            if (IsVerbose())
              llvm::errs() << "gathered sideband files.\n";
          }
        },
        [&](void) -> void {
          std::vector<std::unique_ptr<scoped_fd>> aux_ofdv;
          perf_data.for_each_auxtrace(
              [&](const struct perf::auxtrace_event &aux) {
                if (unlikely(aux.cpu >= aux_ofdv.size())) {
                  aux_nr_cpu = aux.cpu + 1;
                  aux_ofdv.resize(aux_nr_cpu);
                }

                std::unique_ptr<scoped_fd> &aux_ofd = aux_ofdv.at(aux.cpu);
                if (!aux_ofd) {
                  std::string aux_ofname =
                      "perf.data-aux-idx" + std::to_string(aux.cpu) + ".bin";
                  aux_ofd = std::make_unique<scoped_fd>(
                      ::open(aux_ofname.c_str(),
                             O_WRONLY | O_CREAT | O_LARGEFILE, 0666));
                }

                off_t the_off =
                    (reinterpret_cast<uintptr_t>(&aux) + aux.header.size) -
                    reinterpret_cast<uintptr_t>(perf_data.contents.mmap->ptr);
                if (robust_sendfile_from_fd(aux_ofd->get(),
                                            perf_data.contents.fd->get(),
                                            &the_off, aux.size) < 0)
                  WithColor::error() << llvm::formatv("sendfile failed: {0}\n",
                                                      strerror(errno));
              });
        });

    if (Failed)
      return 1;
  }

  //
  // perf-get-opts (written for ptdump and ptxed)
  //
  fs::path path_to_opts = fs::path(temporary_dir()) / "get-opts.txt";

  fs::path path_to_get_opts = libipt_scripts_dir / "perf-get-opts.bash";
  if (RunExecutableToExit(
          path_to_get_opts.string(),
          [&](auto Arg) { Arg(path_to_get_opts.string()); },
          path_to_opts.c_str())) {
    WithColor::error() << "failed to run libipt/script/perf-get-opts.bash\n";
    return 1;
  }

  std::string opts_str = read_file_into_string(path_to_opts.c_str());
  boost::algorithm::trim(opts_str);

  std::vector<std::string> ptdump_args;
  boost::algorithm::split(ptdump_args, opts_str, boost::is_any_of(" "),
                          boost::token_compress_on);

  std::vector<char *> ptdump_argv;
  ptdump_argv.push_back(const_cast<char *>("ptdump"));
  for (std::string &argstr : ptdump_args)
    ptdump_argv.push_back(const_cast<char *>(argstr.c_str()));
  ptdump_argv.push_back(nullptr);

  if (IsVerbose())
    llvm::errs() << llvm::formatv("ptdump {0}\n", opts_str);

  std::vector<unsigned> cpuv;
  cpuv.resize(aux_nr_cpu);
  std::iota(cpuv.begin(), cpuv.end(), 0);

  std::for_each(
      std::execution::par_unseq,
      cpuv.begin(),
      cpuv.end(), [&](unsigned cpu) {
        std::string aux_fname =
            "perf.data-aux-idx" + std::to_string(cpu) + ".bin";
        if (!fs::exists(aux_fname))
          return;

        auto len = fs::file_size(aux_fname);

        if (IsVerbose())
          WithColor::note()
              << llvm::formatv("auxtrace size for cpu {0}: {1}\n", cpu, len);

        scoped_fd aux_fd(::open(aux_fname.c_str(), O_RDONLY));
        if (!aux_fd)
          die(std::string("failed to open \"") + aux_fname + "\"");

        scoped_mmap mmap(nullptr, len, PROT_READ, MAP_PRIVATE, aux_fd.get(), 0);

        if (!mmap)
          die(std::string("failed to mmap \"") + aux_fname + "\"");

        if (::madvise(mmap.ptr, mmap.len, MADV_SEQUENTIAL) < 0)
          WithColor::warning()
              << llvm::formatv("madvise failed: {0}\n", strerror(errno));

        IntelPT ipt(ptdump_argv.size() - 1, ptdump_argv.data(), jv, *E, cpu,
                    AddressSpace, mmap.ptr,
                    reinterpret_cast<uint8_t *>(mmap.ptr) + len);

        try {
          ipt.explore();
        } catch (const IntelPT::truncated_aux_exception &) {
          if (IsVerbose())
            WithColor::warning()
                << llvm::formatv("truncated aux (cpu {0})\n", cpu);
        }

        fflush(stdout);
        fflush(stderr);
      });

  return 0;
}
}

#endif /* x86 */
