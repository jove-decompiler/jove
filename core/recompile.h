#pragma once
#include "jove/jove.h"
#include "tcg.h"
#include <boost/filesystem.hpp>

namespace jove {

struct dso_properties_t {
  unsigned BIdx;
};

typedef boost::adjacency_list<boost::setS,           /* OutEdgeList */
                              boost::vecS,           /* VertexList */
                              boost::bidirectionalS, /* Directed */
                              dso_properties_t       /* VertexProperties */>
    dso_graph_t;

typedef dso_graph_t::vertex_descriptor dso_t;

struct recompiler_options_t {
  bool ForCBE = false;
  bool Verbose = false;
  unsigned VerbosityLevel = 0;
  std::string Output;
  bool ForeignLibs = true;
  bool RuntimeMT = true;
  bool DFSan = false;
  bool SkipCopyRelocHack = false;
  bool Optimize = false;
  bool CallStack = false;
  bool CheckEmulatedStackReturnAddress = false;
  bool Trace = false;
  bool DebugSjlj = false;
  bool ABICalls = true;
  bool InlineHelpers = false;
  bool BreakBeforeUnreachables = false;
  bool LayOutSections = false;
  bool PlaceSectionBreakpoints = false;

  bool IsVerbose(void) const { return VerbosityLevel >= 1; };
  bool IsVeryVerbose(void) const { return VerbosityLevel >= 2; };

  tcg_global_set_t PinnedEnvGlbs = InitPinnedEnvGlbs;

  std::string temp_dir;
};

template <bool MT, bool MinSize>
class recompiler_t {
  using jv_t = jv_base_t<MT, MinSize>;
  using binary_t = binary_base_t<MT, MinSize>;
  using icfg_t = ip_icfg_base_t<MT>;
  using bb_t = typename ip_icfg_base_t<MT>::vertex_descriptor;

  const jv_t &jv;

  const recompiler_options_t &opts;
  tiny_code_generator_t &TCG;

  locator_t &locator_;

  struct binary_state_t {
    std::unique_ptr<llvm::object::Binary> Bin;

    boost::filesystem::path chrooted_path;

    uint64_t Base = 0, End = 0;

    struct {
      std::optional<std::string> interp;
    } _elf;

    std::vector<std::string> needed_vec;
    struct {
      std::vector<std::string> needed_delay_vec;
    } _coff;
    std::string soname;
    dso_t dso;

    binary_state_t(const binary_t &b) { Bin = B::Create(b.data()); }
  };

  jv_state_t<binary_state_t, void, void, AreWeMT, true, false, true, true, MT,
             MinSize>
      state;

  const bool IsCOFF;

  boost::unordered::unordered_flat_map<
      std::string, boost::unordered::unordered_flat_set<binary_index_t>>
      soname_map;

  dso_graph_t dso_graph;

  std::atomic<bool> worker_failed = false;

  bool IsVerbose(void) const { return opts.VerbosityLevel >= 1; };
  bool IsVeryVerbose(void) const { return opts.VerbosityLevel >= 2; };
  const std::string &temporary_dir(void) const { return opts.temp_dir; }
  locator_t &locator(void) { return locator_; }

public:
  recompiler_t(const jv_t &jv, const recompiler_options_t &opts,
               tiny_code_generator_t &TCG, locator_t &locator_)
      : jv(jv), opts(opts), TCG(TCG), locator_(locator_), state(jv),
        IsCOFF(B::is_coff(*state.for_binary(jv.Binaries.at(0)).Bin)) {
    if (IsCOFF) {
      if (!opts.ForeignLibs)
        throw std::runtime_error("COFF is only supported in executable-only mode");
    }
  }

  int go(void);

private:
  void worker(dso_t dso);
  void write_dso_graphviz(std::ostream &out, const dso_graph_t &);

  binary_index_t ChooseBinaryWithSoname(const std::string &soname);
};

}
