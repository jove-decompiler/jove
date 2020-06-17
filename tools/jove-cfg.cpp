#include "tcgcommon.hpp"

#include <memory>
#include <boost/filesystem.hpp>
#include <cinttypes>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/WithColor.h>
#include <llvm/Target/TargetMachine.h>
#include <sys/wait.h>

#include <boost/icl/split_interval_map.hpp>

#include "jove/jove.h"
#include <boost/format.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/serialization/bitset.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/set.hpp>
#include <boost/graph/filtered_graph.hpp>
#include <boost/graph/breadth_first_search.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/graph/graphviz.hpp>
#include <boost/unordered_set.hpp>

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace opts {
  static cl::OptionCategory JoveCategory("Specific Options");

  static cl::opt<std::string> jv("decompilation", cl::desc("Jove decompilation"),
				 cl::Required, cl::cat(JoveCategory));

  static cl::alias jvAlias("d", cl::desc("Alias for --decompilation."),
			   cl::aliasopt(jv), cl::cat(JoveCategory));

  static cl::opt<std::string> Binary("binary", cl::desc("Binary of function"),
                                     cl::Required, cl::cat(JoveCategory));

  static cl::alias BinaryAlias("b", cl::desc("Alias for --binary."),
                               cl::aliasopt(Binary), cl::cat(JoveCategory));

  static cl::opt<std::string> FunctionAddress(cl::Positional,
                                              cl::desc("<address>"),
                                              cl::Required,
                                              cl::cat(JoveCategory));
}

namespace jove {
static int cfg(void);
}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::ParseCommandLineOptions(argc, argv, "CFG Visualizer\n");

  return jove::cfg();
}

namespace jove {

typedef boost::format fmt;

static binary_index_t BinaryIndex = invalid_binary_index;

#if defined(__x86_64__) || defined(__aarch64__) || defined(__mips64)
typedef typename obj::ELF64LEObjectFile ELFO;
typedef typename obj::ELF64LEFile ELFT;
#elif defined(__i386__) || defined(__mips__)
typedef typename obj::ELF32LEObjectFile ELFO;
typedef typename obj::ELF32LEFile ELFT;
#else
#error
#endif

typedef typename ELFT::Elf_Dyn Elf_Dyn;
typedef typename ELFT::Elf_Dyn_Range Elf_Dyn_Range;
typedef typename ELFT::Elf_Phdr Elf_Phdr;
typedef typename ELFT::Elf_Phdr_Range Elf_Phdr_Range;
typedef typename ELFT::Elf_Rela Elf_Rela;
typedef typename ELFT::Elf_Shdr Elf_Shdr;
typedef typename ELFT::Elf_Shdr_Range Elf_Shdr_Range;
typedef typename ELFT::Elf_Sym Elf_Sym;
typedef typename ELFT::Elf_Sym_Range Elf_Sym_Range;

template <class T>
static T unwrapOrError(llvm::Expected<T> EO) {
  if (EO)
    return *EO;

  std::string Buf;
  {
    llvm::raw_string_ostream OS(Buf);
    llvm::logAllUnhandledErrors(EO.takeError(), OS, "");
  }
  fprintf(stderr, "%s\n", Buf.c_str());
  exit(1);
}

static int await_process_completion(pid_t);

struct reached_visitor : public boost::default_bfs_visitor {
  boost::unordered_set<basic_block_t> &out;

  reached_visitor(boost::unordered_set<basic_block_t> &out) : out(out) {}

  void discover_vertex(basic_block_t bb,
                       const interprocedural_control_flow_graph_t &) const {
    out.insert(bb);
  }
};

//
// globals
//
static decompilation_t Decompilation;

typedef boost::filtered_graph<
    interprocedural_control_flow_graph_t,
    boost::keep_all,
    boost::is_in_subset<boost::unordered_set<basic_block_t>>>
    control_flow_graph_t;

static std::string disassemble_basic_block(const control_flow_graph_t &G,
					   control_flow_graph_t::vertex_descriptor);

static std::unique_ptr<tiny_code_generator_t> TCG;

static llvm::Triple TheTriple;
static llvm::SubtargetFeatures Features;

static const llvm::Target *TheTarget;
static std::unique_ptr<const llvm::MCRegisterInfo> MRI;
static std::unique_ptr<const llvm::MCAsmInfo> AsmInfo;
static std::unique_ptr<const llvm::MCSubtargetInfo> STI;
static std::unique_ptr<const llvm::MCInstrInfo> MII;
static std::unique_ptr<llvm::MCObjectFileInfo> MOFI;
static std::unique_ptr<llvm::MCContext> MCCtx;
static std::unique_ptr<llvm::MCDisassembler> DisAsm;
static std::unique_ptr<llvm::MCInstPrinter> IP;
static std::unique_ptr<llvm::TargetMachine> TM;

struct section_properties_t {
  llvm::StringRef name;
  llvm::ArrayRef<uint8_t> contents;

  bool operator==(const section_properties_t &sect) const {
    return name == sect.name;
  }

  bool operator<(const section_properties_t &sect) const {
    return name < sect.name;
  }
};

typedef std::set<section_properties_t> section_properties_set_t;
static boost::icl::split_interval_map<std::uintptr_t, section_properties_set_t>
    SectMap;

struct graphviz_label_writer {
  const control_flow_graph_t &cfg;

  graphviz_label_writer(const control_flow_graph_t &cfg) : cfg(cfg) {}

  void operator()(std::ostream &out,
                  const control_flow_graph_t::vertex_descriptor &v) const {
    std::string src = disassemble_basic_block(cfg, v);

    src.reserve(2 * src.size());

    boost::replace_all(src, "\\", "\\\\");
    boost::replace_all(src, "\r\n", "\\l");
    boost::replace_all(src, "\n", "\\l");
    boost::replace_all(src, "\"", "\\\"");
    boost::replace_all(src, "{", "\\{");
    boost::replace_all(src, "}", "\\}");
    boost::replace_all(src, "|", "\\|");
    boost::replace_all(src, "|", "\\|");
    //boost::replace_all(src, "<", "\\<");
    //boost::replace_all(src, ">", "\\>");
    boost::replace_all(src, "(", "\\(");
    boost::replace_all(src, ")", "\\)");
    //boost::replace_all(src, ",", "\\,");
    boost::replace_all(src, ";", "\\;");
    //boost::replace_all(src, ":", "\\:");
    //boost::replace_all(src, " ", "\\ ");

    out << "[label=\"";
    out << src;
    out << "\"]";
  }
};

static std::string disassemble_basic_block(const control_flow_graph_t &G,
					   control_flow_graph_t::vertex_descriptor V) {
  assert(BinaryIndex != invalid_binary_index);

  const binary_t &binary = Decompilation.Binaries[BinaryIndex];

  auto it = SectMap.find(G[V].Addr);
  if (it == SectMap.end()) {
    WithColor::warning() << llvm::formatv("no section for given address {0:x}",
                                          G[V].Addr);
    return "ERROR";
  }

  const auto &SectProp = *(*it).second.begin();
  const uintptr_t SectBase = (*it).first.lower();

  TCG->set_section(SectBase, SectProp.contents.data());

  std::string res = (fmt("%08x [%u]\n\n") % G[V].Addr % G[V].Size).str();

  uint64_t InstLen = 0;
  for (uintptr_t A = G[V].Addr; A < G[V].Addr + G[V].Size; A += InstLen) {
    llvm::MCInst Inst;

    std::string errmsg;
    bool Disassembled;
    {
      llvm::raw_string_ostream ErrorStrStream(errmsg);

      ptrdiff_t Offset = A - SectBase;
      Disassembled = DisAsm->getInstruction(
          Inst, InstLen, SectProp.contents.slice(Offset), A, ErrorStrStream);
    }

    if (!Disassembled) {
      res.append("failed to disassemble");
      if (!errmsg.empty()) {
	res.append(": ");
        res.append(errmsg);
      }
      res.push_back('\n');
      break;
    }

    std::string line;
    {
      llvm::raw_string_ostream StrStream(line);
      IP->printInst(&Inst, A, "", *STI, StrStream);
    }
    boost::trim(line);

    res.append((fmt("%08x   ") % A).str());
    res.append(line);
    res.push_back('\n');
  }

  res.push_back('\n');
  res.append(description_of_terminator(G[V].Term.Type));
  res.push_back('\n');

  return res;
}

struct graphviz_edge_prop_writer {
  const control_flow_graph_t &cfg;
  graphviz_edge_prop_writer(const control_flow_graph_t &cfg) : cfg(cfg) {}

  template <class Edge>
  void operator()(std::ostream &out, const Edge &e) const {
    static const char *edge_type_styles[] = {
        "solid", "dashed", /*"invis"*/ "dotted"
    };

    out << "[style=\"" << edge_type_styles[0] << "\"]";
  }
};

struct graphviz_prop_writer {
  void operator()(std::ostream &out) const {
    out << "fontname = \"Courier\"\n"
           "fontsize = 10\n"
           "\n"
           "node [\n"
           "fontname = \"Courier\"\n"
           "fontsize = 10\n"
           "shape = \"record\"\n"
           "]\n"
           "\n"
           "edge [\n"
           "fontname = \"Courier\"\n"
           "fontsize = 10\n"
           "]\n"
           "\n";
  }
};

static void print_command(const char **argv);

static char tmpdir[] = {'/', 't', 'm', 'p', '/', 'X',
                        'X', 'X', 'X', 'X', 'X', '\0'};

int cfg(void) {
  if (!fs::exists(opts::jv)) {
    WithColor::error() << "can't find decompilation.jv\n";
    return 1;
  }

  //
  // parse the existing decompilation
  //
  {
    std::ifstream ifs(fs::is_directory(opts::jv)
                          ? (fs::path(opts::jv) / "decompilation.jv").string()
                          : opts::jv);

    boost::archive::binary_iarchive ia(ifs);
    ia >> Decompilation;
  }

  assert(!opts::FunctionAddress.empty());

  //
  // find the binary of interest
  //
  BinaryIndex = invalid_binary_index;

  for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    const binary_t &binary = Decompilation.Binaries[BIdx];
    if (binary.Path.find(opts::Binary) == std::string::npos)
      continue;

    BinaryIndex = BIdx;
    break;
  }

  if (BinaryIndex == invalid_binary_index) {
    WithColor::error() << llvm::formatv("failed to find binary \"{0}\"\n",
                                        opts::Binary);
    return 1;
  }

  const binary_t &binary = Decompilation.Binaries[BinaryIndex];

  //
  // initialize state associated with binary
  //
  TCG.reset(new tiny_code_generator_t);

  // Initialize targets and assembly printers/parsers.
  llvm::InitializeNativeTarget();
  llvm::InitializeNativeTargetDisassembler();

  llvm::StringRef Buffer(reinterpret_cast<const char *>(&binary.Data[0]),
                         binary.Data.size());
  llvm::StringRef Identifier(binary.Path);
  llvm::MemoryBufferRef MemBuffRef(Buffer, Identifier);

  llvm::Expected<std::unique_ptr<obj::Binary>> BinaryOrErr =
      obj::createBinary(MemBuffRef);

  if (!BinaryOrErr) {
    fprintf(stderr, "failed to open %s\n", opts::Binary.c_str());
    return 1;
  }

  obj::Binary *B = BinaryOrErr.get().get();
  if (!llvm::isa<ELFO>(B)) {
    fprintf(stderr, "invalid binary\n");
    return 1;
  }

  const ELFO &O = *llvm::cast<ELFO>(B);
  const ELFT &E = *O.getELFFile();

  std::string ArchName;
  llvm::Triple TheTriple = O.makeTriple();
  std::string Error;

  TheTarget = llvm::TargetRegistry::lookupTarget(ArchName, TheTriple, Error);
  if (!TheTarget) {
    fprintf(stderr, "failed to lookup target: %s\n", Error.c_str());
    return 1;
  }

  std::string TripleName = TheTriple.getTriple();
  std::string MCPU;
  llvm::SubtargetFeatures Features = O.getFeatures();

  MRI.reset(TheTarget->createMCRegInfo(TripleName));
  if (!MRI) {
    fprintf(stderr, "no register info for target\n");
    return 1;
  }

  {
    llvm::MCTargetOptions Options;
    AsmInfo.reset(
	TheTarget->createMCAsmInfo(*MRI, TripleName, Options));
  }
  if (!AsmInfo) {
    fprintf(stderr, "no assembly info\n");
    return 1;
  }

  STI.reset(
      TheTarget->createMCSubtargetInfo(TripleName, MCPU, Features.getString()));
  if (!STI) {
    fprintf(stderr, "no subtarget info\n");
    return 1;
  }

  MII.reset(TheTarget->createMCInstrInfo());
  if (!MII) {
    fprintf(stderr, "no instruction info\n");
    return 1;
  }

  MOFI.reset(new llvm::MCObjectFileInfo);
  MCCtx.reset(new llvm::MCContext(AsmInfo.get(), MRI.get(), MOFI.get()));

  // FIXME: for now initialize MCObjectFileInfo with default values
  MOFI->InitMCObjectFileInfo(TheTriple, false, *MCCtx);

  DisAsm.reset(TheTarget->createMCDisassembler(*STI, *MCCtx));
  if (!DisAsm) {
    fprintf(stderr, "no disassembler for target\n");
    return 1;
  }

  int AsmPrinterVariant =
#if defined(__x86_64__) || defined(__i386__)
      1
#else
      AsmInfo->getAssemblerDialect()
#endif
      ;
  IP.reset(TheTarget->createMCInstPrinter(
      llvm::Triple(TripleName), AsmPrinterVariant, *AsmInfo, *MII, *MRI));
  if (!IP) {
    fprintf(stderr, "no instruction printer\n");
    return 1;
  }

  //
  // build section map
  //
  for (const Elf_Shdr &Sec : unwrapOrError(E.sections())) {
    if (!(Sec.sh_flags & llvm::ELF::SHF_ALLOC))
      continue;

    llvm::Expected<llvm::ArrayRef<uint8_t>> contents =
        E.getSectionContents(&Sec);

    if (!contents)
      continue;

    llvm::Expected<llvm::StringRef> name = E.getSectionName(&Sec);

    if (!name)
      continue;

    boost::icl::interval<std::uintptr_t>::type intervl =
        boost::icl::interval<std::uintptr_t>::right_open(
            Sec.sh_addr, Sec.sh_addr + Sec.sh_size);

    section_properties_t sectprop;
    sectprop.name = *name;
    sectprop.contents = *contents;

    SectMap.add({intervl, {sectprop}});
  }

  //
  // find the function of interest
  //
  function_index_t FunctionIndex = invalid_function_index;

  assert(!opts::FunctionAddress.empty());
  uintptr_t FuncAddr = std::stoi(opts::FunctionAddress.c_str(), 0, 16);

  const auto &ICFG = binary.Analysis.ICFG;

  for (function_index_t FIdx = 0; FIdx < binary.Analysis.Functions.size(); ++FIdx) {
    const function_t &f = binary.Analysis.Functions[FIdx];

    uintptr_t EntryAddr = ICFG[boost::vertex(f.Entry, ICFG)].Addr;
    if (EntryAddr != FuncAddr)
      continue;

    FunctionIndex = FIdx;
    break;
  }

  if (FunctionIndex == invalid_function_index) {
    WithColor::error() << llvm::formatv(
        "failed to find function matching given address ({0:x})\n", FuncAddr);
    return 1;
  }

  const function_t &f = binary.Analysis.Functions[FunctionIndex];

  boost::unordered_set<basic_block_t> blocks;

  reached_visitor vis(blocks);
  boost::breadth_first_search(ICFG, f.Entry, boost::visitor(vis));

  boost::keep_all e_filter;
  boost::is_in_subset<boost::unordered_set<basic_block_t>> v_filter(blocks);

  control_flow_graph_t cfg(ICFG, e_filter, v_filter);

  //
  // create temporary directory
  //
  if (!mkdtemp(tmpdir)) {
    WithColor::error() << "mkdtemp failed : " << strerror(errno) << '\n';
    return 1;
  }

  llvm::outs() << "tmpdir: " << tmpdir << '\n';

  std::string dot_path = (fs::path(tmpdir) / "cfg.dot").string();

  //
  // generate graphviz
  //
  {
    std::ofstream ofs(dot_path);

    std::map<control_flow_graph_t::vertex_descriptor, int> idx_map;
    {
      int i = 0;
      control_flow_graph_t::vertex_iterator vi, vi_end;
      for (std::tie(vi, vi_end) = boost::vertices(cfg); vi != vi_end; ++vi)
        idx_map[*vi] = i++;
    }

    boost::write_graphviz(
        ofs, cfg,
	graphviz_label_writer(cfg),
        graphviz_edge_prop_writer(cfg),
	graphviz_prop_writer(),
        boost::associative_property_map<std::map<control_flow_graph_t::vertex_descriptor, int>>(idx_map));
  }

  //
  // graph-easy
  //
  bool haveGraphEasy = fs::exists("/usr/bin/vendor_perl/graph-easy") ||
                       fs::exists("/usr/bin/graph-easy");

  if (haveGraphEasy) {
    pid_t pid = fork();
    if (!pid) {
      std::string input_arg = "--input=" + dot_path;

      const char *arg_arr[] = {
        fs::exists("/usr/bin/vendor_perl/graph-easy")
            ? "/usr/bin/vendor_perl/graph-easy"
            : "/usr/bin/graph-easy",

        input_arg.c_str(),
#if 0
	"--as=ascii",
#else
        "--as=boxart",
#endif

        nullptr
      };

      print_command(&arg_arr[0]);

      close(STDIN_FILENO);
      execve(arg_arr[0], const_cast<char **>(&arg_arr[0]), ::environ);

      int err = errno;
      WithColor::error() << llvm::formatv("execve failed: {0}\n",
                                          strerror(err));
      return 1;
    }

    //
    // check exit code
    //
    if (await_process_completion(pid))
      WithColor::warning() << "graph-easy failed for " << dot_path << '\n';
  } else {
    WithColor::error() << "failed to find graph-easy executable file\n";
  }

  return 0;
}

void _qemu_log(const char *cstr) {
  fputs(cstr, stdout);
}

int await_process_completion(pid_t pid) {
  int wstatus;
  do {
    if (waitpid(pid, &wstatus, WUNTRACED | WCONTINUED) < 0)
      abort();

    if (WIFEXITED(wstatus)) {
      //printf("exited, status=%d\n", WEXITSTATUS(wstatus));
      return WEXITSTATUS(wstatus);
    } else if (WIFSIGNALED(wstatus)) {
      //printf("killed by signal %d\n", WTERMSIG(wstatus));
      return 1;
    } else if (WIFSTOPPED(wstatus)) {
      //printf("stopped by signal %d\n", WSTOPSIG(wstatus));
      return 1;
    } else if (WIFCONTINUED(wstatus)) {
      //printf("continued\n");
    }
  } while (!WIFEXITED(wstatus) && !WIFSIGNALED(wstatus));

  abort();
}

void print_command(const char **argv) {
  for (const char **s = argv; *s; ++s)
    llvm::outs() << *s << ' ';

  llvm::outs() << '\n';
}

}
