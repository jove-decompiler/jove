#include "syscall_nrs.hpp"

namespace jove {

static llvm::DataLayout DL("");

static decompilation_t Decompilation;

static std::unique_ptr<tiny_code_generator_t> TCG;
static std::unique_ptr<llvm::LLVMContext> Context;
static std::unique_ptr<llvm::Module> Module;

typedef boost::format fmt;

static tcg_global_set_t CmdlinePinnedEnvGlbs = PinnedEnvGlbs;

struct helper_function_t {
  llvm::Function *F;
  int EnvArgNo;

  struct {
    bool Simple;
    tcg_global_set_t InGlbs, OutGlbs;
  } Analysis;
};

static std::unordered_map<uintptr_t, helper_function_t> HelperFuncMap;

static bool AnalyzeHelper(helper_function_t &hf);

static void explode_tcg_global_set(std::vector<unsigned> &out,
                                   tcg_global_set_t glbs) {
  if (glbs.none())
    return;

  out.reserve(glbs.count());

  constexpr bool FitsInUnsignedLongLong =
      tcg_num_globals <= sizeof(unsigned long long) * 8;

  if (FitsInUnsignedLongLong) { /* use ffsll */
    unsigned long long x = glbs.to_ullong();

    int idx = 0;
    do {
      int pos = ffsll(x);
      x >>= pos;
      idx += pos;
      out.push_back(idx - 1);
    } while (x);
  } else {
    for (size_t glb = glbs._Find_first(); glb < glbs.size();
         glb = glbs._Find_next(glb))
      out.push_back(glb);
  }
}

template <typename Graph>
struct graphviz_label_writer {
  const Graph &G;

  graphviz_label_writer(const Graph &G) : G(G) {}

  template <typename Vertex>
  void operator()(std::ostream &out, Vertex V) const {
    std::string str;

    str += (fmt("%#lx") % G[V].Addr).str();

    str.push_back('\n');
    str.push_back('[');
    {
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, G[V].IN);
      bool first = true;
      for (unsigned glb : glbv) {
        if (!first)
          str.push_back(' ');

        str += TCG->_ctx.temps[glb].name;

        first = false;
      }
    }
    str.push_back(']');

    str.push_back('\n');

    str.push_back('[');
    {
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, G[V].OUT);
      bool first = true;
      for (unsigned glb : glbv) {
        if (!first)
          str.push_back(' ');

        str += TCG->_ctx.temps[glb].name;

        first = false;
      }
    }
    str.push_back(']');

    boost::replace_all(str, "\\", "\\\\");
    boost::replace_all(str, "\r\n", "\\l");
    boost::replace_all(str, "\n", "\\l");
    boost::replace_all(str, "\"", "\\\"");
    boost::replace_all(str, "{", "\\{");
    boost::replace_all(str, "}", "\\}");
    boost::replace_all(str, "|", "\\|");
    boost::replace_all(str, "|", "\\|");
    boost::replace_all(str, "<", "\\<");
    boost::replace_all(str, ">", "\\>");
    boost::replace_all(str, "(", "\\(");
    boost::replace_all(str, ")", "\\)");
    boost::replace_all(str, ",", "\\,");
    boost::replace_all(str, ";", "\\;");
    boost::replace_all(str, ":", "\\:");
    boost::replace_all(str, " ", "\\ ");

    out << "[shape=box label=\"";
    out << str;
    out << "\"]";
  }
};

struct flow_vertex_properties_t {
  const basic_block_properties_t *bbprop;

  tcg_global_set_t IN, OUT;
};

struct flow_edge_properties_t {
  struct {
    tcg_global_set_t mask = ~tcg_global_set_t();
  } reach;
};

typedef boost::adjacency_list<boost::setS,              /* OutEdgeList */
                              boost::vecS,              /* VertexList */
                              boost::bidirectionalS,    /* Directed */
                              flow_vertex_properties_t, /* VertexProperties */
                              flow_edge_properties_t    /* EdgeProperties */>
    flow_graph_t;

typedef flow_graph_t::vertex_descriptor flow_vertex_t;
typedef flow_graph_t::edge_descriptor flow_edge_t;

struct vertex_copier {
  const interprocedural_control_flow_graph_t &ICFG;
  flow_graph_t &G;

  vertex_copier(const interprocedural_control_flow_graph_t &ICFG,
                flow_graph_t &G)
      : ICFG(ICFG), G(G) {}

  void operator()(basic_block_t bb, flow_vertex_t V) const {
    G[V].bbprop = &ICFG[bb];
  }
};

struct edge_copier {
  void operator()(control_flow_t, flow_edge_t) const {}
};

static const basic_block_properties_t EmptyBBProp{};

static flow_vertex_t copy_function_cfg(flow_graph_t &G,
                                       function_t &f,
                                       std::vector<flow_vertex_t> &exitVertices,
                                       std::unordered_map<function_t *, std::pair<flow_vertex_t, std::vector<flow_vertex_t>>> &memoize) {
  //
  // make sure basic blocks have been analyzed
  //
  auto &Binary = Decompilation.Binaries.at(f.BIdx);
  auto &ICFG = Binary.Analysis.ICFG;
  for (basic_block_t bb : f.BasicBlocks)
    ICFG[bb].Analyze(f.BIdx);

  //
  // have we already copied this function's CFG?
  //
  {
    auto it = memoize.find(&f);
    if (it != memoize.end()) {
      exitVertices = (*it).second.second;
      return (*it).second.first;
    }
  }

  assert(!f.BasicBlocks.empty());

  //
  // copy the function's CFG into the flow graph, maintaining a mapping from the
  // CFG's basic blocks to the flow graph vertices
  //
  std::map<basic_block_t, flow_vertex_t> Orig2CopyMap;
  {
    vertex_copier vc(ICFG, G);
    edge_copier ec;

    boost::copy_component(
        ICFG, f.BasicBlocks.front(), G,
        boost::orig_to_copy(
            boost::associative_property_map<
                std::map<basic_block_t, flow_vertex_t>>(Orig2CopyMap))
            .vertex_copy(vc)
            .edge_copy(ec));
  }

  flow_vertex_t res;
  {
    auto it = Orig2CopyMap.find(f.BasicBlocks.front());
    assert(it != Orig2CopyMap.end());
    res = (*it).second;
  }

  exitVertices.resize(f.ExitBasicBlocks.size());
  std::transform(f.ExitBasicBlocks.begin(),
                 f.ExitBasicBlocks.end(),
                 exitVertices.begin(),
                 [&](basic_block_t bb) -> flow_vertex_t {
                   auto it = Orig2CopyMap.find(bb);
                   assert(it != Orig2CopyMap.end());
                   return (*it).second;
                 });

  memoize.insert({&f, {res, exitVertices}});

  //
  // this recursive function's duty is also to inline calls to functions and
  // indirect jumps
  //
  for (basic_block_t bb : f.BasicBlocks) {
    function_t *callee_ptr = nullptr;

    switch (ICFG[bb].Term.Type) {
    case TERMINATOR::INDIRECT_CALL: {
      auto &DynTargets = ICFG[bb].DynTargets;
      if (DynTargets.empty())
        continue;

      std::vector<std::pair<binary_index_t, function_index_t>> DynTargetSampled;
      std::sample(DynTargets.begin(), DynTargets.end(),
                  std::back_inserter(DynTargetSampled), 1,
                  std::mt19937{std::random_device{}()});

      assert(DynTargetSampled.size() == 1);

      auto &DynTarget = DynTargetSampled.front();

      callee_ptr = &Decompilation.Binaries[DynTarget.first]
                        .Analysis.Functions[DynTarget.second];
      /* fallthrough */
    }

    case TERMINATOR::CALL: {
      function_t &callee =
          callee_ptr ? *callee_ptr
                     : Binary.Analysis.Functions.at(ICFG[bb].Term._call.Target);

      std::vector<flow_vertex_t> calleeExitVertices;
      flow_vertex_t calleeEntryV =
          copy_function_cfg(G, callee, calleeExitVertices, memoize);

      boost::add_edge(Orig2CopyMap[bb], calleeEntryV, G);

      auto eit_pair = boost::out_edges(bb, ICFG);
      if (eit_pair.first == eit_pair.second)
        break;

      assert(eit_pair.first != eit_pair.second &&
             std::next(eit_pair.first) == eit_pair.second);

      flow_vertex_t succV = Orig2CopyMap[boost::target(*eit_pair.first, ICFG)];

      boost::remove_edge(Orig2CopyMap[bb], succV, G);

      for (flow_vertex_t exitV : calleeExitVertices) {
        flow_edge_t E = boost::add_edge(exitV, succV, G).first;
        if (callee.IsABI)
          G[E].reach.mask = CallConvRets;
      }

      break;
    }

    case TERMINATOR::INDIRECT_JUMP: {
      auto it = std::find(exitVertices.begin(),
                          exitVertices.end(),
                          Orig2CopyMap[bb]);
      if (it == exitVertices.end())
        continue;

      const auto &DynTargets = ICFG[bb].DynTargets;
      if (DynTargets.empty())
        continue;

      std::vector<std::pair<binary_index_t, function_index_t>> DynTargetSampled;
      std::sample(DynTargets.begin(), DynTargets.end(),
                  std::back_inserter(DynTargetSampled), 1,
                  std::mt19937{std::random_device{}()});

      assert(DynTargetSampled.size() == 1);

      auto &DynTarget = DynTargetSampled.front();

      auto eit_pair = boost::out_edges(bb, ICFG);
      assert(eit_pair.first == eit_pair.second);

      function_t &callee = Decompilation.Binaries[DynTarget.first]
                               .Analysis.Functions[DynTarget.second];

      std::vector<flow_vertex_t> calleeExitVertices;
      flow_vertex_t calleeEntryV =
          copy_function_cfg(G, callee, calleeExitVertices, memoize);
      flow_vertex_t newExitV = boost::add_vertex(G);
      G[newExitV].bbprop = &EmptyBBProp;

      boost::add_edge(Orig2CopyMap[bb], calleeEntryV, G);

      for (flow_vertex_t V : calleeExitVertices) {
        flow_edge_t E = boost::add_edge(V, newExitV, G).first;
        if (callee.IsABI)
          G[E].reach.mask = CallConvRets;
      }

      exitVertices.erase(it);
      exitVertices.push_back(newExitV);
      break;
    }

    default:
      continue;
    }
  }

  return res;
}

template <typename GraphTy>
struct dfs_visitor : public boost::default_dfs_visitor {
  typedef typename GraphTy::vertex_descriptor VertTy;

  std::vector<VertTy> &out;

  dfs_visitor(std::vector<VertTy> &out) : out(out) {}

  void discover_vertex(VertTy v, const GraphTy &) const { out.push_back(v); }
};

void function_t::Analyze(void) {
  if (!this->Analysis.Stale)
    return;
  this->Analysis.Stale = false;

  {
    flow_graph_t G;

    std::unordered_map<function_t *,
                       std::pair<flow_vertex_t, std::vector<flow_vertex_t>>>
        memoize;

    std::vector<flow_vertex_t> exitVertices;
    flow_vertex_t entryV = copy_function_cfg(G, *this, exitVertices, memoize);

    //
    // build vector of vertices in DFS order
    //
    std::vector<flow_vertex_t> Vertices;
    Vertices.reserve(boost::num_vertices(G));

    {
      dfs_visitor<flow_graph_t> vis(Vertices);

      std::map<flow_vertex_t, boost::default_color_type> colorMap;
#if 0
    boost::depth_first_visit(
        G, entryV, vis,
        boost::associative_property_map<
            std::map<flow_vertex_t, boost::default_color_type>>(colorMap));
#else
      boost::depth_first_search(
          G, vis,
          boost::associative_property_map<
              std::map<flow_vertex_t, boost::default_color_type>>(colorMap));
#endif
    }

    bool change;

    //
    // liveness analysis
    //
    for (flow_vertex_t V : Vertices) {
      G[V].IN.reset();
      G[V].OUT.reset();
    }

    do {
      change = false;

      for (flow_vertex_t V : boost::adaptors::reverse(Vertices)) {
        const tcg_global_set_t _IN = G[V].IN;

        auto eit_pair = boost::out_edges(V, G);
        G[V].OUT = std::accumulate(
            eit_pair.first,
            eit_pair.second,
            tcg_global_set_t(),
            [&](tcg_global_set_t res, flow_edge_t E) -> tcg_global_set_t {
              return res | G[boost::target(E, G)].IN;
            });

        tcg_global_set_t use = G[V].bbprop->Analysis.live.use;
        tcg_global_set_t def = G[V].bbprop->Analysis.live.def;

        G[V].IN = use | (G[V].OUT & ~def);

        change = change || _IN != G[V].IN;
      }
    } while (change);

    this->Analysis.args = G[entryV].IN & ~(NotArgs | CmdlinePinnedEnvGlbs);

    //
    // reaching definitions
    //
    for (flow_vertex_t V : Vertices) {
      G[V].IN.reset();
      G[V].OUT.reset();
    }

    do {
      change = false;

      for (flow_vertex_t V : Vertices) {
        const tcg_global_set_t _OUT = G[V].OUT;

        auto eit_pair = boost::in_edges(V, G);
        G[V].IN = std::accumulate(
            eit_pair.first,
            eit_pair.second,
            tcg_global_set_t(),
            [&](tcg_global_set_t res, flow_edge_t E) -> tcg_global_set_t {
              return res | (G[boost::source(E, G)].OUT & G[E].reach.mask);
            });
        G[V].OUT = G[V].bbprop->Analysis.reach.def | G[V].IN;

        change = change || _OUT != G[V].OUT;
      }
    } while (change);

    if (exitVertices.empty()) {
      this->Analysis.rets.reset();
    } else {
      this->Analysis.rets =
          std::accumulate(
              exitVertices.begin(),
              exitVertices.end(),
              ~tcg_global_set_t(),
              [&](tcg_global_set_t res, flow_vertex_t V) -> tcg_global_set_t {
                return res & G[V].OUT;
              }) &
          ~(NotRets | CmdlinePinnedEnvGlbs);
    }
  }

  if (this->IsABI) {
#if 0
    //
    // for ABI's, if we need a return register whose index > 0, then we will
    // infer that all the preceeding return registers are live as well
    //
    std::vector<unsigned> glbv;
    explode_tcg_global_set(glbv, this->Analysis.rets);
    std::sort(glbv.begin(), glbv.end(), [](unsigned a, unsigned b) {
      return std::find(CallConvRetArray.begin(), CallConvRetArray.end(), a) <
             std::find(CallConvRetArray.begin(), CallConvRetArray.end(), b);
    });

    auto rit = std::accumulate(
        glbv.begin(), glbv.end(), CallConvRetArray.crend(),
        [](CallConvArgArrayTy::const_reverse_iterator res, unsigned glb) {
          return std::min(res, std::find(CallConvRetArray.crbegin(),
                                         CallConvRetArray.crend(), glb));
        });

    if (rit != CallConvRetArray.crend()) {
      unsigned idx = std::distance(CallConvRetArray.cbegin(), rit.base()) - 1;
      for (unsigned i = 0; i <= idx; ++i)
        this->Analysis.rets.set(CallConvRetArray[i]);
    }
#elif 0
    // XXX TODO
    assert(!CallConvRetArray.empty());
    if (this->Analysis.rets[CallConvRetArray.front()]) {
      this->Analysis.rets.reset();
      this->Analysis.rets.set(CallConvRetArray.front());
    } else {
      this->Analysis.rets.reset();
    }
#endif
  }

  //
  // for ABI's, if we need a register parameter whose index > 0, then we will
  // infer that all the preceeding paramter registers are live as well
  //
  if (this->IsABI) {
    std::vector<unsigned> glbv;
    explode_tcg_global_set(glbv, this->Analysis.args);

    auto rit = std::accumulate(
        glbv.begin(), glbv.end(), CallConvArgArray.crend(),
        [](CallConvArgArrayTy::const_reverse_iterator res, unsigned glb) {
          return std::min(res, std::find(CallConvArgArray.crbegin(),
                                         CallConvArgArray.crend(), glb));
        });

    if (rit != CallConvArgArray.crend()) {
      unsigned idx = std::distance(CallConvArgArray.cbegin(), rit.base()) - 1;
      for (unsigned i = 0; i <= idx; ++i)
        this->Analysis.args.set(CallConvArgArray[i]);
    }
  }

  //
  // all non-ABI functions will be passed the stack pointer, and will return
  // it as well. XXX if we know this to be a leaf function, we can do better
  //
  if (!this->IsABI) {
    this->Analysis.args.set(tcg_stack_pointer_index);
    this->Analysis.rets.set(tcg_stack_pointer_index);
  }
}

const helper_function_t &LookupHelper(TCGOp *op);

void basic_block_properties_t::Analyze(binary_index_t BIdx) {
  if (!this->Analysis.Stale)
    return;

  this->Analysis.Stale = false;

  auto &SectMap = Decompilation.Binaries[BIdx].SectMap;

  const uintptr_t Addr = this->Addr;
  const unsigned Size = this->Size;

  auto sectit = SectMap.find(Addr);
  assert(sectit != SectMap.end());

  const section_properties_t &sectprop = *(*sectit).second.begin();
  assert(sectprop.x);
  TCG->set_section((*sectit).first.lower(), sectprop.contents.data());

  TCGContext *s = &TCG->_ctx;

  unsigned size = 0;
  jove::terminator_info_t T;
  do {
    unsigned len;
    std::tie(len, T) = TCG->translate(Addr + size, Addr + Size);

    TCGOp *op, *op_next;
    QTAILQ_FOREACH_SAFE(op, &s->ops, link, op_next) {
      TCGOpcode opc = op->opc;

      tcg_global_set_t iglbs, oglbs;

      int nb_oargs, nb_iargs;
      if (opc == INDEX_op_call) {
        nb_oargs = TCGOP_CALLO(op);
        nb_iargs = TCGOP_CALLI(op);

        const helper_function_t &hf = LookupHelper(op);

        iglbs = hf.Analysis.InGlbs;
        oglbs = hf.Analysis.OutGlbs;
      } else {
        const TCGOpDef &opdef = tcg_op_defs[opc];

        nb_iargs = opdef.nb_iargs;
        nb_oargs = opdef.nb_oargs;
      }

      for (int i = 0; i < nb_iargs; ++i) {
        TCGTemp *ts = arg_temp(op->args[nb_oargs + i]);
        if (!ts->temp_global)
          continue;

        unsigned glb_idx = temp_idx(ts);
        if (glb_idx == tcg_env_index)
          continue;

        iglbs.set(glb_idx);
      }

      for (int i = 0; i < nb_oargs; ++i) {
        TCGTemp *ts = arg_temp(op->args[i]);
        if (!ts->temp_global)
          continue;

        unsigned glb_idx = temp_idx(ts);
        if (glb_idx == tcg_env_index)
          continue;

        oglbs.set(glb_idx);
      }

      this->Analysis.live.use |= (iglbs & ~this->Analysis.live.def);
      this->Analysis.live.def |= (oglbs & ~this->Analysis.live.use);

      this->Analysis.reach.def |= oglbs;
    }

    size += len;
  } while (size < Size);

#if 0
  if (false /* opts::PrintDefAndUse */) {
    llvm::outs() << (fmt("%#lx") % Addr).str() << '\n';

    uint64_t InstLen;
    for (uintptr_t A = Addr; A < Addr + Size; A += InstLen) {
      std::ptrdiff_t Offset = A - (*sectit).first.lower();

      llvm::MCInst Inst;
      bool Disassembled = DisAsm->getInstruction(
          Inst, InstLen, sectprop.contents.slice(Offset), A, llvm::nulls());
      if (!Disassembled) {
        WithColor::error() << "failed to disassemble "
                           << (fmt("%#lx") % Addr).str() << '\n';
        break;
      }

      IP->printInst(&Inst, A, "", *STI, llvm::outs());
      llvm::outs() << '\n';
    }

    llvm::outs() << '\n';

    llvm::outs() << "live.def:";
    {
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, this->Analysis.live.def);
      for (unsigned glb : glbv)
        llvm::outs() << ' ' << s->temps[glb].name;
    }
    llvm::outs() << '\n';

    llvm::outs() << "live.use:";
    {
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, this->Analysis.live.use);
      for (unsigned glb : glbv)
        llvm::outs() << ' ' << s->temps[glb].name;
    }
    llvm::outs() << '\n';

    llvm::outs() << "reach.def:";
    {
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, this->Analysis.reach.def);
      for (unsigned glb : glbv)
        llvm::outs() << ' ' << s->temps[glb].name;
    }
    llvm::outs() << '\n';
  }
#endif
}

bool AnalyzeHelper(helper_function_t &hf) {
  if (hf.EnvArgNo < 0)
    return true; /* doesn't take CPUState* parameter */

  bool res = true;

  llvm::Function::arg_iterator arg_it = hf.F->arg_begin();
  std::advance(arg_it, hf.EnvArgNo);
  llvm::Argument &A = *arg_it;

  for (llvm::User *EnvU : A.users()) {
    if (llvm::isa<llvm::GetElementPtrInst>(EnvU)) {
      llvm::GetElementPtrInst *EnvGEP =
          llvm::cast<llvm::GetElementPtrInst>(EnvU);

      if (!llvm::cast<llvm::GEPOperator>(EnvGEP)->hasAllConstantIndices()) {
        res = false;
        continue;
      }

      llvm::APInt Off(DL.getIndexSizeInBits(EnvGEP->getPointerAddressSpace()), 0);
      llvm::cast<llvm::GEPOperator>(EnvGEP)->accumulateConstantOffset(DL, Off);
      unsigned off = Off.getZExtValue();

      if (!(off < sizeof(tcg_global_by_offset_lookup_table)) ||
          tcg_global_by_offset_lookup_table[off] == 0xff) {

#if 0
        if (opts::Verbose)
          WithColor::warning() << llvm::formatv("{0}: off={1} EnvGEP={2}\n",
                                                __func__, off, *EnvGEP);
#endif

        res = false;
        continue;
      }

      unsigned glb =
          static_cast<unsigned>(tcg_global_by_offset_lookup_table[off]);

      for (llvm::User *GEPU : EnvGEP->users()) {
        if (llvm::isa<llvm::LoadInst>(GEPU)) {
          hf.Analysis.InGlbs.set(glb);
        } else if (llvm::isa<llvm::StoreInst>(GEPU)) {
          hf.Analysis.OutGlbs.set(glb);
        } else {
          assert(llvm::isa<llvm::Instruction>(GEPU));
          if (!llvm::Instruction::isCast(
                  llvm::cast<llvm::Instruction>(GEPU)->getOpcode())) {
            WithColor::warning() << llvm::formatv(
                "{0}: unknown global GEP user {1}\n", __func__, *GEPU);
          }

          res = false;
        }
      }
    } else {
      WithColor::warning() << llvm::formatv(
          "{0}: unknown env user {1}\n", __func__, *EnvU);

      res = false;
    }
  }

  return res;
}

static bool isDFSan(void);

const helper_function_t &LookupHelper(TCGOp *op) {
  int nb_oargs = TCGOP_CALLO(op);
  int nb_iargs = TCGOP_CALLI(op);
  int nb_cargs;

  {
    const TCGOpcode opc = op->opc;
    const TCGOpDef &def = tcg_op_defs[opc];

    nb_cargs = def.nb_cargs;
  }

  uintptr_t helper_addr = op->args[nb_oargs + nb_iargs];

  auto it = HelperFuncMap.find(helper_addr);
  if (it == HelperFuncMap.end()) {
    TCGContext *s = &TCG->_ctx;
    const char *helper_nm = tcg_find_helper(s, helper_addr);
    assert(helper_nm);

    if (llvm::Function *F = Module->getFunction(std::string("helper_") + helper_nm)) {
      if (F->user_begin() == F->user_end()) {
        F->eraseFromParent();
      } else {
        static int i = 0;
        F->setName(std::string("helper_") + helper_nm + std::string("_") +
                   std::to_string(i++));
      }
    }

    assert(!Module->getFunction(std::string("helper_") + helper_nm) &&
           "helper function already exists");

    std::string suffix = isDFSan() ? ".dfsan.bc" : ".bc";

    std::string helperModulePath =
        (boost::dll::program_location().parent_path() / "helpers" / (std::string(helper_nm) + suffix)).string();

    llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> BufferOr =
        llvm::MemoryBuffer::getFile(helperModulePath);
    if (!BufferOr) {
      WithColor::error() << "could not open bitcode for helper_" << helper_nm
                         << " at " << helperModulePath << " (" << BufferOr.getError().message() << ")\n";
      exit(1);
    }

    llvm::Expected<std::unique_ptr<llvm::Module>> helperModuleOr =
        llvm::parseBitcodeFile(BufferOr.get()->getMemBufferRef(), *Context);
    if (!helperModuleOr) {
      llvm::logAllUnhandledErrors(helperModuleOr.takeError(), llvm::errs(),
                                  "could not parse helper bitcode: ");
      exit(1);
    }

    std::unique_ptr<llvm::Module> &helperModule = helperModuleOr.get();

    //
    // process helper bitcode
    //
    {
      llvm::Module &helperM = *helperModule;

      //
      // internalize all functions except the desired helper
      //
      for (llvm::Function &F : helperM.functions()) {
        if (F.isIntrinsic())
          continue;

        // is declaration?
        if (F.empty())
          continue;

        // is helper function?
        if (F.getName() == std::string("helper_") + helper_nm) {
          assert(F.getLinkage() == llvm::GlobalValue::ExternalLinkage);
          continue;
        }

#if 1
        F.setLinkage(llvm::GlobalValue::InternalLinkage);
#else
        F.setLinkage(llvm::GlobalValue::LinkOnceODRLinkage);
        F.setVisibility(llvm::GlobalValue::HiddenVisibility);
#endif
      }

      //
      // internalize global variables
      //
      for (llvm::GlobalVariable &GV : helperM.globals()) {
        if (!GV.hasInitializer())
          continue;

#if 1
        GV.setLinkage(llvm::GlobalValue::InternalLinkage);
#else
        GV.setLinkage(llvm::GlobalValue::LinkOnceODRLinkage);
#endif
      }
    }

    llvm::Linker::linkModules(*Module, std::move(helperModule));

    llvm::Function *helperF =
        Module->getFunction(std::string("helper_") + helper_nm);

    if (!helperF) {
      WithColor::error() << llvm::formatv("cannot find helper function {0}\n",
                                          helper_nm);
      abort();
    }

#if 0
    if (helperF->arg_size() != nb_iargs) {
      WithColor::error() << llvm::formatv(
          "helper {0} takes {1} args but nb_iargs={2}\n", helper_nm,
          helperF->arg_size(), nb_iargs);
      exit(1);
    }
#else
    assert(nb_iargs >= helperF->arg_size());
#endif

    assert(helperF->getLinkage() == llvm::GlobalValue::ExternalLinkage);
    helperF->setVisibility(llvm::GlobalValue::HiddenVisibility);

    //
    // analyze helper
    //
    int EnvArgNo = -1;
    {
      TCGArg *const inputs_beg = &op->args[nb_oargs + 0];
      TCGArg *const inputs_end = &op->args[nb_oargs + nb_iargs];
      TCGArg *it =
          std::find(inputs_beg, inputs_end,
                    reinterpret_cast<TCGArg>(&s->temps[tcg_env_index]));

      if (it != inputs_end)
        EnvArgNo = std::distance(inputs_beg, it);
    }

    helper_function_t &hf = HelperFuncMap[helper_addr];
    hf.F = helperF;
    hf.EnvArgNo = EnvArgNo;
    hf.Analysis.Simple = AnalyzeHelper(hf); /* may modify hf.Analysis.InGlbs */

    //
    // is this a system call?
    //
    const uintptr_t syscall_helper_addr = (uintptr_t)
#if defined(TARGET_X86_64)
        helper_syscall
#elif defined(TARGET_I386)
        helper_raise_interrupt
#elif defined(TARGET_AARCH64)
        helper_exception_with_syndrome
#elif defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
        helper_raise_exception_err
#else
#error
#endif
        ;

    if (helper_addr == syscall_helper_addr)
      hf.Analysis.Simple = true; /* force */

    {
      std::string InGlbsStr;

      {
        std::vector<unsigned> iglbv;
        explode_tcg_global_set(iglbv, hf.Analysis.InGlbs);

        //InGlbsStr.push_back('{');
        for (auto it = iglbv.begin(); it != iglbv.end(); ++it) {
          unsigned glb = *it;

          InGlbsStr.append(TCG->_ctx.temps[glb].name);
          if (std::next(it) != iglbv.end())
            InGlbsStr.append(", ");
        }
        //InGlbsStr.push_back('}');
      }

      std::string OutGlbsStr;

      {
        std::vector<unsigned> oglbv;
        explode_tcg_global_set(oglbv, hf.Analysis.OutGlbs);

        //OutGlbsStr.push_back('{');
        for (auto it = oglbv.begin(); it != oglbv.end(); ++it) {
          unsigned glb = *it;

          OutGlbsStr.append(TCG->_ctx.temps[glb].name);
          if (std::next(it) != oglbv.end())
            OutGlbsStr.append(", ");
        }
        //OutGlbsStr.push_back('}');
      }

      const char *IsSimpleStr = hf.Analysis.Simple ? "-" : "+";

      if (!InGlbsStr.empty() || !OutGlbsStr.empty()) {
        WithColor::note() << llvm::formatv("[helper] ({0}) {1} : {2} -> {3}\n",
                                           IsSimpleStr,
                                           helper_nm,
                                           InGlbsStr,
                                           OutGlbsStr);
      } else {
        WithColor::note() << llvm::formatv("[helper] ({0}) {1}\n", IsSimpleStr,
                                           helper_nm);
      }
    }

    return hf;
  } else {
    return (*it).second;
  }
}


}
