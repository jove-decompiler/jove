typedef std::tuple<llvm::MCDisassembler &,
                   const llvm::MCSubtargetInfo &,
                   llvm::MCInstPrinter &>
    disas_t;

static basic_block_index_t translate_basic_block(binary_t &b,
                                                 tiny_code_generator_t &,
                                                 disas_t &,
                                                 const target_ulong Addr,
                                                 fnmap_t &,
                                                 bbmap_t &,
                                                 std::function<void(binary_t &, basic_block_t, disas_t &)> on_newbb_proc = [](binary_t &, basic_block_t, disas_t &){});

static function_index_t translate_function(binary_t &b,
                                           tiny_code_generator_t &tcg,
                                           disas_t &dis,
                                           const target_ulong Addr,
                                           fnmap_t &fnmap,
                                           bbmap_t &bbmap,
                                           std::function<void(binary_t &, basic_block_t, disas_t &)> on_newbb_proc = [](binary_t &, basic_block_t, disas_t &){}) {
#if defined(TARGET_MIPS32) || defined(TARGET_MIPS64)
  assert((Addr & 1) == 0);
#endif

  {
    auto it = fnmap.find(Addr);
    if (it != fnmap.end())
      return (*it).second;
  }

  const function_index_t res = b.Analysis.Functions.size();
  (void)b.Analysis.Functions.emplace_back();

  fnmap.insert({Addr, res});

  basic_block_index_t Entry =
      translate_basic_block(b, tcg, dis, Addr, fnmap, bbmap, on_newbb_proc);

#ifdef WARN_ON
  WARN_ON(!is_basic_block_index_valid(Entry));
#endif

  {
    function_t &f = b.Analysis.Functions[res];

    f.Analysis.Stale = true;
    f.IsABI = false;
    f.IsSignalHandler = false;
    f.Entry = Entry;
  }

  return res;
}

static bool does_function_definitely_return(binary_t &, function_index_t);

basic_block_index_t translate_basic_block(binary_t &b,
                                          tiny_code_generator_t &tcg,
                                          disas_t &dis,
                                          const target_ulong Addr,
                                          fnmap_t &fnmap,
                                          bbmap_t &bbmap,
                                          std::function<void(binary_t &, basic_block_t, disas_t &)> on_newbb_proc) {
#if defined(TARGET_MIPS32) || defined(TARGET_MIPS64)
  assert((Addr & 1) == 0);
#endif

  auto &ICFG = b.Analysis.ICFG;
  auto &ObjectFile = b.ObjectFile;

  //
  // does this new basic block start in the middle of a previously-created
  // basic block?
  //
  {
    auto it = bbmap.find(Addr);
    if (it != bbmap.end()) {
      basic_block_index_t bbidx = -1+(*it).second;
      basic_block_t bb = boost::vertex(bbidx, ICFG);

      assert(bbidx < boost::num_vertices(ICFG));

      uintptr_t beg = ICFG[bb].Addr;

      if (Addr == beg) {
        assert(ICFG[bb].Addr == (*it).first.lower());
        return bbidx;
      }

      //
      // before splitting the basic block, let's check to make sure that the
      // new block doesn't start in the middle of an instruction. if that would
      // occur, then we will assume the control-flow is invalid
      //
      {
        llvm::MCDisassembler &DisAsm = std::get<0>(dis);
        const llvm::MCSubtargetInfo &STI = std::get<1>(dis);
        llvm::MCInstPrinter &IP = std::get<2>(dis);

        const ELFF &E = *llvm::cast<ELFO>(ObjectFile.get())->getELFFile();

        uint64_t InstLen = 0;
        for (target_ulong A = beg; A < beg + ICFG[bb].Size; A += InstLen) {
          llvm::MCInst Inst;

          std::string errmsg;
          bool Disassembled;
          {
            llvm::raw_string_ostream ErrorStrStream(errmsg);

            llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(A);
            if (!ExpectedPtr)
              abort();

            Disassembled = DisAsm.getInstruction(
                Inst, InstLen,
                llvm::ArrayRef<uint8_t>(*ExpectedPtr, ICFG[bb].Size), A,
                ErrorStrStream);
          }

          if (!Disassembled)
            llvm::WithColor::error() << llvm::formatv(
                "failed to disassemble {0:x}: {1}\n", A, errmsg);

          assert(Disassembled);

          if (A == Addr)
            goto on_insn_boundary;
        }

        llvm::WithColor::error() << llvm::formatv(
            "control flow to {0:x} in {1} doesn't lie on instruction boundary\n",
            Addr, b.Path);

        return invalid_basic_block_index;

on_insn_boundary:
        //
        // proceed.
        //
        ;
      }

      std::vector<basic_block_t> out_verts;
      {
        icfg_t::out_edge_iterator e_it, e_it_end;
        for (std::tie(e_it, e_it_end) = boost::out_edges(bb, ICFG);
             e_it != e_it_end; ++e_it)
          out_verts.push_back(boost::target(*e_it, ICFG));
      }

      // if we get here, we know that beg != Addr
      assert(Addr > beg);

      ptrdiff_t off = Addr - beg;
      assert(off > 0);

      boost::icl::interval<target_ulong>::type orig_intervl = (*it).first;

      basic_block_index_t newbbidx = boost::num_vertices(ICFG);
      basic_block_t newbb = boost::add_vertex(ICFG);
      {
        basic_block_properties_t &newbbprop = ICFG[newbb];
        newbbprop.Addr = beg;
        newbbprop.Size = off;
        newbbprop.Term.Type = TERMINATOR::NONE;
        newbbprop.Term.Addr = 0; /* XXX? */
        newbbprop.DynTargetsComplete = false;
        newbbprop.Term._call.Target = invalid_function_index;
        newbbprop.Term._call.Returns = false;
        newbbprop.Term._indirect_jump.IsLj = false;
        newbbprop.Sj = false;
        newbbprop.Term._indirect_call.Returns = false;
        newbbprop.Term._return.Returns = false;
        newbbprop.InvalidateAnalysis();
      }

      ICFG[bb].InvalidateAnalysis();

      std::swap(ICFG[bb], ICFG[newbb]);
      ICFG[newbb].Addr = Addr;
      ICFG[newbb].Size -= off;

      assert(ICFG[newbb].Addr + ICFG[newbb].Size == orig_intervl.upper());

      boost::clear_out_edges(bb, ICFG);
      boost::add_edge(bb, newbb, ICFG);

      for (basic_block_t out_vert : out_verts) {
        boost::add_edge(newbb, out_vert, ICFG);
      }

      assert(ICFG[bb].Term.Type == TERMINATOR::NONE);
      assert(boost::out_degree(bb, ICFG) == 1);

      boost::icl::interval<target_ulong>::type intervl1 =
          boost::icl::interval<target_ulong>::right_open(
              ICFG[bb].Addr, ICFG[bb].Addr + ICFG[bb].Size);

      boost::icl::interval<target_ulong>::type intervl2 =
          boost::icl::interval<target_ulong>::right_open(
              ICFG[newbb].Addr, ICFG[newbb].Addr + ICFG[newbb].Size);

      assert(boost::icl::disjoint(intervl1, intervl2));

      unsigned n = bbmap.iterative_size();
      bbmap.erase((*it).first);
      assert(bbmap.iterative_size() == n - 1);

      assert(bbmap.find(intervl1) == bbmap.end());
      assert(bbmap.find(intervl2) == bbmap.end());

      bbmap.add({intervl1, 1+bbidx});
      bbmap.add({intervl2, 1+newbbidx});

      {
        auto _it = bbmap.find(intervl1);
        assert(_it != bbmap.end());
        assert((*_it).second == 1+bbidx);
      }

      {
        auto _it = bbmap.find(intervl2);
        assert(_it != bbmap.end());
        assert((*_it).second == 1+newbbidx);
      }

      return newbbidx;
    }
  }

  tcg.set_elf(llvm::cast<ELFO>(b.ObjectFile.get())->getELFFile());

  unsigned Size = 0;
  jove::terminator_info_t T;
  do {
    unsigned size;
    std::tie(size, T) = tcg.translate(Addr + Size);

    Size += size;

    {
      boost::icl::interval<target_ulong>::type intervl =
          boost::icl::interval<target_ulong>::right_open(Addr, Addr + Size);
      auto it = bbmap.find(intervl);
      if (it != bbmap.end()) {
        const boost::icl::interval<target_ulong>::type &_intervl = (*it).first;

        assert(intervl.lower() < _intervl.lower());

        //
        // solution here is to prematurely end the basic block with a NONE
        // terminator, and with a next_insn address of _intervl.lower()
        //
        Size = _intervl.lower() - intervl.lower();
        T.Type = TERMINATOR::NONE;
        T.Addr = 0; /* XXX? */
        T._none.NextPC = _intervl.lower();
        break;
      }
    }
  } while (T.Type == TERMINATOR::NONE);

  if (T.Type == TERMINATOR::UNKNOWN) {
    llvm::WithColor::error()
        << (boost::format("%s: unknown terminator @ %#lx\n") % __func__ % Addr).str();

    llvm::MCDisassembler &DisAsm = std::get<0>(dis);
    const llvm::MCSubtargetInfo &STI = std::get<1>(dis);
    llvm::MCInstPrinter &IP = std::get<2>(dis);

    const ELFF &E = *llvm::cast<ELFO>(ObjectFile.get())->getELFFile();

    uint64_t InstLen;
    for (target_ulong A = Addr; A < Addr + Size; A += InstLen) {
      llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(A);
      if (!ExpectedPtr)
        abort();

      llvm::MCInst Inst;
      bool Disassembled = DisAsm.getInstruction(
          Inst, InstLen, llvm::ArrayRef<uint8_t>(*ExpectedPtr, Size), A,
          llvm::nulls());

      if (!Disassembled) {
        llvm::WithColor::error()
            << (boost::format("%s: failed to disassemble %#lx\n") % __func__ % Addr).str();
        break;
      }

      IP.printInst(&Inst, A, "", STI, llvm::errs());
      llvm::errs() << '\n';
    }

    tcg.dump_operations();
    fputc('\n', stdout);
    return invalid_basic_block_index;
  }

  basic_block_index_t bbidx = boost::num_vertices(ICFG);
  basic_block_t bb = boost::add_vertex(ICFG);
  {
    basic_block_properties_t &bbprop = ICFG[bb];
    bbprop.Addr = Addr;
    bbprop.Size = Size;
    bbprop.Term.Type = T.Type;
    bbprop.Term.Addr = T.Addr;
    bbprop.DynTargetsComplete = false;
    bbprop.Term._call.Target = invalid_function_index;
    bbprop.Term._call.Returns = false;
    bbprop.Term._indirect_jump.IsLj = false;
    bbprop.Sj = false;
    bbprop.Term._indirect_call.Returns = false;
    bbprop.Term._return.Returns = false;
    bbprop.InvalidateAnalysis();

    boost::icl::interval<target_ulong>::type intervl =
        boost::icl::interval<target_ulong>::right_open(bbprop.Addr,
                                                       bbprop.Addr + bbprop.Size);
    assert(bbmap.find(intervl) == bbmap.end());
    bbmap.add({intervl, 1+bbidx});
  }

  //
  // a new basic block has been created
  //
  on_newbb_proc(b, bb, dis);

  auto control_flow = [&](target_ulong Target) -> void {
    assert(Target);

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    Target &= ~1UL;
#endif

    basic_block_index_t succidx =
        translate_basic_block(b, tcg, dis, Target, fnmap, bbmap, on_newbb_proc);

    if (succidx == invalid_basic_block_index) {
      llvm::WithColor::warning() << llvm::formatv(
          "control_flow: invalid edge {0:x} -> {1:x}\n", T.Addr, Target);
      return;
    }

    assert(is_basic_block_index_valid(succidx));

    basic_block_t _bb;
    {
      auto it = T.Addr ? bbmap.find(T.Addr) : bbmap.find(Addr);
      assert(it != bbmap.end());

      basic_block_index_t _bbidx = -1+(*it).second;
      _bb = boost::vertex(_bbidx, ICFG);
      assert(T.Type == ICFG[_bb].Term.Type);
    }

    basic_block_t succ = boost::vertex(succidx, ICFG);
    bool isNewTarget = boost::add_edge(_bb, succ, ICFG).second;

    (void)isNewTarget;
  };

  switch (T.Type) {
  case TERMINATOR::UNCONDITIONAL_JUMP:
    control_flow(T._unconditional_jump.Target);
    break;

  case TERMINATOR::CONDITIONAL_JUMP:
    control_flow(T._conditional_jump.Target);
    control_flow(T._conditional_jump.NextPC);
    break;

  case TERMINATOR::CALL: {
    target_ulong CalleeAddr = T._call.Target;

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    CalleeAddr &= ~1UL;
#endif

    function_index_t FIdx = translate_function(b, tcg, dis, CalleeAddr, fnmap, bbmap, on_newbb_proc);

    basic_block_t _bb;
    {
      auto it = T.Addr ? bbmap.find(T.Addr) : bbmap.find(Addr);
      assert(it != bbmap.end());
      basic_block_index_t _bbidx = -1+(*it).second;
      _bb = boost::vertex(_bbidx, ICFG);
    }

    assert(ICFG[_bb].Term.Type == TERMINATOR::CALL);
    ICFG[_bb].Term._call.Target = FIdx;

    if (is_function_index_valid(FIdx) &&
        does_function_definitely_return(b, FIdx))
      control_flow(T._call.NextPC);

    break;
  }

  case TERMINATOR::INDIRECT_CALL:
    //control_flow(T._indirect_call.NextPC);
    break;

  case TERMINATOR::INDIRECT_JUMP:
  case TERMINATOR::RETURN:
  case TERMINATOR::UNREACHABLE:
    break;

  case TERMINATOR::NONE:
    control_flow(T._none.NextPC);
    break;

  default:
    abort();
  }

  return bbidx;
}

struct dfs_reachable_visitor : public boost::default_dfs_visitor {
  std::vector<basic_block_t> &out;

  dfs_reachable_visitor(std::vector<basic_block_t> &out) : out(out) {}

  void discover_vertex(basic_block_t bb, const icfg_t &) const {
    out.push_back(bb);
  }
};

bool does_function_definitely_return(binary_t &b,
                                     function_index_t FIdx) {
  assert(is_function_index_valid(FIdx));

  function_t &f = b.Analysis.Functions.at(FIdx);
  auto &ICFG = b.Analysis.ICFG;

  assert(is_basic_block_index_valid(f.Entry));

  std::vector<basic_block_t> BasicBlocks;
  std::vector<basic_block_t> ExitBasicBlocks;

  std::map<basic_block_t, boost::default_color_type> color;
  dfs_reachable_visitor vis(BasicBlocks);
  boost::depth_first_visit(
      ICFG, boost::vertex(f.Entry, ICFG), vis,
      boost::associative_property_map<
          std::map<basic_block_t, boost::default_color_type>>(color));

  //
  // ExitBasicBlocks
  //
  std::copy_if(BasicBlocks.begin(),
               BasicBlocks.end(),
               std::back_inserter(ExitBasicBlocks),
               [&](basic_block_t bb) -> bool {
                 return IsExitBlock(ICFG, bb);
               });

  return !ExitBasicBlocks.empty();
}
