#include "tool.h"
#include "recompile.h"
#include "tcg.h"

#include <llvm/Support/WithColor.h>

#ifndef JOVE_NO_BACKEND

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

class RecompileTool : public JVTool<ToolKind::CopyOnWrite> {
  struct Cmdline {
    cl::opt<std::string> Output;
    cl::alias OutputAlias;
    cl::opt<bool> Trace;
    cl::opt<std::string> UseLd;
    cl::opt<bool> DFSan;
    cl::opt<bool> CallStack;
    cl::opt<bool> Optimize;
    cl::opt<bool> SkipCopyRelocHack;
    cl::opt<bool> DebugSjlj;
    cl::opt<bool> CheckEmulatedStackReturnAddress;
    cl::opt<bool> SkipLLVM;
    cl::opt<bool> ForeignLibs;
    cl::alias ForeignLibsAlias;
    cl::list<std::string> PinnedGlobals;
    cl::opt<bool> ABICalls;
    cl::opt<bool> InlineHelpers;
    cl::opt<bool> RuntimeMT;
    cl::opt<bool> BreakBeforeUnreachables;
    cl::opt<bool> LayOutSections;
    cl::opt<bool> PlaceSectionBreakpoints;
    cl::opt<bool> DumpPreOpt1;
    cl::opt<bool> SoftfpuBitcode;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Output("output", cl::desc("Output directory"), cl::Required,
                 cl::cat(JoveCategory)),

          OutputAlias("o", cl::desc("Alias for -output."), cl::aliasopt(Output),
                      cl::cat(JoveCategory)),

          Trace(
              "trace",
              cl::desc("Instrument code to output basic block execution trace"),
              cl::cat(JoveCategory)),

          UseLd("use-ld",
                cl::desc("Force using particular linker (lld,bfd,gold)"),
                cl::cat(JoveCategory)),

          DFSan("dfsan", cl::desc("Run dfsan on bitcode"),
                cl::cat(JoveCategory)),

          CallStack("call-stack",
                    cl::desc("Write state of recompiled call stack to file "
                             "path formed from $JOVECALLS"),
                    cl::cat(JoveCategory)),

          Optimize("optimize", cl::desc("Run optimizations on bitcode"),
                   cl::cat(JoveCategory)),

          SkipCopyRelocHack(
              "skip-copy-reloc-hack",
              cl::desc("Do not insert COPY relocations in output file (HACK)"),
              cl::cat(JoveCategory)),

          DebugSjlj(
              "debug-sjlj",
              cl::desc(
                  "Before setjmp/longjmp, dump information about the call"),
              cl::cat(JoveCategory)),

          CheckEmulatedStackReturnAddress("check-emulated-stack-return-address",
                                          cl::desc("Check for stack overrun"),
                                          cl::cat(JoveCategory)),

          SkipLLVM(
              "skip-llvm",
              cl::desc(
                  "Skip running jove-llvm (careful when using this option)"),
              cl::cat(JoveCategory)),

          ForeignLibs("foreign-libs",
                      cl::desc("only recompile the executable itself; "
                               "treat all other binaries as \"foreign\""),
                      cl::cat(JoveCategory), cl::init(true)),

          ForeignLibsAlias("x", cl::desc("Exe only. Alias for --foreign-libs."),
                           cl::aliasopt(ForeignLibs), cl::cat(JoveCategory)),

          PinnedGlobals(
              "pinned-globals", cl::CommaSeparated,
              cl::value_desc("glb_1,glb_2,...,glb_n"),
              cl::desc(
                  "force specified TCG globals to always go through CPUState"),
              cl::cat(JoveCategory)),

          ABICalls("abi-calls",
                   cl::desc("Call ABIs indirectly through _jove_call"),
                   cl::cat(JoveCategory), cl::init(true)),

          InlineHelpers("inline-helpers",
                        cl::desc("Try to inline all helper function calls"),
                        cl::cat(JoveCategory)),

          RuntimeMT("rtmt", cl::desc("Thread model (multi)"),
                    cl::cat(JoveCategory), cl::init(true)),

          BreakBeforeUnreachables("break-before-unreachables",
                                  cl::desc("Debugging purposes only"),
                                  cl::cat(JoveCategory)),

          LayOutSections(
              "lay-out-sections",
              cl::desc("mode where each section becomes a "
                       "distinct global variable. we check in "
                       "_jove_check_sections_laid_out() at runtime to make "
                       "sure that those aforementioned global variables exist "
                       "side-by-side in memory in the way we expect them to"),
              cl::cat(JoveCategory)),

          PlaceSectionBreakpoints(
              "place-section-breakpoints",
              cl::desc("In the section globals, overwrite the bytes at the "
                       "start of every ABI function (which is not setjmp() or "
                       "longjmp()) with an illegal instruction. This is "
                       "used to provoke a fault at runtime when such functions "
                       "are called into from non-recompiled code, so that the "
                       "recompiled versions are called. Unless JOVESECTS=exe, "
                       "this is unnecessary because the section globals will "
                       "not be executable to begin with thus triggering a "
                       "fault."),
              cl::cat(JoveCategory)),

          DumpPreOpt1("dump-pre-opt1", cl::cat(JoveCategory)),

          SoftfpuBitcode(
              "softfpu-bitcode",
              cl::desc("Link the softfpu bitcode rather than the object file"),
              cl::cat(JoveCategory)) {}

  } opts;

  recompiler_options_t options;

public:
  RecompileTool() : opts(JoveCategory) {}

  int Run(void) override;

  void worker(dso_t);
};

JOVE_REGISTER_TOOL("recompile", RecompileTool);

int RecompileTool::Run(void) {
  tiny_code_generator_t TCG;

  for (const std::string &PinnedGlobalName : opts.PinnedGlobals) {
    int idx = TCG.tcg_index_of_named_global(PinnedGlobalName.c_str());
    if (idx < 0)
      die("unknown global to pin: " + PinnedGlobalName);

    options.PinnedEnvGlbs.set(idx);
  }

  options.VerbosityLevel = VerbosityLevel();

#define PROPOGATE_OPTION(name)                                                 \
  do {                                                                         \
    options.name = this->opts.name;                                            \
  } while (false)

  PROPOGATE_OPTION(Output);
  PROPOGATE_OPTION(ForeignLibs);
  PROPOGATE_OPTION(RuntimeMT);
  PROPOGATE_OPTION(DFSan);
  PROPOGATE_OPTION(SkipCopyRelocHack);
  PROPOGATE_OPTION(Optimize);
  PROPOGATE_OPTION(CallStack);
  PROPOGATE_OPTION(CheckEmulatedStackReturnAddress);
  PROPOGATE_OPTION(Trace);
  PROPOGATE_OPTION(DebugSjlj);
  PROPOGATE_OPTION(ABICalls);
  PROPOGATE_OPTION(InlineHelpers);
  PROPOGATE_OPTION(BreakBeforeUnreachables);
  PROPOGATE_OPTION(LayOutSections);
  PROPOGATE_OPTION(PlaceSectionBreakpoints);
  PROPOGATE_OPTION(DumpPreOpt1);
  PROPOGATE_OPTION(SoftfpuBitcode);

  options.temp_dir = temporary_dir();

  llvm::LLVMContext Context;

  recompiler_t recompiler(jv, options, TCG, Context, locator());
  return recompiler.go();
}

}
#endif
