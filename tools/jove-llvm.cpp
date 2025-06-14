#include "tool.h"

#ifndef JOVE_NO_BACKEND
#include "llvm.h"

namespace jove {

namespace cl = llvm::cl;

struct LLVMTool : public JVTool<ToolKind::CopyOnWrite> {
  struct Cmdline {
    cl::opt<std::string> Binary;
    cl::alias BinaryAlias;
    cl::opt<std::string> BinaryIndex;
    cl::opt<std::string> Output;
    cl::alias OutputAlias;
    cl::opt<std::string> VersionScript;
    cl::opt<std::string> LinkerScript;
    cl::opt<bool> Trace;
    cl::opt<bool> PrintPCRel;
    cl::opt<bool> PrintDefAndUse;
    cl::opt<bool> DebugSjlj;
    cl::opt<bool> DumpTCG;
    cl::opt<std::string> ForAddr;
    cl::opt<bool> Optimize;
    cl::opt<bool> VerifyBitcode;
    cl::opt<bool> DumpPreOpt1;
    cl::opt<bool> DumpPostOpt1;
    cl::opt<bool> DFSan;
    cl::opt<std::string> DFSanOutputModuleID;
    cl::opt<bool> CallStack;
    cl::opt<bool> CheckEmulatedStackReturnAddress;
    cl::opt<bool> ForeignLibs;
    cl::alias ForeignLibsAlias;
    cl::list<std::string> PinnedGlobals;
    cl::opt<bool> ABICalls;
    cl::opt<bool> InlineHelpers;
    cl::opt<bool> ForCBE;
    cl::opt<bool> RuntimeMT;
    cl::opt<bool> BreakBeforeUnreachables;
    cl::opt<bool> LayOutSections;
    cl::opt<bool> PlaceSectionBreakpoints;
    cl::opt<bool> Debugify;
    cl::opt<bool> SoftfpuBitcode;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Binary("binary", cl::desc("Binary to translate"),
                 cl::value_desc("path"), cl::cat(JoveCategory)),

          BinaryAlias("b", cl::desc("Alias for -binary."), cl::aliasopt(Binary),
                      cl::cat(JoveCategory)),

          BinaryIndex("binary-index", cl::desc("Index of binary to translate"),
                      cl::cat(JoveCategory)),

          Output("output", cl::desc("Output bitcode"), cl::Required,
                 cl::value_desc("filename"), cl::cat(JoveCategory)),

          OutputAlias("o", cl::desc("Alias for -output."), cl::aliasopt(Output),
                      cl::cat(JoveCategory)),

          VersionScript("version-script",
                        cl::desc("Output version script file for use with ld"),
                        cl::value_desc("filename"), cl::cat(JoveCategory)),

          LinkerScript("linker-script",
                       cl::desc("Output linker script file for use with ld"),
                       cl::value_desc("filename"), cl::cat(JoveCategory)),

          Trace(
              "trace",
              cl::desc("Instrument code to output basic block execution trace"),
              cl::cat(JoveCategory)),

          PrintPCRel("pcrel", cl::desc("Print pc-relative references"),
                     cl::cat(JoveCategory)),

          PrintDefAndUse(
              "print-def-and-use",
              cl::desc("Print use_B and def_B for every basic block B"),
              cl::cat(JoveCategory)),

          DebugSjlj(
              "debug-sjlj",
              cl::desc(
                  "Before setjmp/longjmp, dump information about the call"),
              cl::cat(JoveCategory)),

          DumpTCG("dump-tcg",
                  cl::desc("Dump TCG operations when translating basic blocks"),
                  cl::cat(JoveCategory)),
          ForAddr("for-addr", cl::desc("Do stuff for the given address"),
                  cl::cat(JoveCategory)),

          Optimize("optimize", cl::desc("Optimize bitcode"),
                   cl::cat(JoveCategory)),

          VerifyBitcode("verify-bitcode",
                        cl::desc("run llvm::verifyModule on the bitcode"),
                        cl::cat(JoveCategory)),

          DumpPreOpt1("dump-pre-opt",
                      cl::desc("Dump bitcode before DoOptimize()"),
                      cl::cat(JoveCategory)),

          DumpPostOpt1("dump-post-opt",
                       cl::desc("Dump bitcode after DoOptimize()"),
                       cl::cat(JoveCategory)),

          DFSan("dfsan", cl::desc("Instrument code with DataFlowSanitizer"),
                cl::cat(JoveCategory)),

          DFSanOutputModuleID(
              "dfsan-output-module-id",
              cl::desc("Write to file containing module ID (which is "
                       "found from DFSanModuleID metadata"),
              cl::value_desc("filename"), cl::cat(JoveCategory)),

          CallStack("call-stack",
                    cl::desc("Write state of recompiled call stack to file "
                             "path formed from $JOVECALLS"),
                    cl::cat(JoveCategory)),

          CheckEmulatedStackReturnAddress("check-emu-stack-ret-addr",
                                          cl::desc("Check for stack smashing"),
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

          ForCBE("for-cbe", cl::desc("Generate LLVM for C backend"),
                 cl::cat(JoveCategory)),

          RuntimeMT("rtmt", cl::desc("Runtime thread model"),
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

          Debugify("debugify", cl::cat(JoveCategory)),

          SoftfpuBitcode("softfpu-bitcode",
                         cl::desc("Link in the softfpu bitcode"),
                         cl::cat(JoveCategory)) {}
  } opts;

  analyzer_options_t analyzer_options;
  llvm_options_t llvm_options;

public:
  LLVMTool() : opts(JoveCategory) {}

  int Run(void) override;
};

JOVE_REGISTER_TOOL("llvm", LLVMTool);

int LLVMTool::Run(void) {
  tiny_code_generator_t TCG;

  for (const std::string &PinnedGlobalName : opts.PinnedGlobals) {
    int idx = TCG.tcg_index_of_named_global(PinnedGlobalName.c_str());
    if (idx < 0)
      die("unknown global to pin: " + PinnedGlobalName);

    analyzer_options.PinnedEnvGlbs.set(idx);
    llvm_options.PinnedEnvGlbs.set(idx);
  }

  analyzer_options.VerbosityLevel =
      llvm_options.VerbosityLevel = VerbosityLevel();

  llvm_options.temp_dir = temporary_dir();

#define PROPOGATE_OPTION(name)                                                 \
  do {                                                                         \
    llvm_options.name = this->opts.name;                                       \
  } while (false)

  PROPOGATE_OPTION(Output);
  PROPOGATE_OPTION(Binary);
  PROPOGATE_OPTION(BinaryIndex);
  PROPOGATE_OPTION(ForeignLibs);
  PROPOGATE_OPTION(CheckEmulatedStackReturnAddress);
  PROPOGATE_OPTION(DumpTCG);
  PROPOGATE_OPTION(ForAddr);
  PROPOGATE_OPTION(DFSan);
  PROPOGATE_OPTION(InlineHelpers);
  PROPOGATE_OPTION(ForCBE);
  PROPOGATE_OPTION(DumpPreOpt1);
  PROPOGATE_OPTION(DumpPostOpt1);
  PROPOGATE_OPTION(Optimize);
  PROPOGATE_OPTION(VersionScript);
  PROPOGATE_OPTION(LinkerScript);
  PROPOGATE_OPTION(BreakBeforeUnreachables);
  PROPOGATE_OPTION(Debugify);
  PROPOGATE_OPTION(RuntimeMT);
  PROPOGATE_OPTION(Trace);
  PROPOGATE_OPTION(PlaceSectionBreakpoints);
  PROPOGATE_OPTION(LayOutSections);
  PROPOGATE_OPTION(CallStack);
  PROPOGATE_OPTION(DFSanOutputModuleID);
  PROPOGATE_OPTION(VerifyBitcode);
  PROPOGATE_OPTION(DebugSjlj);
  PROPOGATE_OPTION(ABICalls);
  PROPOGATE_OPTION(PrintPCRel);
  PROPOGATE_OPTION(SoftfpuBitcode);

  analyzer_options.ForCBE = llvm_options.ForCBE; // XXX

  llvm::LLVMContext Context;
  llvm_t llvm(jv, llvm_options, analyzer_options, TCG, Context, locator());
  return llvm.go();
}

}
#endif /* JOVE_NO_BACKEND */
