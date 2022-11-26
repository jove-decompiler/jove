#include "tool.h"
#include "elf.h"
#include "crypto.h"
#include "fd.h"

#include <boost/dll/runtime_symbol_info.hpp>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

#include <string>
#include <cinttypes>
#include <cstring>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "jove_macros.h"

namespace fs = boost::filesystem;
namespace cl = llvm::cl;
namespace obj = llvm::object;

using llvm::WithColor;

namespace jove {

class LoopTool : public Tool {
  struct Cmdline {
    cl::opt<std::string> Prog;
    cl::list<std::string> Args;
    cl::list<std::string> Envs;
    cl::opt<std::string> EnvFromFile;
    cl::opt<std::string> ArgsFromFile;
    cl::list<std::string> BindMountDirs;
    cl::opt<std::string> jv;
    cl::alias jvAlias;
    cl::opt<std::string> Sysroot;
    cl::opt<bool> DFSan;
    cl::opt<bool> Optimize;
    cl::opt<bool> SkipCopyRelocHack;
    cl::opt<bool> ForceRecompile;
    cl::alias ForceRecompileAlias;
    cl::opt<bool> JustRun;
    cl::opt<std::string> UseLd;
    cl::opt<bool> Trace;
    cl::opt<bool> DebugSjlj;
    cl::opt<bool> Verbose;
    cl::alias VerboseAlias;
    cl::opt<std::string> Connect;
    cl::alias ConnectAlias;
    cl::opt<unsigned> Sleep;
    cl::opt<unsigned> DangerousSleep1;
    cl::opt<unsigned> DangerousSleep2;
    cl::opt<bool> ForeignLibs;
    cl::alias ForeignLibsAlias;
    cl::opt<bool> NoChroot;
    cl::alias NoChrootAlias;
    cl::list<std::string> PinnedGlobals;
    cl::opt<std::string> ChangeDirectory;
    cl::opt<bool> ABICalls;
    cl::opt<bool> InlineHelpers;
    cl::opt<std::string> HumanOutput;
    cl::opt<bool> Silent;
    cl::opt<bool> RunAsRoot;
    cl::alias RunAsRootAlias;
    cl::opt<bool> PreserveEnvironment;
    cl::alias PreserveEnvironmentAlias;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Prog(cl::Positional, cl::desc("prog"), cl::Required,
               cl::value_desc("filename"), cl::cat(JoveCategory)),

          Args("args", cl::CommaSeparated, cl::ConsumeAfter,
               cl::desc("<program arguments>..."), cl::cat(JoveCategory)),

          Envs("env", cl::CommaSeparated,
               cl::value_desc("KEY_1=VALUE_1,KEY_2=VALUE_2,...,KEY_n=VALUE_n"),
               cl::desc("Extra environment variables"), cl::cat(JoveCategory)),

          EnvFromFile("env-from-file",
                      cl::desc("use output from `cat /proc/<pid>/environ`"),
                      cl::cat(JoveCategory)),

          ArgsFromFile("args-from-file",
                       cl::desc("use output from `cat /proc/<pid>/cmdline`"),
                       cl::cat(JoveCategory)),

          BindMountDirs("bind", cl::CommaSeparated,
                        cl::value_desc(
                            "/path/to/dir_1,/path/to/dir_2,...,/path/to/dir_n"),
                        cl::desc("List of directories to bind mount"),
                        cl::cat(JoveCategory)),

          jv("jv", cl::desc("Jove jv"),
             cl::value_desc("filename"), cl::cat(JoveCategory)),

          jvAlias("d", cl::desc("Alias for -jv."), cl::aliasopt(jv),
                  cl::cat(JoveCategory)),

          Sysroot("sysroot", cl::desc("Output directory"),
                  cl::cat(JoveCategory)),

          DFSan("dfsan", cl::desc("Run dfsan on bitcode"),
                cl::cat(JoveCategory)),

          Optimize("optimize", cl::desc("Run optimizations on bitcode"),
                   cl::cat(JoveCategory)),

          SkipCopyRelocHack(
              "skip-copy-reloc-hack",
              cl::desc("Do not insert COPY relocations in output file (HACK)"),
              cl::cat(JoveCategory)),

          ForceRecompile("force-recompile",
                         cl::desc("Skip running the prog the first time"),
                         cl::cat(JoveCategory)),

          ForceRecompileAlias("f", cl::desc("Alias for --force-recompile."),
                              cl::aliasopt(ForceRecompile),
                              cl::cat(JoveCategory)),

          JustRun("just-run", cl::desc("Just run, nothing else"),
                  cl::cat(JoveCategory)),

          UseLd("use-ld",
                cl::desc("Force using particular linker (lld,bfd,gold)"),
                cl::cat(JoveCategory)),

          Trace(
              "trace",
              cl::desc("Instrument code to output basic block execution trace"),
              cl::cat(JoveCategory)),

          DebugSjlj(
              "debug-sjlj",
              cl::desc(
                  "Before setjmp/longjmp, dump information about the call"),
              cl::cat(JoveCategory)),

          Verbose("verbose", cl::desc("Output helpful messages for debugging"),
                  cl::cat(JoveCategory)),

          VerboseAlias("v", cl::desc("Alias for --verbose."),
                       cl::aliasopt(Verbose), cl::cat(JoveCategory)),

          Connect("connect", cl::desc("Offload work to remote server"),
                  cl::value_desc("ip address:port"), cl::cat(JoveCategory)),

          ConnectAlias("c", cl::desc("Alias for -connect."),
                       cl::aliasopt(Connect), cl::cat(JoveCategory)),

          Sleep("sleep", cl::value_desc("seconds"),
                cl::desc("Time in seconds to sleep for after finishing waiting "
                         "on child; "
                         "can be useful if the program being recompiled forks"),
                cl::cat(JoveCategory)),

          DangerousSleep1("dangerous-sleep1", cl::value_desc("useconds"),
                          cl::desc("Time in useconds to wait for the dynamic "
                                   "linker to do its thing (1)"),
                          cl::init(30000), cl::cat(JoveCategory)),

          DangerousSleep2("dangerous-sleep2", cl::value_desc("useconds"),
                          cl::desc("Time in useconds to wait for the dynamic "
                                   "linker to do its thing (2)"),
                          cl::init(40000), cl::cat(JoveCategory)),

          ForeignLibs(
              "foreign-libs",
              cl::desc("only recompile the executable itself; "
                       "treat all other binaries as \"foreign\". Implies "
                       "--no-chroot"),
              cl::cat(JoveCategory)),

          ForeignLibsAlias("x", cl::desc("Exe only. Alias for --foreign-libs."),
                           cl::aliasopt(ForeignLibs), cl::cat(JoveCategory)),

          NoChroot("no-chroot", cl::desc("run program under real sysroot"),
                   cl::cat(JoveCategory)),

          NoChrootAlias("N", cl::desc("Alias for --no-chroot."),
                        cl::aliasopt(NoChroot), cl::cat(JoveCategory)),

          PinnedGlobals(
              "pinned-globals", cl::CommaSeparated,
              cl::value_desc("glb_1,glb_2,...,glb_n"),
              cl::desc(
                  "force specified TCG globals to always go through CPUState"),
              cl::cat(JoveCategory)),

          ChangeDirectory("cd",
                          cl::desc("change directory after chroot(2)'ing"),
                          cl::cat(JoveCategory)),

          ABICalls("abi-calls",
                   cl::desc("Call ABIs indirectly through _jove_call"),
                   cl::cat(JoveCategory), cl::init(true)),

          InlineHelpers("inline-helpers",
                        cl::desc("Try to inline all helper function calls"),
                        cl::cat(JoveCategory)),

          HumanOutput("human-output",
                      cl::desc("Print messages to the given file path"),
                      cl::cat(JoveCategory)),

          Silent("silent",
                 cl::desc(
                     "Leave the stdout/stderr of the application undisturbed"),
                 cl::cat(JoveCategory)),

          RunAsRoot("superuser",
                    cl::desc("Run the given command as the superuser"),
                    cl::cat(JoveCategory)),

          RunAsRootAlias("r", cl::desc("Alias for --superuser"),
                         cl::aliasopt(RunAsRoot), cl::cat(JoveCategory)),

          PreserveEnvironment(
              "preserve-environment",
              cl::desc("Preserve environment variables when running as root"),
              cl::cat(JoveCategory)),

          PreserveEnvironmentAlias(
              "E", cl::desc("Alias for --preserve-environment"),
              cl::aliasopt(PreserveEnvironment), cl::cat(JoveCategory)) {}
  } opts;

  std::string jv_path;

public:
  LoopTool() : opts(JoveCategory) {}

  int Run(void);

  std::string soname_of_binary(binary_t &b);
};

JOVE_REGISTER_TOOL("loop", LoopTool);

static fs::path jove_rt_path, jove_dfsan_path;

static std::atomic<bool> Cancelled(false);

static std::atomic<pid_t> app_pid, run_pid;

static Tool *pTool;

static void SigHandler(int no) {
  assert(pTool);
  Tool &tool = *pTool;

  switch (no) {
  case SIGTERM:
    if (pid_t pid = app_pid.load()) {
      // what we really want to do is terminate the child.
      if (::kill(pid, SIGTERM) < 0) {
        int err = errno;
        tool.HumanOut() << llvm::formatv(
            "failed to redirect SIGTERM: {0}\n", strerror(err));
      }
    } else {
      tool.HumanOut() << "received SIGTERM but no app to redirect to! exiting...\n";
      exit(0);
    }
    break;

  case SIGINT:
    if (pid_t pid = run_pid.load()) {
      // tell run to exit sleep loop
      if (::kill(pid, SIGUSR1) < 0) {
        int err = errno;
        tool.HumanOut() << llvm::formatv(
            "failed to send SIGUSR1 to jove-run: {0}\n", strerror(err));
      }
    } else {
      tool.HumanOut() << "Received SIGINT. Cancelling..\n";

      Cancelled.store(true);
    }
    break;

  case SIGBUS:
  case SIGSEGV: {
    const char *msg = "jove-loop crashed! attach with a debugger..";
    ::write(STDERR_FILENO, msg, strlen(msg));

    for (;;)
      sleep(1);

    __builtin_unreachable();
  }

  default:
    abort();
  }
}

int LoopTool::Run(void) {
  pTool = this;

  for (char *dashdash_arg : dashdash_args)
    opts.Args.push_back(dashdash_arg);

  if (!opts.Silent && !opts.HumanOutput.empty())
    HumanOutToFile(opts.HumanOutput);

  //
  // signal handlers
  //
  {
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = SigHandler;

    if (::sigaction(SIGINT, &sa, nullptr) < 0 ||
        ::sigaction(SIGTERM, &sa, nullptr) < 0 ||
        ::sigaction(SIGSEGV, &sa, nullptr) < 0 ||
        ::sigaction(SIGBUS, &sa, nullptr) < 0) {
      int err = errno;
      HumanOut() << llvm::formatv("{0}: sigaction failed ({1})\n", __func__,
                                  strerror(err));
      return 1;
    }
  }

  jove_rt_path =
      (boost::dll::program_location().parent_path() / "libjove_rt.so").string();
  if (!fs::exists(jove_rt_path)) {
    HumanOut() << llvm::formatv("could not find libjove_rt.so ({0})\n",
                                jove_rt_path.c_str());
    return 1;
  }

  jove_dfsan_path =
      (boost::dll::program_location().parent_path().parent_path().parent_path() /
       "prebuilts" / "lib" / ("libclang_rt.dfsan.jove-" TARGET_ARCH_NAME ".so"))
          .string();
  if (!fs::exists(jove_dfsan_path)) {
    HumanOut() << llvm::formatv("could not find {0}\n",
                                jove_dfsan_path.c_str());
    return 1;
  }

  const char *const sudo_path = "/usr/bin/sudo";

  const bool WillChroot = !(opts.NoChroot || opts.ForeignLibs);
  const bool LivingDangerously = !WillChroot && !opts.ForeignLibs;

  bool sudo = (WillChroot || LivingDangerously || opts.RunAsRoot) &&
              fs::exists(sudo_path);

  if (::getuid() == 0)
    sudo = false; /* we are already root */

  if (!opts.Connect.empty() && opts.Connect.find(':') == std::string::npos) {
    HumanOut() << "usage: --connect IPADDRESS:PORT\n";
    return 1;
  }

  jv_path = opts.jv;
  if (jv_path.empty())
    jv_path = path_to_jv(opts.Prog.c_str());

  std::string sysroot = opts.Sysroot;
  if (sysroot.empty())
    sysroot = path_to_sysroot(opts.Prog.c_str(), opts.ForeignLibs);

  if (!fs::exists(sysroot)) {
    fs::create_directory(sysroot);
  } else if (!fs::is_directory(sysroot)) {
    HumanOut() << llvm::formatv("sysroot {0} is not directory\n", sysroot);
    return 1;
  }

  if (!fs::exists(jv_path)) {
    HumanOut() << jv_path << " does not exist\n";
    return 1;
  }

  while (!Cancelled) {
    pid_t pid;

    static bool FirstTime = true;
    if (unlikely(FirstTime)) {
      FirstTime = false;

      if (opts.ForceRecompile)
        goto skip_run;
    }

    {
      fs::path chrooted_path(sysroot);
      chrooted_path /= opts.Prog;

      if (!fs::exists(chrooted_path)) {
        HumanOut() << llvm::formatv(
            "{0} does not exist; recompiling...\n", chrooted_path.c_str());
        goto skip_run;
      }
    }

    //
    // run
    //
run:
    {
      std::string fifo_dir = "/tmp/jove.XXXXXX";
      if (!mkdtemp(&fifo_dir[0])) {
        int err = errno;
        throw std::runtime_error("failed to make temporary directory: " +
                                 std::string(strerror(err)));
      }

      if (::chmod(fifo_dir.c_str(), 0777) < 0) {
        int err = errno;
        throw std::runtime_error("failed to change permissions of temporary directory: " +
                                 std::string(strerror(err)));
      }

      std::string fifo_path = fifo_dir + "/pid.fifo";
      if (::mkfifo(fifo_path.c_str(), 0666) < 0) {
        int err = errno;
        HumanOut() << llvm::formatv("mkfifo failed : %s\n", strerror(err));
        return 1;
      }

      pid = ::fork();
      if (!pid) {
        std::vector<const char *> arg_vec;

        if (sudo) {
          arg_vec.push_back(sudo_path);

          if (opts.PreserveEnvironment)
            arg_vec.push_back("-E");
        }

        std::string jove_path = boost::dll::program_location().string();
        if (boost::algorithm::ends_with(jove_path, " (deleted)"))
          jove_path = jove_path.substr(0, jove_path.size() - sizeof(" (deleted)") + 1);

        arg_vec.push_back(jove_path.c_str());
        arg_vec.push_back("run");

        arg_vec.push_back("--pid-fifo");
        arg_vec.push_back(fifo_path.c_str());

        std::string gid_arg;
        if (sudo && ::getgid() > 0 && !opts.RunAsRoot) {
          gid_arg = std::to_string(::getgid());

          arg_vec.push_back("-g");
          arg_vec.push_back(gid_arg.c_str());
        }

        std::string uid_arg;
        if (sudo && ::getuid() > 0 && !opts.RunAsRoot) {
          uid_arg = std::to_string(::getuid());

          arg_vec.push_back("-u");
          arg_vec.push_back(uid_arg.c_str());
        }

        arg_vec.push_back("--sysroot");
        arg_vec.push_back(sysroot.c_str());
        arg_vec.push_back("-d");
        arg_vec.push_back(jv_path.c_str());

        if (!opts.HumanOutput.empty()) {
          arg_vec.push_back("--human-output");
          arg_vec.push_back(opts.HumanOutput.c_str());
        }

        if (opts.Verbose)
          arg_vec.push_back("--verbose");

        if (opts.ForeignLibs)
          arg_vec.push_back("--foreign-libs");

        if (opts.NoChroot || opts.ForeignLibs)
          arg_vec.push_back("--no-chroot");

        std::string danger_sleep1_arg;
        if (opts.NoChroot && !opts.ForeignLibs) {
          danger_sleep1_arg = "--dangerous-sleep1=" + std::to_string(opts.DangerousSleep1);
          arg_vec.push_back(danger_sleep1_arg.c_str());
        }

        std::string danger_sleep2_arg;
        if (opts.NoChroot && !opts.ForeignLibs) {
          danger_sleep2_arg = "--dangerous-sleep2=" + std::to_string(opts.DangerousSleep2);
          arg_vec.push_back(danger_sleep2_arg.c_str());
        }

        if (!opts.ChangeDirectory.empty()) {
          arg_vec.push_back("--cd");
          arg_vec.push_back(opts.ChangeDirectory.c_str());
        }

        std::string env_arg;

        if (!opts.EnvFromFile.empty()) {
          arg_vec.push_back("--env-from-file");
          arg_vec.push_back(opts.EnvFromFile.c_str());
        }

        if (!opts.ArgsFromFile.empty()) {
          arg_vec.push_back("--args-from-file");
          arg_vec.push_back(opts.ArgsFromFile.c_str());
        }

        std::string bind_arg;
        if (!opts.BindMountDirs.empty()) {
          bind_arg = "--bind=";

          for (const std::string &Dir : opts.BindMountDirs) {
            bind_arg.append(Dir);
            bind_arg.push_back(',');
          }
          bind_arg.resize(bind_arg.size() - 1); /* remove extra comma */

          arg_vec.push_back(bind_arg.c_str());
        }

        if (!opts.Envs.empty()) {
          for (std::string &s : opts.Envs) {
            env_arg.append(s);
            env_arg.push_back(',');
          }
          env_arg.resize(env_arg.size() - 1);

          arg_vec.push_back("--env");
          arg_vec.push_back(env_arg.c_str());
        }

        std::string sleep_arg;
        if (unsigned Sec = opts.Sleep) {
          arg_vec.push_back("--sleep");
          sleep_arg = std::to_string(Sec);
          arg_vec.push_back(sleep_arg.c_str());
        }

        //
        // program + args
        //
        arg_vec.push_back(opts.Prog.c_str());
        if (!opts.Args.empty())
          arg_vec.push_back("--");
        for (std::string &s : opts.Args)
          arg_vec.push_back(s.c_str());

        arg_vec.push_back(nullptr);

        std::vector<const char *> env_vec;

        //
        // initialize env from environ
        //
        for (char **p = ::environ; *p; ++p)
          env_vec.push_back(*p);

        env_vec.push_back(nullptr);

        if (opts.Verbose)
          print_command(&arg_vec[0]);

        ::execve(sudo ? "/usr/bin/sudo" : jove_path.c_str(),
                 const_cast<char **>(&arg_vec[0]),
                 const_cast<char **>(&env_vec[0]));

        int err = errno;
        HumanOut() << llvm::formatv("execve failed: {0}\n",
                                    strerror(err));
        return 1;
      }

      IgnoreCtrlC();

      run_pid.store(pid);

      //
      // read app pid from fifo
      //
      {
        int pid_fd = ::open(fifo_path.c_str(), O_RDONLY);
        if (pid_fd < 0) {
          int err = errno;
          HumanOut() << llvm::formatv("failed to open pid fifo: {0}\n",
                                      strerror(err));
        } else {
          uint64_t u64;

          ssize_t ret = robust_read(pid_fd, &u64, sizeof(u64));

          if (ret != sizeof(u64)) {
            if (ret < 0)
              HumanOut() << llvm::formatv(
                  "failed to read pid from pipe: {0}\n", strerror(-ret));
            else
              HumanOut() << llvm::formatv(
                  "failed to read pid from pipe: got {0}\n", ret);
          } else {
            app_pid.store(u64);
          }

          if (::close(pid_fd) < 0) {
            int err = errno;
            HumanOut() << llvm::formatv("failed to close pid fifo: {0}\n",
                                        strerror(err));
          }
        }

        if (::unlink(fifo_path.c_str()) < 0) {
          int err = errno;
          HumanOut() << llvm::formatv("failed to delete pid fifo: {0}\n",
                                      strerror(err));
        }

        fs::remove_all(fifo_dir);
      }

      {
        int ret = WaitForProcessToExit(pid);

        //
        // XXX currently the only way to know that jove-recover was run is by
        // looking at the exit status
        //
        if (ret != 'b' &&
            ret != 'f' &&
            ret != 'F' &&
            ret != 'r')
          break;
      }

      run_pid.store(0); /* reset */
      app_pid.store(0); /* reset */
    }

    if (opts.JustRun)
      break;

skip_run:
    if (!opts.Connect.empty()) { /* remote */
      //
      // connect to jove-server
      //
      int remote_fd = ::socket(AF_INET, SOCK_STREAM, 0);
      if (remote_fd < 0) {
        int err = errno;
        HumanOut() << llvm::formatv("socket failed: {0}\n", strerror(err));
        return 1;
      }

      scoped_fd __remote_fd(remote_fd);

      std::string addr_str;

      unsigned port = 0;
      {
        auto colon_idx = opts.Connect.find(':');
        assert(colon_idx != std::string::npos);
        std::string port_s = opts.Connect.substr(colon_idx + 1, std::string::npos);
        if (opts.Verbose)
          HumanOut() << llvm::formatv("parsed port as {0}\n", port_s);
        port = atoi(port_s.c_str());

        addr_str = opts.Connect.substr(0, colon_idx);
      }

      struct sockaddr_in server_addr;

      server_addr.sin_family = AF_INET;
      server_addr.sin_port = htons(port);
      server_addr.sin_addr.s_addr = inet_addr(addr_str.c_str());

      int connect_ret;
      if (opts.Verbose)
        HumanOut() << llvm::formatv("connecting to remote {0}...\n", opts.Connect);
      connect_ret = ::connect(remote_fd,
                              reinterpret_cast<struct sockaddr *>(&server_addr),
                              sizeof(sockaddr_in));
      if (connect_ret < 0 && errno != EINPROGRESS) {
        int err = errno;
        HumanOut() << llvm::formatv("connect failed: {0}\n", strerror(err));
        return 1;
      }

      //
      // send magic bytes
      //
      {
        char magic[4] = {'J', 'O', 'V', 'E'};

        ssize_t ret = robust_write(remote_fd, &magic[0], sizeof(magic));

        if (ret < 0) {
          HumanOut() << llvm::formatv(
              "failed to send magic bytes: {0}\n", strerror(-ret));
          break;
        }
      }

      //
      // send header
      //
      {
        std::bitset<8> headerBits;

        headerBits.set(0, opts.DFSan);
        headerBits.set(1, opts.ForeignLibs);
        headerBits.set(2, opts.Trace);
        headerBits.set(3, opts.Optimize);
        headerBits.set(4, opts.SkipCopyRelocHack);
        headerBits.set(5, opts.DebugSjlj);
        headerBits.set(6, opts.ABICalls);

        uint8_t header = headerBits.to_ullong();

        ssize_t ret = robust_write(remote_fd, &header, sizeof(header));

        if (ret < 0) {
          HumanOut() << llvm::formatv(
              "failed to send header to remote: {0}\n", strerror(-ret));

          break;
        }
      }

      //
      // --pinned-globals XXX
      //
      {
        uint8_t NPinnedGlobals = opts.PinnedGlobals.size();

        ssize_t ret = robust_write(remote_fd, &NPinnedGlobals, sizeof(NPinnedGlobals));

        if (ret < 0) {
          HumanOut() << llvm::formatv(
              "failed to send NPinnedGlobals to remote: {0}\n",
              strerror(-ret));

          break;
        }

        for (const std::string &PinnedGlobalStr : opts.PinnedGlobals) {
          uint8_t PinnedGlobalStrLen = PinnedGlobalStr.size();

          if (robust_write(remote_fd, &PinnedGlobalStrLen, sizeof(PinnedGlobalStrLen)) < 0) {
            HumanOut() << "failed to send PinnedGlobalStr to remote: {0}\n";
            return 0;
          }

          if (robust_write(remote_fd, PinnedGlobalStr.c_str(), PinnedGlobalStr.size()) < 0) {
            HumanOut() << "failed to send PinnedGlobalStr\n";
            return 0;
          }
        }
      }

      //
      // send the jv
      //
      {
        if (opts.Verbose)
          HumanOut() << llvm::formatv("sending {0}\n", jv_path.c_str());

        ssize_t ret = robust_sendfile_with_size(remote_fd, jv_path.c_str());

        if (ret < 0) {
          HumanOut() << llvm::formatv(
              "failed to send jv: {0}\n", strerror(-ret));

          break;
        }
      }

      ReadJvFromFile(jv_path, jv);

      //
      // ... the remote analyzes and recompiles and sends us a new jv
      //
      {
        std::string tmpjv = "/tmp/tmpjv.jv";

        if (opts.Verbose)
          HumanOut() << llvm::formatv("receiving {0}\n", jv_path.c_str());

        ssize_t ret = robust_receive_file_with_size(remote_fd, jv_path.c_str(), 0666);
        if (ret < 0) {
          HumanOut() << llvm::formatv(
              "failed to receive jv from remote: {0}\n",
              strerror(-ret));
          break;
        }
      }

      for (const binary_t &binary : jv.Binaries) {
        if (binary.IsVDSO)
          continue;
        if (binary.IsDynamicLinker)
          continue;

        fs::path chrooted_path(fs::path(sysroot) / binary.Path);

        fs::create_directories(chrooted_path.parent_path());

        std::string new_chrooted_path = chrooted_path.string() + ".new";

        if (opts.Verbose)
          HumanOut() << llvm::formatv("receiving {0}\n", chrooted_path.c_str());

        ssize_t ret = robust_receive_file_with_size(remote_fd, new_chrooted_path.c_str(), 0777);
        if (ret < 0) {
          HumanOut()
              << llvm::formatv("failed to receive file {0} from remote: {1}\n",
                               chrooted_path.c_str(), strerror(-ret));
          return 1;
        }

        if (::rename(new_chrooted_path.c_str(), chrooted_path.c_str()) < 0) {
          int err = errno;
          HumanOut() << llvm::formatv("rename of {0} to {1} failed: {2}\n",
                                      new_chrooted_path.c_str(),
                                      chrooted_path.c_str(),
                                      strerror(err));
        }
      }

      // XXX duplicated code with jove-recompile
      if (opts.DFSan) {
        {
          fs::path dir = fs::path(sysroot) / "jove" / "BinaryBlockAddrTables";
          fs::remove_all(dir); /* wipe any old tables */
          fs::create_directories(dir);
        }

        {
          std::ofstream ofs((fs::path(sysroot) / "jove" / "BinaryPathsTable.txt").c_str());

          for (const binary_t &binary : jv.Binaries)
            ofs << binary.Path << '\n';
        }

        for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
          binary_t &binary = jv.Binaries[BIdx];
          auto &ICFG = binary.Analysis.ICFG;

          {
            std::ofstream ofs((fs::path(sysroot) / "jove" /
                               "BinaryBlockAddrTables" / std::to_string(BIdx))
                                  .c_str());

            for (basic_block_index_t BBIdx = 0; BBIdx < boost::num_vertices(ICFG);
                 ++BBIdx) {
              basic_block_t bb = boost::vertex(BBIdx, ICFG);
              tcg_uintptr_t Addr = ICFG[bb].Term.Addr; /* XXX */
              ofs.write(reinterpret_cast<char *>(&Addr), sizeof(Addr));
            }
          }
        }
      }

      //
      // XXX duplicated code with jove-recompile
      //

      //
      // create symlink back to jv
      //
      if (fs::exists(fs::path(sysroot) / ".jv")) // delete any stale symlinks
        fs::remove(fs::path(sysroot) / ".jv");

      fs::create_symlink(fs::canonical(jv_path), fs::path(sysroot) / ".jv");

      //
      // create basic directories (for chroot) XXX duplicated code from recompile
      //
      if (!opts.NoChroot) {
        fs::create_directories(fs::path(sysroot) / "proc");
        fs::create_directories(fs::path(sysroot) / "sys");
        fs::create_directories(fs::path(sysroot) / "dev");
        fs::create_directories(fs::path(sysroot) / "run");
        fs::create_directories(fs::path(sysroot) / "tmp");
        fs::create_directories(fs::path(sysroot) / "etc");
        fs::create_directories(fs::path(sysroot) / "mnt"); /* dfsan_log.pb */
        fs::create_directories(fs::path(sysroot) / "usr" / "bin");
        fs::create_directories(fs::path(sysroot) / "usr" / "lib");
        fs::create_directories(fs::path(sysroot) / "var" / "run");
        fs::create_directories(fs::path(sysroot) / "lib"); /* XXX */
      }

#if 0
      //
      // (1) copy jove runtime XXX duplicated code w/ jove-recompile
      //
      {
        fs::path chrooted_path =
            fs::path(Prefix) / "usr" / "lib" / "libjove_rt.so";

        fs::create_directories(chrooted_path.parent_path());
        fs::copy_file(jove_rt_path, chrooted_path,
                      fs::copy_option::overwrite_if_exists);

        //
        // /lib could just be a symlink to usr/lib, in which case we don't want
        // the following
        //
        if (!fs::equivalent(chrooted_path,
                            fs::path(Prefix) / "lib" / "libjove_rt.so")) {
          fs::create_directories(fs::path(Prefix) / "lib");

          try {
            // XXX some dynamic linkers only look in /lib
            fs::copy_file(jove_rt_path,
                          fs::path(Prefix) / "lib" / "libjove_rt.so",
                          fs::copy_option::overwrite_if_exists);
          } catch (...) {
            ;
          }
        }
      }
#else
      //
      // delete any pre-existing runtime libraries so that we can be sure that
      // the newest version is the one that the dynamic linker reads
      //
      const char *Prefix = opts.NoChroot ? "/" : sysroot.c_str();

      fs::remove(fs::path(Prefix) / "usr" / "lib" / "libjove_rt.so");
      fs::remove(fs::path(Prefix) / "lib" / "libjove_rt.so");

      //
      // get jove runtime from remote
      //
      {
        fs::path rt_path =
            fs::path(Prefix) / "usr" / "lib" / "libjove_rt.so";

        if (opts.Verbose)
          HumanOut() << "receiving jove runtime\n";

        ssize_t ret =
            robust_receive_file_with_size(remote_fd, rt_path.c_str(), 0777);
        if (ret < 0) {
          HumanOut() << llvm::formatv(
              "failed to receive runtime {0} from remote: {1}\n",
              rt_path.c_str(), strerror(-ret));
          return 1;
        }

        //
        // /lib could just be a symlink to usr/lib, in which case we don't want
        // the following
        //
        if (!fs::equivalent(rt_path,
                            fs::path(Prefix) / "lib" / "libjove_rt.so")) {
          fs::create_directories(fs::path(Prefix) / "lib");

          try {
            // XXX some dynamic linkers only look in /lib
            fs::copy_file(rt_path,
                          fs::path(Prefix) / "lib" / "libjove_rt.so",
                          fs::copy_option::overwrite_if_exists);
          } catch (...) {
            ;
          }
        }
      }
#endif

      //
      // additional stuff for DFSan XXX taken from recompile
      //
      if (opts.DFSan) {
        fs::create_directories(fs::path(Prefix) / "jove");
        fs::create_directories(fs::path(Prefix) / "dfsan");

        {
          std::ofstream ofs(
              (fs::path(Prefix) / "jove" / "BinaryPathsTable.txt").c_str());

          for (const binary_t &binary : jv.Binaries)
            ofs << binary.Path << '\n';
        }

        fs::create_directories(fs::path(Prefix) / "jove" /
                               "BinaryBlockAddrTables");

        for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
          binary_t &binary = jv.Binaries[BIdx];
          auto &ICFG = binary.Analysis.ICFG;

          {
            std::ofstream ofs((fs::path(Prefix) / "jove" /
                               "BinaryBlockAddrTables" / std::to_string(BIdx))
                                  .c_str());

            for (basic_block_index_t BBIdx = 0; BBIdx < boost::num_vertices(ICFG);
                 ++BBIdx) {
              basic_block_t bb = boost::vertex(BBIdx, ICFG);
              tcg_uintptr_t Addr = ICFG[bb].Term.Addr; /* XXX */
              ofs.write(reinterpret_cast<char *>(&Addr), sizeof(Addr));
            }
          }
        }
      }

      //
      // get dfsan runtime from remote
      //
      if (opts.DFSan) {
        const char *dfsan_rt_filename = "libclang_rt.dfsan.jove-" TARGET_ARCH_NAME ".so";

        fs::remove(fs::path(Prefix) / "usr" / "lib" / dfsan_rt_filename);
        fs::remove(fs::path(Prefix) / "lib" / dfsan_rt_filename);

        fs::path dfsan_rt_path =
            fs::path(Prefix) / "usr" / "lib" / dfsan_rt_filename;

        if (opts.Verbose)
          HumanOut() << "receiving jove dfsan runtime\n";

        ssize_t ret =
            robust_receive_file_with_size(remote_fd, dfsan_rt_path.c_str(), 0777);
        if (ret < 0) {
          HumanOut() << llvm::formatv(
              "failed to receive runtime {0} from remote: {1}\n",
              dfsan_rt_path.c_str(), strerror(-ret));
          return 1;
        }

        //
        // /lib could just be a symlink to usr/lib, in which case we don't want
        // the following
        //
        if (!fs::equivalent(dfsan_rt_path,
                            fs::path(Prefix) / "lib" / dfsan_rt_filename)) {
          try {
            // XXX some dynamic linkers only look in /lib
            fs::copy_file(dfsan_rt_path,
                          fs::path(Prefix) / "lib" / dfsan_rt_filename,
                          fs::copy_option::overwrite_if_exists);
          } catch (...) {
            ;
          }
        }
      }

      //
      // create symlinks as necessary
      //
      if (!opts.NoChroot) {
        for (binary_t &b : jv.Binaries) {
          if (b.IsVDSO)
            continue;

          std::string soname = soname_of_binary(b);

          if (soname.empty())
            continue;

          fs::path chrooted_path = fs::path(sysroot) / b.Path;
          std::string binary_filename = fs::path(b.Path).filename().string();

          if (opts.Verbose)
            HumanOut() << llvm::formatv("{0}'s soname is {1}\n", b.Path, soname);

          if (binary_filename != soname) {
            fs::path dst = chrooted_path.parent_path() / soname;

            if (fs::exists(dst))
              fs::remove(dst);

            fs::create_symlink(binary_filename, dst);
          }
        }
      }
    } else { /* local */
      //
      // analyze
      //
      pid = ::fork();
      if (!pid) {
        std::vector<const char *> arg_vec = {
            "-d", jv_path.c_str()
        };

        std::string pinned_globals_arg = "--pinned-globals=";
        if (!opts.PinnedGlobals.empty()) {
          for (const std::string &PinnedGlbStr : opts.PinnedGlobals) {
            pinned_globals_arg.append(PinnedGlbStr);
            pinned_globals_arg.push_back(',');
          }
          assert(!pinned_globals_arg.empty());
          pinned_globals_arg.resize(pinned_globals_arg.size() - 1);

          arg_vec.push_back(pinned_globals_arg.c_str());
        }

        if (opts.ForeignLibs)
          arg_vec.push_back("--exe");

        if (opts.Verbose)
          print_tool_command("analyze", arg_vec);
        exec_tool("analyze", arg_vec);

        int err = errno;
        HumanOut() << llvm::formatv("execve failed: {0}\n",
                                    strerror(err));
        return 1;
      }

      if (int ret = WaitForProcessToExit(pid)) {
        HumanOut() << llvm::formatv("jove-analyze failed [{0}]\n", ret);
        return ret;
      }

      //
      // recompile
      //
      pid = ::fork();
      if (!pid) {
        std::vector<const char *> arg_vec = {
            "-d", jv_path.c_str(),
            "-o", sysroot.c_str(),
        };

        std::string use_ld_arg;
        if (!opts.UseLd.empty()) {
          use_ld_arg = "--use-ld=" + opts.UseLd;
          arg_vec.push_back(use_ld_arg.c_str());
        }

        if (opts.Verbose)
          arg_vec.push_back("--verbose");

        if (opts.DFSan)
          arg_vec.push_back("--dfsan");

        if (opts.Optimize)
          arg_vec.push_back("--optimize");

        if (opts.Trace)
          arg_vec.push_back("--trace");

        if (opts.DebugSjlj)
          arg_vec.push_back("--debug-sjlj");

        if (opts.ForeignLibs)
          arg_vec.push_back("--foreign-libs");

        if (!opts.ABICalls)
          arg_vec.push_back("--abi-calls=0");

        if (opts.InlineHelpers)
          arg_vec.push_back("--inline-helpers");

        std::string pinned_globals_arg;
        if (!opts.PinnedGlobals.empty()) {
          pinned_globals_arg = "--pinned-globals=";
          for (const std::string &PinnedGlbStr : opts.PinnedGlobals) {
            pinned_globals_arg.append(PinnedGlbStr);
            pinned_globals_arg.push_back(',');
          }
          pinned_globals_arg.resize(pinned_globals_arg.size() - 1);

          arg_vec.push_back(pinned_globals_arg.c_str());
        }

        if (opts.Verbose)
          print_tool_command("recompile", arg_vec);
        exec_tool("recompile", arg_vec);

        int err = errno;
        HumanOut() << llvm::formatv("execve failed: {0}\n",
                                    strerror(err));
        return 1;
      }

      if (int ret = WaitForProcessToExit(pid)) {
        HumanOut() << llvm::formatv("jove-recompile failed [{0}]\n", ret);
        return ret;
      }
    }
  }

  return 0;
}

std::string LoopTool::soname_of_binary(binary_t &b) {
  auto Bin = CreateBinary(b.Data);
  if (!llvm::isa<ELFO>(Bin.get())) {
    HumanOut() << "is not ELF of expected type\n";
    return "";
  }

  ELFO &O = *llvm::cast<ELFO>(Bin.get());

  const ELFF &E = *O.getELFFile();

  DynRegionInfo DynamicTable(O.getFileName());
  loadDynamicTable(&E, &O, DynamicTable);

  auto dynamic_table = [&](void) -> Elf_Dyn_Range {
    return DynamicTable.getAsArrayRef<Elf_Dyn>();
  };

  if (!DynamicTable.Addr)
    return "";

  llvm::StringRef DynamicStringTable;
  const Elf_Shdr *SymbolVersionSection;
  std::vector<VersionMapEntry> VersionMap;
  llvm::Optional<DynRegionInfo> OptionalDynSymRegion =
      loadDynamicSymbols(&E, &O,
                         DynamicTable,
                         DynamicStringTable,
                         SymbolVersionSection,
                         VersionMap);

  if (!DynamicStringTable.data())
    return "";

  //
  // parse dynamic table
  //
  llvm::Optional<uint64_t> SONameOffset;

  for (const Elf_Dyn &Dyn : dynamic_table()) {
    if (unlikely(Dyn.d_tag == llvm::ELF::DT_NULL))
      break; /* marks end of dynamic table. */

    switch (Dyn.d_tag) {
    case llvm::ELF::DT_SONAME:
      SONameOffset.emplace(Dyn.getVal());
      break;
    }
  }

  if (SONameOffset) {
    uint64_t Off = *SONameOffset;
    if (Off >= DynamicStringTable.size()) {
      if (opts.Verbose)
        HumanOut() << llvm::formatv("[{0}] bad SONameOffset {1}\n",
                                    b.Path, Off);
    } else {
      const char *c_str = DynamicStringTable.data() + Off;
      return c_str;
    }
  }

  return "";
}

} // namespace jove
