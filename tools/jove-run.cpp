#include "tool.h"
#include "recovery.h"
#include "B.h"
#include "crypto.h"
#include "tcg.h"
#include "explore.h"
#include "ansi.h"
#include "pidfd.h"
#include "fork.h"
#include "mmap.h"
#include "redirect.h"

#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/scope/defer.hpp>
#include <boost/preprocessor/seq/for_each.hpp>
#include <boost/preprocessor/seq/elem.hpp>
#include <boost/preprocessor/seq/seq.hpp>
#include <boost/interprocess/anonymous_shared_memory.hpp>
#include <boost/interprocess/managed_external_buffer.hpp>

#include <llvm/Support/FormatVariadic.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/WithColor.h>

#include <atomic>
#include <cinttypes>
#include <string>
#include <thread>

#include <fcntl.h>
#include <pthread.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <poll.h>
#include <linux/prctl.h>  /* Definition of PR_* constants */
#include <sys/prctl.h>

#include "jove/assert.h"

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

namespace {

struct binary_state_t {
  std::unique_ptr<llvm::object::Binary> Bin;

  binary_state_t(const auto &b) { Bin = B::Create(b.data()); }
};

struct shared_data_t {
  ip_mutex mtx;
  std::atomic<char> recovered_ch = '\0';
};

}

struct RunTool : public StatefulJVTool<ToolKind::Standard, binary_state_t, void, void> {
  struct Cmdline {
    cl::opt<std::string> Prog;
    cl::list<std::string> Args;
    cl::list<std::string> Envs;
    cl::opt<std::string> EnvFromFile;
    cl::opt<std::string> ArgsFromFile;
    cl::list<std::string> BindMountDirs;
    cl::opt<std::string> sysroot;
    cl::opt<unsigned> Sleep;
    cl::opt<unsigned> DangerousSleep1;
    cl::opt<unsigned> DangerousSleep2;
    cl::opt<bool> NoChroot;
    cl::opt<std::string> ChangeDirectory;
    cl::opt<bool> ForeignLibs;
    cl::alias ForeignLibsAlias;
    cl::opt<std::string> HumanOutput;
    cl::opt<bool> Silent;
    cl::opt<std::string> Group;
    cl::alias GroupAlias;
    cl::opt<std::string> User;
    cl::alias UserAlias;
    cl::opt<unsigned> ChildFd;
    cl::opt<std::string> WineStderr;
    cl::opt<std::string> Stdout;
    cl::opt<std::string> Stderr;
    cl::opt<bool> Symbolize;

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

          sysroot("sysroot", cl::desc("Output directory"), cl::Required,
                  cl::cat(JoveCategory)),

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

          NoChroot("no-chroot",
                   cl::desc("run program under real sysroot (useful when "
                            "combined with --foreign-libs)"),
                   cl::cat(JoveCategory)),

          ChangeDirectory("cd",
                          cl::desc("change directory after chroot(2)'ing"),
                          cl::cat(JoveCategory)),

          ForeignLibs(
              "foreign-libs",
              cl::desc("only recompile the executable itself; "
                       "treat all other binaries as \"foreign\". Implies "
                       "--no-chroot"),
              cl::cat(JoveCategory), cl::init(true)),

          ForeignLibsAlias("x", cl::desc("Exe only. Alias for --foreign-libs."),
                           cl::aliasopt(ForeignLibs), cl::cat(JoveCategory)),

          HumanOutput("human-output",
                      cl::desc("Print messages to the given file path"),
                      cl::cat(JoveCategory)),

          Silent("silent",
                 cl::desc(
                     "Leave the stdout/stderr of the application undisturbed"),
                 cl::cat(JoveCategory)),

          Group("group", cl::desc("Run as given group"),
                cl::cat(JoveCategory)),

          GroupAlias("g", cl::desc("Alias for --group"), cl::aliasopt(Group),
                     cl::cat(JoveCategory)),

          User("user", cl::desc("Run as given user"),
               cl::cat(JoveCategory)),

          UserAlias("u", cl::desc("Alias for --user"), cl::aliasopt(User),
                    cl::cat(JoveCategory)),

          ChildFd("child-fd",
                  cl::desc("File descriptor to which child PID will be written"),
                  cl::cat(JoveCategory)),

          WineStderr("wine-stderr",
                     cl::desc("Redirect WINEDEBUG output with WINEDEBUGLOG"),
                     cl::cat(JoveCategory)),

          Stdout("stdout", cl::desc("Redirect stdout to file"),
                 cl::cat(JoveCategory)),

          Stderr("stderr", cl::desc("Redirect stderr to file"),
                 cl::cat(JoveCategory)),

          Symbolize("symbolize",
                 cl::desc("When recovering try to symbolize addresses"),
                 cl::init(true),
                 cl::cat(JoveCategory))
          {}
  } opts;

  static constexpr unsigned shared_region_size = 1024;

  boost::interprocess::mapped_region shared_mem;
  boost::interprocess::managed_external_buffer shared_buff;
  shared_data_t &shared_data;

  const bool IsCOFF;

  std::unique_ptr<disas_t> disas;
  std::unique_ptr<tiny_code_generator_t> tcg;
  std::unique_ptr<symbolizer_t> symbolizer;
  std::unique_ptr<explorer_t<IsToolMT, IsToolMinSize>> Explorer;
  std::unique_ptr<CodeRecovery<IsToolMT, IsToolMinSize>> Recovery;

  std::unique_ptr<scoped_mmap> child_mapping;

  int get_child_fd(void) const {
    if (!child_mapping)
      std::abort();
    if (!(*child_mapping))
      return -1;

    return __atomic_load_n(reinterpret_cast<int *>(child_mapping->ptr),
                           __ATOMIC_RELAXED);
  }

public:
  RunTool()
      : opts(JoveCategory),
        shared_mem(boost::interprocess::anonymous_shared_memory(shared_region_size)),
        shared_buff(boost::interprocess::create_only, shared_mem.get_address(), shared_region_size),
        shared_data(*shared_buff.construct<shared_data_t>(boost::interprocess::anonymous_instance)()),
        IsCOFF(B::is_coff(*state.for_binary(jv.Binaries.at(0)).Bin))
  {}

  int Run(void) override;

  template <bool WillChroot, bool LivingDangerously>
  int DoRun(void);

  static inline const char exited_char = '!';

  std::atomic<bool> FileSystemRestored = false;

  template <bool LivingDangerously>
  int FifoProc(const char *const fifo_file_path);

  void DropPrivileges(void);
};

JOVE_REGISTER_TOOL("run", RunTool);

typedef boost::format fmt;

static const boost::unordered::unordered_set<int> SignalsToRedirect = {
    SIGINT, SIGTERM, SIGUSR1, SIGUSR2};

int RunTool::Run(void) {
  if (!opts.HumanOutput.empty())
    HumanOutToFile(opts.HumanOutput);

  const bool WillChroot = !(opts.NoChroot || opts.ForeignLibs);
  const bool LivingDangerously = !WillChroot && !opts.ForeignLibs;

  if (WillChroot || LivingDangerously) {
    if (::getuid() > 0) {
      WithColor::error() << "must be root\n";
      return 1;
    }
  }

#define WILL_CHROOT_POSSIBILTIES                                               \
    ((true))                                                                   \
    ((false))
#define LIVING_DANGEROUSLY_POSSIBILTIES                                        \
    ((true))                                                                   \
    ((false))

#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)

#define RUN_CASE(r, product)                                                   \
  if (WillChroot        == GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)) &&         \
      LivingDangerously == GET_VALUE(BOOST_PP_SEQ_ELEM(1, product)))           \
    return DoRun<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),                     \
                 GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))>();

  BOOST_PP_SEQ_FOR_EACH_PRODUCT(RUN_CASE, (WILL_CHROOT_POSSIBILTIES)(LIVING_DANGEROUSLY_POSSIBILTIES))

  assert(false);
  return 1;
}

static void *recover_proc(const char *fifo_path);

#if 0
static std::atomic<bool> InterruptSleep = false;
#endif
static std::atomic<bool> StopFifoProc = false;
static std::atomic<bool> DeathHandlerVerbose = false;

static constexpr unsigned MAX_UMOUNT_RETRIES = 10;

struct ScopedMount {
  RunTool &tool;

  const char *const source;
  const char *const target;
  const char *const filesystemtype;
  const unsigned long mountflags;
  const void *const data;

  bool mounted = false;

  ScopedMount() = delete;

  ScopedMount(RunTool &tool,
              const char *source,
              const char *target,
              const char *filesystemtype,
              unsigned long mountflags,
              const void *data)
      : tool(tool),
        source(source),
        target(target),
        filesystemtype(filesystemtype),
        mountflags(mountflags),
        data(data) {
    if (source && *source == '\0')
      return;

    for (;;) {
      int ret = ::mount(this->source,
                        this->target,
                        this->filesystemtype,
                        this->mountflags,
                        this->data);
      if (ret < 0) {
        int err = errno;
        switch (err) {
        case EINTR:
          continue;

        default:
          if (tool.IsVerbose())
            tool.HumanOut() << llvm::formatv("mount(\"{0}\", \"{1}\", \"{2}\", {3:x}, {4}) failed: {5}\n",
                    this->source,
                    this->target,
                    this->filesystemtype,
                    (unsigned)this->mountflags,
                    (void *)this->data,
                    strerror(err));
          return;
        }
      } else {
        /* mount suceeded */
        this->mounted = true;
        break;
      }
    }
  }

  ~ScopedMount () {
    if (!this->mounted)
      return;

    unsigned retries = 0;

    for (;;) {
      int ret = ::umount2(this->target, 0);

      if (ret < 0) {
        int err = errno;

        switch (err) {
        case EBUSY:
          if (retries++ < MAX_UMOUNT_RETRIES) {
            if (tool.IsVerbose())
              tool.HumanOut() << llvm::formatv("retrying umount of {0} shortly...\n", this->target);

            usleep(10000 /* 0.01 s */);
          } else {
            tool.HumanOut() << llvm::formatv("unmounting {0} failed: EBUSY...\n", this->target);
            return;
          }
          /* fallthrough */
        case EINTR:
          continue;

        default:
          tool.HumanOut() << llvm::formatv("umount(\"{0}\") failed: {1}\n",
                                           this->target,
                                           strerror(err));
          return;
        }
      } else {
        if (tool.IsVerbose())
          tool.HumanOut() << llvm::formatv("unmounted {0}.\n", this->target);

        /* unmount suceeded */
        break;
      }
    }
  }
};

void RunTool::DropPrivileges(void) {
  if (!opts.Group.empty()) {
    unsigned gid = atoi(opts.Group.c_str());

    if (::setgid(gid) < 0) {
      int err = errno;
      HumanOut() << llvm::formatv("setgid failed: {0}", strerror(err));
    }
  }

  if (!opts.User.empty()) {
    unsigned uid = atoi(opts.User.c_str());

    if (::setuid(uid) < 0) {
      int err = errno;
      HumanOut() << llvm::formatv("setuid failed: {0}", strerror(err));
    }
  }
}

static void touch(const fs::path &);

#define __BEGIN_MOUNTS__ {
#define __END_MOUNTS__ }

template <bool WillChroot, bool LivingDangerously>
int RunTool::DoRun(void) {
  disas = std::make_unique<disas_t>();
  tcg = std::make_unique<tiny_code_generator_t>();
  if (opts.Symbolize)
    symbolizer = std::make_unique<symbolizer_t>();
  Explorer = std::make_unique<explorer_t<IsToolMT, IsToolMinSize>>(
      jv_file, jv, *disas, *tcg, GetVerbosityLevel());
  Recovery = std::make_unique<CodeRecovery<IsToolMT, IsToolMinSize>>(
      jv_file, jv, *Explorer,
      symbolizer ? boost::optional<symbolizer_t &>(*symbolizer) : boost::none);

  //
  // code recovery fifo. why don't we use an anonymous pipe? because the
  // program being recompiled may decide to close all the open file descriptors
  //
  std::string stuff_dir;
  if (WillChroot)
    stuff_dir = opts.sysroot;
  stuff_dir.append("/tmp/jove.XXXXXX");

  if (!mkdtemp(&stuff_dir[0])) {
    int err = errno;

    throw std::runtime_error("failed to make temporary directory: " +
                             std::string(strerror(err)));
  }

  BOOST_SCOPE_DEFER [&] {
    //
    // clean-up temporary files
    //
    if (ShouldDeleteTemporaryFiles())
      fs::remove_all(stuff_dir);
  };

  if (::chmod(stuff_dir.c_str(), 0777) < 0)
    throw std::runtime_error(
        "failed to change permissions of temporary directory: " +
        std::string(strerror(errno)));

  std::string fifo_path = stuff_dir + "/jove.fifo";
  if (mkfifo(fifo_path.c_str(), 0666) < 0)
    throw std::runtime_error("mkfifo failed: " + std::string(strerror(errno)));

  if (::chmod(fifo_path.c_str(), 0666) < 0)
    throw std::runtime_error(
        "failed to change permissions of temporary fifo: " +
        std::string(strerror(errno)));

  fs::path fifo_file_path = fs::canonical(fifo_path);

  std::string fifo_path_under_sysroot;
  if (WillChroot)
    fifo_path_under_sysroot = "/" + fs::relative(fifo_file_path, fs::canonical(opts.sysroot)).string();

  //
  // communicating child PID to jove-loop (1)
  //
  if (opts.ChildFd.getNumOccurrences() > 0) {
    child_mapping = std::make_unique<scoped_mmap>(nullptr, JOVE_PAGE_SIZE,
                                                  PROT_READ | PROT_WRITE,
                                                  MAP_SHARED, opts.ChildFd, 0);

    if (*child_mapping) {
      __atomic_store_n(reinterpret_cast<int *>(child_mapping->ptr), -1,
                       __ATOMIC_RELAXED); /* reset */

      ::close(opts.ChildFd);
    } else {
      if (IsVerbose())
        WithColor::warning()
            << llvm::formatv("failed to mmap child fd: {0} ({1})\n",
                             strerror(errno), opts.ChildFd);
    }
  }

  //
  // create process reading from fifo
  //
  pid_t fifo_child = jove::fork();
  if (!fifo_child) {
    DeathHandlerVerbose.store(IsVerbose(), std::memory_order_relaxed);
    auto death_handler = [](int sig) -> void {
      if (DeathHandlerVerbose.load(std::memory_order_relaxed))
        WithColor::note() << "death_handler\n";

      StopFifoProc.store(true, std::memory_order_relaxed);
    };

    struct sigaction sa;
    sa.sa_handler = death_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* no SA_RESTART here, so that open() will return EINTR */
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv(
          "failed to set FifoProc SIGTERM death handler: {0}\n", strerror(err));
    } else {
      if (::prctl(PR_SET_PDEATHSIG, SIGTERM) < 0) {
        int err = errno;
        if (IsVerbose())
          WithColor::warning()
              << llvm::formatv("prctl failed: {0}\n", strerror(err));
      }
    }

    int ret = 1;
    ignore_exception([&] {
      ret = FifoProc<LivingDangerously>(fifo_file_path.c_str());
    });
    _exit(ret);
  }

  scoped_fd pidfd(pidfd_open(fifo_child, 0));
  if (!pidfd) {
    int err = errno;
    WithColor::error() << llvm::formatv("pidfd failed: {0}\n", strerror(err));
  }

  auto KillFifoProc = [&](void) -> void {
    if (IsVeryVerbose())
      HumanOut() << "killing FifoProc\n";

    ip_scoped_lock<ip_mutex> e_lck(shared_data.mtx,
                                   boost::interprocess::defer_lock);
    if (!e_lck.try_lock_for(boost::chrono::milliseconds(20000)))
      WithColor::error() << "FifoProc ain't giving up lock!\n";

    if (pidfd_send_signal(pidfd.get(), SIGKILL, nullptr, 0) < 0) {
      int err = errno;

      if (err != ESRCH) {
        if (IsVerbose())
          WithColor::error() << llvm::formatv("pidfd_send_signal failed: {0}\n",
                                              strerror(err));
      }
    }
  };

  auto IsFifoProcStillRunning = [&](int timeout) -> bool {
    struct pollfd pfd = {.fd = pidfd.get(), .events = POLLIN};

    if (IsVeryVerbose())
      HumanOut() << "polling...\n";

    int poll_ret = ::poll(&pfd, 1, timeout);
    if (poll_ret < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv("poll failed: {0}\n", strerror(err));
      return false;
    }

    if (IsVeryVerbose())
      HumanOut() << "polled.\n";

    return poll_ret == 0;
  };

  unsigned TimesToldToStop = 0;
  auto TellFifoProcToStop = [&](void) -> bool {
    int fd = -1;
    int err = 0;
    do {
      fd = ::open(fifo_file_path.c_str(), O_WRONLY | O_NONBLOCK);
      err = errno;
    } while (fd < 0 && err == EINTR);

    scoped_fd recover_fd(fd);
    if (!recover_fd) {
      if (err != ENXIO)
        WithColor::error() << llvm::formatv(
            "failed to open fifo (\"{0}\") to signal app has exited: {1}\n",
            fifo_path, strerror(err));
      return false;
    }

    ssize_t ret = -1;
    err = 0;
    do {
      ret = ::write(fd, &exited_char, 1);
      err = errno;
    } while (ret < 0 && err == EINTR);

    if (ret != 1) {
      WithColor::error() << llvm::formatv(
          "failed to write to fifo (\"{0}\") to signal app has exited: {1}\n",
          fifo_path, strerror(err));
      return false;
    }

    ++TimesToldToStop;

    return true;
  };

  BOOST_SCOPE_DEFER [&] {
    //
    // tell FifoProc to stop running
    //
    if (IsFifoProcStillRunning(0u)) {
      if (TellFifoProcToStop()) {
        if (IsVerbose())
          WithColor::note() << "told FifoProc to stop\n";

        if (IsFifoProcStillRunning(10000))
          KillFifoProc();
      } else {
        if (IsFifoProcStillRunning(0u))
          KillFifoProc();
      }
    } else {
      WithColor::warning() << llvm::formatv("FifoProc vanished!\n");
    }

    {
      siginfo_t si;
      if (waitid(P_PIDFD, pidfd.get(), &si, WEXITED) < 0) {
        int err = errno;
        WithColor::error() << llvm::formatv("waitid failed: {0}\n",
                                            strerror(err));
      }
    }
  };

  int ret_val = 1;

#if 0 /* is this necessary? */
  if (::mount(opts.sysroot, opts.sysroot, "", MS_BIND, nullptr) < 0)
    fprintf(stderr, "bind mounting %s failed : %s\n", opts.sysroot,
            strerror(errno));
#endif

  using ScopedMayMount =
      std::conditional_t<WillChroot, ScopedMount, __do_nothing_t>;

  __BEGIN_MOUNTS__

  fs::path proc_path = fs::path(opts.sysroot) / "proc";
  ScopedMayMount proc_mnt(*this,
                                   "proc",
                                   proc_path.c_str(),
                                   "proc",
                                   MS_NOSUID | MS_NODEV | MS_NOEXEC,
                                   nullptr);

  fs::path sys_path = fs::path(opts.sysroot) / "sys";
  ScopedMayMount sys_mnt(*this,
                                  "sys",
                                  sys_path.c_str(),
                                  "sysfs",
                                  MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
                                  nullptr);

  //
  // command-line bind mounts
  //
  std::list<fs::path>                CmdLineBindMountChrootedDirs;
  std::list<ScopedMayMount> CmdLineBindMounts;

  for (const std::string &Dir : opts.BindMountDirs) {
    fs::path &chrooted_dir =
        CmdLineBindMountChrootedDirs.emplace_back(fs::path(opts.sysroot) / Dir);
    fs::create_directories(chrooted_dir);

    CmdLineBindMounts.emplace_back(*this,
                                   Dir.c_str(),
                                   chrooted_dir.c_str(),
                                   "",
                                   MS_BIND,
                                   nullptr);
  }

#if 0
  //
  // common bind mounts
  //
  fs::path dev_path = fs::path(opts.sysroot) / "dev";
  ScopedMayMount dev_mnt(*this,
                                  "udev",
                                  dev_path.c_str(),
                                  "devtmpfs",
                                  MS_NOSUID,
                                  "mode=0755");

  fs::path dev_pts_path = fs::path(opts.sysroot) / "dev" / "pts";
  ScopedMayMount dev_pts_mnt(*this,
                                      "devpts",
                                      dev_pts_path.c_str(),
                                      "devpts",
                                      MS_NOSUID | MS_NOEXEC,
                                      "mode=0620,gid=5");

  fs::path dev_shm_path = fs::path(opts.sysroot) / "dev" / "shm";
  ScopedMayMount dev_shm_mnt(*this,
                                      "shm",
                                      dev_shm_path.c_str(),
                                      "tmpfs",
                                      MS_NOSUID | MS_NODEV,
                                      "mode=1777");

  fs::path tmp_path = fs::path(opts.sysroot) / "tmp";
  ScopedMayMount tmp_mnt(*this,
                                  "tmp",
                                  tmp_path.c_str(),
                                  "tmpfs",
                                  MS_NOSUID | MS_NODEV | MS_STRICTATIME,
                                  "mode=1777");
#endif

#define __BIND_MOUNT_DIR(name, dir)                                            \
  fs::path _##name##_path;                                                     \
  try {                                                                        \
    _##name##_path = fs::canonical(dir);                                       \
  } catch (...) {                                                              \
    ;                                                                          \
  }                                                                            \
                                                                               \
  fs::path _##chrooted_##name = fs::path(opts.sysroot) / dir;                 \
                                                                               \
  if (!_##name##_path.empty())                                                 \
    fs::create_directories(_##chrooted_##name);                                \
                                                                               \
  ScopedMayMount name##_mnt(*this,                                    \
                                     _##name##_path.c_str(),                   \
                                     _##chrooted_##name.c_str(),               \
                                     "",                                       \
                                     MS_BIND,                                  \
                                     nullptr);

  __BIND_MOUNT_DIR(dev, "/dev")
  __BIND_MOUNT_DIR(run, "/run")
  __BIND_MOUNT_DIR(var, "/var")
  __BIND_MOUNT_DIR(tmp, "/tmp")
  __BIND_MOUNT_DIR(etc, "/etc")
  __BIND_MOUNT_DIR(libnvram, "/firmadyne/libnvram")

#undef __BIND_MOUNT_DIR

#define __BIND_MOUNT_FILE(name, filepath)                                      \
  fs::path _##name##_path;                                                     \
  try {                                                                        \
    _##name##_path = fs::canonical(filepath);                                  \
  } catch (...) {                                                              \
    ;                                                                          \
  }                                                                            \
                                                                               \
  fs::path _##chrooted_##name = fs::path(opts.sysroot) / filepath;             \
                                                                               \
  if (!_##name##_path.empty())                                                 \
    touch(_##chrooted_##name.c_str());                                         \
                                                                               \
  ScopedMayMount name##_mnt(*this,                                    \
                                     _##name##_path.c_str(),                   \
                                     _##chrooted_##name.c_str(), "", MS_BIND,  \
                                     nullptr);


#if 0 /* already bind mounted /etc */
  __BIND_MOUNT_FILE(resolv_conf,  "/etc/resolv.conf")
  __BIND_MOUNT_FILE(etc_passwd,   "/etc/passwd")
  __BIND_MOUNT_FILE(etc_group,    "/etc/group")
  __BIND_MOUNT_FILE(etc_shadow,   "/etc/shadow")
  __BIND_MOUNT_FILE(etc_nsswitch, "/etc/nsswitch.conf")
  __BIND_MOUNT_FILE(etc_hosts,    "/etc/hosts")
#endif

#undef __BIND_MOUNT_FILE

  {
  scoped_fd rfd;
  scoped_fd wfd;

  if (LivingDangerously) {
    //
    // this pipe will be used to make sure we don't proceed further unless the
    // execve(2) has already happened (close-on-exec)
    //
    {
      int pipefd[2] = {-1, -1};
      if (::pipe(pipefd) < 0) {
        HumanOut() << "pipe(2) failed. bug?\n";
        return 1;
      }

      rfd = pipefd[0];
      wfd = pipefd[1];
    }

    //
    // danger zone: this is where we modify the root file system
    //

    //
    // (1) create hard links to pre-existing binaries with .jove.sav suffix
    //
    for (const binary_t &binary : jv.Binaries) {
      if (binary.IsExecutable)
        continue;
      if (binary.IsVDSO)
        continue;
      if (binary.IsDynamicLinker)
        continue;

      std::string sav_path = binary.path_str() + ".jove.sav";
      if (::link(binary.path(), sav_path.c_str()) < 0) {
        int err = errno;
        HumanOut() << llvm::formatv("failed to create hard link for {0}: {1}\n",
                                    binary.path_str(), strerror(err));
        return 1;
      }
    }

    //
    // (2) copy recompiled binaries to root filesystem
    //
    for (const binary_t &binary : jv.Binaries) {
      if (binary.IsExecutable)
        continue;
      if (binary.IsVDSO)
        continue;
      if (binary.IsDynamicLinker)
        continue;

      fs::path chrooted_path = fs::path(opts.sysroot) / binary.path_str();
      std::string new_path = binary.path_str() + ".jove.new";

      if (::link(chrooted_path.c_str(), new_path.c_str()) < 0) {
        if (IsVerbose()) {
          int err = errno;
          HumanOut() << llvm::formatv("failed to create hard link {0} -> {1}: {2}\n",
                                      chrooted_path.c_str(), new_path, strerror(err));
        }

        //
        // link may fail if src and dst are in different file systems. fallback
        // to regular copy file
        //
        try {
          fs::copy_file(chrooted_path, new_path);
        } catch (...) {
          HumanOut() << llvm::formatv(
              "failed to copy {0} to {1}\n",
              chrooted_path.c_str(), new_path.c_str());
          return 1;
        }
      }
    }
  }

  //
  // now actually exec the given executable
  //
  fs::path prog_path = opts.Prog;
  if (!WillChroot && fs::equivalent(opts.Prog, jv.Binaries.at(0).path_str()))
    prog_path = fs::path(opts.sysroot) / jv.Binaries.at(0).path_str();

  pid_t pid = -1;
  try {
    std::string path_to_exec =
        IsCOFF ? locator().wine(IsTarget32) : prog_path.string();

    pid = RunExecutable(
        path_to_exec,
        [&](auto Arg) {
          if (!opts.ArgsFromFile.empty()) {
            std::ifstream ifs(opts.ArgsFromFile);

            while (ifs) {
              std::string arg_entry;
              char ch;
              while (ifs.read(&ch, sizeof(ch))) {
                if (ch == '\0')
                  break;

                arg_entry.push_back(ch);
              }

              if (!arg_entry.empty())
                Arg(arg_entry);
            }
          } else {
            Arg(path_to_exec);

            if (IsCOFF)
              Arg(prog_path.string());

            for (const std::string &s : opts.Args)
              Arg(s);
          }
        },
        [&](auto Env) {
          if (!opts.EnvFromFile.empty()) {
            std::ifstream ifs(opts.EnvFromFile);

            while (ifs) {
              std::string env_entry;
              char ch;
              while (ifs.read(&ch, sizeof(ch))) {
                if (ch == '\0')
                  break;

                env_entry.push_back(ch);
              }

              if (!env_entry.empty())
                Env(env_entry);
            }
          } else {
            InitWithEnviron(Env);

            if (IsCOFF) {
              if (!getenv("WINEPREFIX")) {
                std::string new_wine_prefix =
#if 0
                    temporary_dir() + "/.wine"
#else
                    locator().wine_prefix(IsTarget32)
#endif
                    ;

                if (IsVerbose())
                  WithColor::note() << llvm::formatv("setting WINEPREFIX={0}\n",
                                                     new_wine_prefix);
                Env("WINEPREFIX=" + new_wine_prefix);
              }

              if (!getenv("WINEARCH")) {
                // it simplifies things if we can forget about WOW64
                Env(std::string("WINEARCH=win") + (IsTarget32 ? "32" : "64"));
              }

              assert(opts.WineStderr.empty()); /* FIXME */
              assert(!WillChroot);

              std::string wine_stderr_path = stuff_dir + "/wine.stderr";
              if (IsVeryVerbose())
                WithColor::note()
                    << llvm::formatv("WINEDEBUGLOG={0}\n", wine_stderr_path);

              // FIXME look for preexisting WINEDEBUG
              Env("WINEDEBUG=+module,+loaddll,+err");
              Env("WINEDEBUGLOG=" + wine_stderr_path);
            } else {
              Env("LD_LIBRARY_PATH=" +
                  (fs::path(opts.sysroot) / "usr" / "lib").string());
            }
          }

          std::string fifo_env("JOVE_RECOVER_FIFO=");
          fifo_env.append(WillChroot ? fifo_path_under_sysroot.c_str()
                                     : fifo_file_path.c_str());

          Env(fifo_env);

          if (IsVerbose())
            HumanOut() << stuff_dir << '\n';

          SetupEnvironForRun(Env);

          if (fs::exists("/firmadyne/libnvram.so")) /* XXX firmadyne */
            Env("LD_PRELOAD=/firmadyne/libnvram.so");

          for (const std::string &s : opts.Envs)
            Env(s);
        },
        opts.Stdout,
        opts.Stderr,
        [&](const char **_argv, const char **_argc) {
          if (LivingDangerously) {
            //
            // close unused read end of pipe
            //
            rfd.close();

            //
            // make the write end of the pipe be close-on-exec
            //
            if (::fcntl(wfd.get(), F_SETFD, FD_CLOEXEC) < 0) {
              int err = errno;
              HumanOut() << llvm::formatv(
                  "failed to set pipe write end close-on-exec: {0}\n",
                  strerror(err));
            }
          }

          if (WillChroot) {
            if (::chroot(opts.sysroot.c_str()) < 0) {
              int err = errno;

              throw std::runtime_error(std::string("chroot failed: ") +
                                       strerror(err));
            }

            const char *working_dir = !opts.ChangeDirectory.empty()
                                          ? opts.ChangeDirectory.c_str()
                                          : "/";

            if (::chdir(working_dir) < 0) {
              int err = errno;

              throw std::runtime_error(std::string("chdir failed: ") +
                                       strerror(err));
            }
          }

          if (LivingDangerously) {
            //
            // (3) perform the renames!!! do this as close as possible before
            // execve
            //
            if (IsVerbose())
              HumanOut() << (__ANSI_CYAN
                             "*** modifying root file system ***" __ANSI_NORMAL_COLOR
                             "\n");

            for (const binary_t &binary : jv.Binaries) {
              if (binary.IsExecutable)
                continue;
              if (binary.IsVDSO)
                continue;
              if (binary.IsDynamicLinker)
                continue;

              std::string new_path = binary.path_str() + ".jove.new";

              if (::rename(new_path.c_str(), binary.path()) < 0) {
                int err = errno;

                HumanOut() << llvm::formatv(__ANSI_BOLD_RED
                    "rename of {0} to {1} failed: {2}\n" __ANSI_NORMAL_COLOR,
                    new_path.c_str(),
                    binary.path_str(),
                    strerror(err));
              }
            }

            if (IsVerbose())
              HumanOut()
                  << (__ANSI_CYAN
                      "*** modified root file system ***" __ANSI_NORMAL_COLOR
                      "\n");
          }

          DropPrivileges();
        });
  } catch (const std::exception &e) {
#if 0
    if (LivingDangerously)
      wfd.close(); /* close-on-exec didn't happen */
#endif

    HumanOut() << e.what() << '\n';
    return 1;
  }

  //
  // communicating child PID to jove-loop (2)
  //
  if (child_mapping && *child_mapping) {
    __atomic_store_n(reinterpret_cast<int *>(child_mapping->ptr), pid,
                     __ATOMIC_RELAXED);

    for (int no : SignalsToRedirect)
      setup_to_redirect_signal(no, *this,
                               std::bind(&RunTool::get_child_fd, this));
  }

  IgnoreCtrlC();

  if (LivingDangerously) {
    wfd.close();

    ssize_t ret;
    do {
      uint8_t byte;
      ret = ::read(rfd.get(), &byte, 1);
    } while (!(ret <= 0));

    /* if we got here, the other end of the pipe must have been closed,
     * most likely by close-on-exec */

    if (usleep(opts.DangerousSleep1) < 0) { /* wait for the dynamic linker to load the program */
      int err = errno;
      HumanOut() << llvm::formatv("usleep failed: {0}\n", strerror(err));
    }

    if (IsVerbose())
      HumanOut() << (__ANSI_MAGENTA
                     "*** restoring root file system ***" __ANSI_NORMAL_COLOR
                     "\n");

    //
    // (4) perform the renames to undo the changes we made to the root
    // filesystem all DSO's except those dynamically loaded (we do that after the second sleep)
    //
    bool HaveDynamicallyLoaded = false;
    for (const binary_t &binary : jv.Binaries) {
      if (binary.IsExecutable)
        continue;
      if (binary.IsVDSO)
        continue;
      if (binary.IsDynamicLinker)
        continue;
      if (binary.IsDynamicallyLoaded) {
        HaveDynamicallyLoaded = true;
        continue;
      }

      std::string sav_path = binary.path_str() + ".jove.sav";

      if (::rename(sav_path.c_str(), binary.path()) < 0) {
        int err = errno;
        HumanOut() << llvm::formatv(__ANSI_BOLD_RED "rename of {0} to {1} failed: {2}\n"
                                    __ANSI_NORMAL_COLOR,
                                    sav_path.c_str(),
                                    binary.path_str(),
                                    strerror(err));
      }
    }

    if (HaveDynamicallyLoaded) {
      usleep(opts.DangerousSleep2); /* wait for the dynamic linker to load the rest */

      //
      // (5) perform the renames to undo the changes we made to the root filesystem
      // for all the dynamically loaded DSOs
      //
      for (const binary_t &binary : jv.Binaries) {
        if (binary.IsExecutable)
          continue;
        if (binary.IsVDSO)
          continue;
        if (binary.IsDynamicLinker)
          continue;
        if (!binary.IsDynamicallyLoaded)
          continue;

        std::string sav_path = binary.path_str() + ".jove.sav";

        if (::rename(sav_path.c_str(), binary.path()) < 0) {
          int err = errno;
          HumanOut() << llvm::formatv(
              "rename of {0} to {1} failed: {2}\n",
              sav_path.c_str(), binary.path_str(), strerror(err));
        }
      }
    }

    FileSystemRestored.store(true);

    if (IsVerbose())
      HumanOut() << (__ANSI_MAGENTA
                     "*** restored root file system ***" __ANSI_NORMAL_COLOR
                     "\n");

    rfd.close();
  }

  //
  // wait for process to exit
  //
  ret_val = WaitForProcessToExit(pid);

  //
  // communicating child PID to jove-loop (3)
  //
  if (child_mapping && *child_mapping)
    __atomic_store_n(reinterpret_cast<int *>(child_mapping->ptr), -1,
                     __ATOMIC_RELAXED); /* reset */

  if (IsVeryVerbose())
    HumanOut() << llvm::formatv("app has exited ({0}).\n", ret_val);

  //
  // optionally sleep
  //
  if (unsigned sec = opts.Sleep) {
    HumanOut() << llvm::formatv("sleeping for {0} seconds...\n", sec);
    for (unsigned t = 0; t < sec; ++t) {
      sleep(1);

#if 0
      if (InterruptSleep.load()) {
        if (IsVerbose())
          HumanOut() << "sleep interrupted\n";
        break;
      }
#endif

      if (shared_data.recovered_ch.load(std::memory_order_relaxed)) {
        if (IsVerbose())
          HumanOut() << "sleep interrupted by jove-recover\n";
        sleep(std::min<unsigned>(sec - t, 3));
        break;
      }

      HumanOut() << ".";
    }
  }

  }

#if 0 /* is this necessary? */
  if (::umount2(opts.sysroot, 0) < 0)
    fprintf(stderr, "unmounting %s failed : %s\n", opts.sysroot, strerror(errno));
#endif

  __END_MOUNTS__

  DropPrivileges();

  {
    //
    // robust means of determining whether jove-recover has run
    //
    char ch = shared_data.recovered_ch.load(std::memory_order_relaxed);
    if (ch)
      return ch; /* return char jove-loop will recognize */
  }

  return ret_val;
}

void touch(const fs::path &p) {
  fs::create_directories(p.parent_path());
  if (!fs::exists(p))
    ::close(::open(p.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666));
}

template <bool LivingDangerously>
int RunTool::FifoProc(const char *const fifo_path) {
  if (StopFifoProc.load(std::memory_order_relaxed)) {
    if (IsVerbose())
      HumanOut() << "stopping FifoProc...\n";
    return 0;
  }

  if (IsVeryVerbose())
    HumanOut() << llvm::formatv("FifoProc: opening fifo at {0}...\n", fifo_path);

  int fd = -1;
  int err = 0;
  do {
    fd = ::open(fifo_path, O_RDONLY | O_CLOEXEC);
    err = errno;

    if (StopFifoProc.load(std::memory_order_relaxed)) {
      if (IsVerbose())
        HumanOut() << "stopping FifoProc...\n";
      return 0;
    }
  } while (fd < 0 && err == EINTR);

  {
  scoped_fd recover_fd(fd);
  if (!recover_fd) {
    int err = errno;
    die("FifoProc: failed to open fifo at " + std::string(fifo_path) + ": " +
        strerror(err));
  }

  if (IsVeryVerbose())
    HumanOut() << "FifoProc: fifo opened.\n";

  for (;;) {
    char ch;

    {
      if (IsVeryVerbose())
        HumanOut() << "FifoProc: reading from fifo...\n";

      ssize_t ret = ::read(recover_fd.get(), &ch, 1);
      if (ret != 1) {
        if (ret < 0) {
          err = errno;

          if (StopFifoProc.load(std::memory_order_relaxed)) {
            if (IsVerbose())
              HumanOut() << "stopping FifoProc...\n";
            return 0;
          }

          if (err == EINTR) {
            if (IsVeryVerbose())
              HumanOut() << "FifoProc: read interrupted\n";
            continue;
          }

          die("FifoProc: failed to read: " + std::string(strerror(err)));
        } else if (ret == 0) { /* closed */
          break;
        }

        die("FifoProc: read returned impossible value");
      }
    }

    if (IsVeryVerbose())
      HumanOut() << llvm::formatv("recover_proc: got '{0}'\n", ch);

    {
      static bool FirstTime = true;

      if (unlikely(FirstTime)) {
        FirstTime = false;

        if (LivingDangerously)
          while (!FileSystemRestored.load())
            usleep(10000 /* 0.01 s */);
      }
    }

    //
    // we assume ch is loaded with a byte from the fifo. it's got to be either
    // 'f', 'F', 'O', 'b', 'B', 'a', 'r', or '!'
    //
    if (unlikely(ch == exited_char))
      return 0; /* if we see this, the app has exited. */

    assert(Recovery);
    shared_data.recovered_ch.store(ch, std::memory_order_relaxed);

    auto do_recover = [&](void) -> std::string {
//
// paranoid (raw) macro which locks a shared mutex. this is meant to defend
// against FifoProc going (hypothetically) haywire. we are being super careful.
//
#define ___recovering___() ip_scoped_lock<ip_mutex> e_lck(shared_data.mtx)

      if (ch == 'f') {
        struct {
          uint32_t BIdx;
          uint32_t BBIdx;
        } Caller;

        struct {
          uint32_t BIdx;
          uint32_t FIdx;
        } Callee;

        {
          ssize_t ret;

          ret = robust_read(recover_fd.get(), &Caller.BIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));

          ret = robust_read(recover_fd.get(), &Caller.BBIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));

          ret = robust_read(recover_fd.get(), &Callee.BIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));

          ret = robust_read(recover_fd.get(), &Callee.FIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));
        }

        if (IsVerbose())
          HumanOut() << llvm::formatv("RecoverDynamicTarget({0}, {1}, {2}, {3})\n",
                                      Caller.BIdx,
                                      Caller.BBIdx,
                                      Callee.BIdx,
                                      Callee.FIdx);

        ___recovering___();
        return Recovery->RecoverDynamicTarget(Caller.BIdx,
                                              Caller.BBIdx,
                                              Callee.BIdx,
                                              Callee.FIdx);
      } else if (ch == 'b') {
        struct {
          uint32_t BIdx;
          uint32_t BBIdx;
        } IndBr;

        taddr_t Addr;

        {
          ssize_t ret;

          ret = robust_read(recover_fd.get(), &IndBr.BIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));

          ret = robust_read(recover_fd.get(), &IndBr.BBIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));

          ret = robust_read(recover_fd.get(), &Addr, sizeof(taddr_t));
          assert(ret == sizeof(taddr_t));
        }

        if (IsVerbose())
          HumanOut() << llvm::formatv("RecoverBasicBlock({0}, {1}, {2})\n",
                                      IndBr.BIdx,
                                      IndBr.BBIdx,
                                      taddr2str(Addr, false));

        ___recovering___();
        return Recovery->RecoverBasicBlock(IndBr.BIdx,
                                           IndBr.BBIdx,
                                           Addr);
      } else if (ch == 'F') {
        struct {
          uint32_t BIdx;
          uint32_t BBIdx;
        } IndCall;

        struct {
          uint32_t BIdx;
          taddr_t Addr;
        } Callee;

        {
          ssize_t ret;

          ret = robust_read(recover_fd.get(), &IndCall.BIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));

          ret = robust_read(recover_fd.get(), &IndCall.BBIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));

          ret = robust_read(recover_fd.get(), &Callee.BIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));

          ret = robust_read(recover_fd.get(), &Callee.Addr, sizeof(taddr_t));
          assert(ret == sizeof(taddr_t));
        }

        if (IsVerbose())
          HumanOut() << llvm::formatv(
              "RecoverFunctionAtAddress({0}, {1}, {2}, {3})\n",
              IndCall.BIdx,
              IndCall.BBIdx,
              Callee.BIdx,
              Callee.Addr);

        ___recovering___();
        return Recovery->RecoverFunctionAtAddress(IndCall.BIdx,
                                                  IndCall.BBIdx,
                                                  Callee.BIdx,
                                                  Callee.Addr);
      } else if (ch == 'O') {
        struct {
          uint32_t BIdx;
          uint32_t BBIdx;
        } IndCall;

        struct {
          uint32_t BIdx;
          taddr_t Offset;
        } Callee;

        {
          ssize_t ret;

          ret = robust_read(recover_fd.get(), &IndCall.BIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));

          ret = robust_read(recover_fd.get(), &IndCall.BBIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));

          ret = robust_read(recover_fd.get(), &Callee.BIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));

          ret = robust_read(recover_fd.get(), &Callee.Offset, sizeof(taddr_t));
          assert(ret == sizeof(taddr_t));
        }

        if (IsVerbose())
          HumanOut() << llvm::formatv(
              "RecoverFunctionAtOffset({0}, {1}, {2}, {3})\n",
              IndCall.BIdx,
              IndCall.BBIdx,
              Callee.BIdx,
              Callee.Offset);

        ___recovering___();
        return Recovery->RecoverFunctionAtOffset(IndCall.BIdx,
                                                 IndCall.BBIdx,
                                                 Callee.BIdx,
                                                 Callee.Offset);
      } else if (ch == 'a') {
        struct {
          uint32_t BIdx;
          uint32_t FIdx;
        } NewABI;

        {
          ssize_t ret;

          ret = robust_read(recover_fd.get(), &NewABI.BIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));

          ret = robust_read(recover_fd.get(), &NewABI.FIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));
        }

        if (IsVerbose())
          HumanOut() << llvm::formatv("RecoverABI({0}, {1})\n",
                                      NewABI.BIdx,
                                      NewABI.FIdx);
        ___recovering___();
        return Recovery->RecoverABI(NewABI.BIdx,
                                    NewABI.FIdx);
      } else if (ch == 'r') {
        struct {
          uint32_t BIdx;
          uint32_t BBIdx;
        } Call;

        {
          ssize_t ret;

          ret = robust_read(recover_fd.get(), &Call.BIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));

          ret = robust_read(recover_fd.get(), &Call.BBIdx, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));
        }

        if (IsVerbose())
          HumanOut() << llvm::formatv("Returns({0}, {1})\n",
                                      Call.BIdx,
                                      Call.BBIdx);

        ___recovering___();
        return Recovery->Returns(Call.BIdx,
                                 Call.BBIdx);
      } else if (ch == 'B') {
        uint32_t PathLen;
        std::string Path;

        {
          ssize_t ret;

          ret = robust_read(recover_fd.get(), &PathLen, sizeof(uint32_t));
          assert(ret == sizeof(uint32_t));

          Path.resize(PathLen);

          ret = robust_read(recover_fd.get(), &Path[0], PathLen);
          assert(ret == PathLen);
        }

        if (IsVerbose())
          HumanOut() << llvm::formatv("RecoverForeignBinary(\"{0}\")\n",
                                           Path);

        ___recovering___();
        return Recovery->RecoverForeignBinary(Path.c_str());
      } else {
        std::string ch_s;
        ch_s.push_back(ch);
        throw std::runtime_error("unknown character \"" + ch_s + "\"");
      }

#undef ___recovering___
    };

    try {
      HumanOut() << do_recover() << '\n';
    } catch (const std::exception &e) {
      HumanOut() << llvm::formatv(
          __ANSI_RED "failed to recover: {0}" __ANSI_NORMAL_COLOR "\n",
          e.what());
      break;
    }
  }

  }

  __attribute__((musttail)) return FifoProc<LivingDangerously>(fifo_path);
}
}
