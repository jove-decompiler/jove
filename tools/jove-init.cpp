#include <string>
#include <vector>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/graphviz.hpp>

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sched.h>
#include <tuple>
#include <thread>
#include <chrono>
#include <memory>
#include <mutex>
#include <queue>
#include <sstream>
#include <fstream>
#include <unordered_set>
#include <boost/filesystem.hpp>
#include <boost/dll/runtime_symbol_info.hpp>
#include <llvm/ADT/StringRef.h>
#include <llvm/Object/ELF.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/WithColor.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "jove/jove.h"
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/bitset.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/set.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/graph/topological_sort.hpp>
#include <boost/format.hpp>

#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

static void __warn(const char *file, int line);

#ifndef WARN
#define WARN()                                                                 \
  do {                                                                         \
    __warn(__FILE__, __LINE__);                                                \
  } while (0)
#endif

#ifndef WARN_ON
#define WARN_ON(condition)                                                     \
  ({                                                                           \
    int __ret_warn_on = !!(condition);                                         \
    if (unlikely(__ret_warn_on))                                               \
      WARN();                                                                  \
    unlikely(__ret_warn_on);                                                   \
  })
#endif

namespace fs = boost::filesystem;
namespace cl = llvm::cl;
namespace obj = llvm::object;

using llvm::WithColor;

namespace jove {
static unsigned num_cpus(void);
}

namespace opts {
static cl::OptionCategory JoveCategory("Specific Options");

static cl::opt<std::string> TemporaryDir("tmpdir", cl::value_desc("directory"),
                                         cl::cat(JoveCategory));

static cl::opt<std::string> Input(cl::Positional, cl::desc("prog"),
                                  cl::Required, cl::value_desc("filename"),
                                  cl::cat(JoveCategory));

static cl::opt<std::string> Output("output", cl::desc("Output"), cl::Required,
                                   cl::value_desc("filename"),
                                   cl::cat(JoveCategory));

static cl::alias OutputAlias("o", cl::desc("Alias for -output."),
                             cl::aliasopt(Output), cl::cat(JoveCategory));

static cl::opt<unsigned> Threads("num-threads",
                                 cl::desc("Number of CPU threads to use"),
                                 cl::init(jove::num_cpus()),
                                 cl::value_desc("int"), cl::cat(JoveCategory));

static cl::opt<bool> Git("git", cl::desc("git mode"), cl::cat(JoveCategory));

static cl::opt<bool>
    Verbose("verbose",
            cl::desc("Print extra information for debugging purposes"));

static cl::alias VerboseAlias("v", cl::desc("Alias for -verbose."),
                              cl::aliasopt(Verbose), cl::cat(JoveCategory));
} // namespace opts

namespace jove {
static int init(void);
}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::HideUnrelatedOptions({&opts::JoveCategory, &llvm::ColorCategory});
  cl::AddExtraVersionPrinter([](llvm::raw_ostream &OS) -> void {
    OS << "jove version " JOVE_VERSION "\n";
  });
  cl::ParseCommandLineOptions(argc, argv, "Jove Init\n");

  {
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = SIG_IGN;

    sigaction(SIGINT, &sa, nullptr);
  }

  return jove::init();
}

namespace jove {

#include "elf.hpp"

static void spawn_workers(void);

static std::queue<std::string> Q;

static std::string tmpdir;

static int await_process_completion(pid_t);

static void print_command(const char **argv);

static std::string jove_add_path, harvest_vdso_path;

static int null_fd;

static bool HasVDSO(void);
static std::pair<void *, unsigned> GetVDSO(void);

static std::string program_interpreter_of_executable(const char *exepath);

static ssize_t robust_read(int fd, void *const buf, const size_t count);
static ssize_t robust_write(int fd, const void *const buf, const size_t count);

int init(void) {
  null_fd = open("/dev/null", O_WRONLY);
  if (null_fd < 0) {
    WithColor::error() << "could not open /dev/null : " << strerror(errno)
                       << '\n';
    return 1;
  }

  jove_add_path =
      (boost::dll::program_location().parent_path() / std::string("jove-add"))
          .string();
  if (!fs::exists(jove_add_path)) {
    WithColor::error() << "could not find jove-add at " << jove_add_path << '\n';
    return 1;
  }

  harvest_vdso_path = (boost::dll::program_location().parent_path() /
                       std::string("harvest-vdso"))
                          .string();
  if (!fs::exists(harvest_vdso_path)) {
    WithColor::error() << "could not find harvest-vdso at " << harvest_vdso_path << '\n';
    return 1;
  }

  //
  // run program with LD_TRACE_LOADED_OBJECTS=1 and no arguments. capture the
  // standard output, which will tell us what binaries are needed by prog.
  //
  int pipefd[2];
  if (pipe(pipefd) < 0) {
    WithColor::error() << "pipe failed : " << strerror(errno) << '\n';
    return 1;
  }

  int rfd = pipefd[0];
  int wfd = pipefd[1];

  const bool firmadyne = fs::exists("/firmadyne/libnvram.so");

  pid_t pid = fork();

  //
  // are we the child?
  //
  if (!pid) {
    close(rfd); /* close unused read end */

    /* make stdout be the write end of the pipe */
    if (dup2(wfd, STDOUT_FILENO) < 0) {
      WithColor::error() << "dup2 failed : " << strerror(errno) << '\n';
      exit(1);
    }

    std::vector<const char *> arg_vec = {opts::Input.c_str(), nullptr};

    std::vector<const char *> env_vec;
    for (char **env = ::environ; *env; ++env)
      env_vec.push_back(*env);

    env_vec.push_back("LD_TRACE_LOADED_OBJECTS=1");

    if (firmadyne)
      env_vec.push_back("LD_PRELOAD=/firmadyne/libnvram.so");

    env_vec.push_back(nullptr);

    print_command(&arg_vec[0]);
    execve(arg_vec[0],
           const_cast<char **>(&arg_vec[0]),
           const_cast<char **>(&env_vec[0]));

    /* if we get here, exec failed */
    int err = errno;
    WithColor::error() << llvm::formatv("failed to exec {0}: {1}\n",
                                        arg_vec[0],
                                        strerror(err));
    return 1;
  }

  close(wfd); /* close unused write end */

  //
  // slurp up the result of executing the binary
  //
  std::string dynlink_stdout;
  {
    char buf;
    while (read(rfd, &buf, 1) > 0)
      dynlink_stdout += buf;
  }

  close(rfd); /* close read end */

  //
  // check exit code
  //
  if (int ret = await_process_completion(pid)) {
    WithColor::error() << "LD_TRACE_LOADED_OBJECTS=1 " << opts::Input
                 << " returned nonzero exit code " << ret << '\n';
    return 1;
  }

  //
  // prepare to process the binaries by creating a unique temporary directory
  //
  if (opts::TemporaryDir.empty()) {
    tmpdir = "/tmp/XXXXXX";

    if (!mkdtemp(&tmpdir[0])) {
      int err = errno;
      WithColor::error() << llvm::formatv("mkdtemp failed: {0}\n", strerror(err));
      return 1;
    }
  } else {
    srand(time(nullptr));
    tmpdir = (fs::path(opts::TemporaryDir) / std::to_string(rand())).string();

    if (opts::Verbose)
      llvm::errs() << "temporary dir: " << tmpdir.c_str() << '\n';

    if (mkdir(tmpdir.c_str(), 0777) < 0) {
      int err = errno;
      if (err != EEXIST) {
        WithColor::error() << llvm::formatv("could not create temporary directory: {0}\n", strerror(err));
        return 1;
      }
    }
  }

  //
  // parse the standard output from the dynamic linker to produce a set of paths
  // to binaries that will be added to the decompilation
  //
  std::vector<std::string> binary_paths;
  binary_paths.reserve(3);

  //
  // executable should be first
  //
  binary_paths.push_back(fs::canonical(opts::Input).string());

  //
  // to get the vdso, we run $(BINDIR)/$(target)/harvest-vdso. if it exists, it
  // will write the contents to STDOUT. otherwise it returns a non-zero number.
  //
  if (pipe(pipefd) < 0) {
    int err = errno;
    WithColor::error() << llvm::formatv("pipe failed: {0}\n", strerror(err));
    return 1;
  }

  rfd = pipefd[0];
  wfd = pipefd[1];

  //
  // run harvest-vdso
  //
  pid = fork();
  if (!pid) {
    close(rfd); /* close unused read end */

    /* make stdout be the write end of the pipe */
    if (dup2(wfd, STDOUT_FILENO) < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv("dup2 failed: {0}\n", strerror(err));
      return 1;
    }

    std::vector<const char *> arg_vec = {harvest_vdso_path.c_str(), nullptr};

    std::vector<const char *> env_vec;
    for (char **env = ::environ; *env; ++env)
      env_vec.push_back(*env);

    env_vec.push_back(nullptr);

    execve(arg_vec[0],
           const_cast<char **>(&arg_vec[0]),
           const_cast<char **>(&env_vec[0]));

    /* if we get here, exec failed */
    int err = errno;
    WithColor::error() << llvm::formatv("failed to exec {0}: {1}\n",
                                        arg_vec[0],
                                        strerror(err));
    return 1;
  }

  {
    int rc = close(wfd);
    assert(!(rc < 0));
  }

  //
  // stdout are contents of VDSO, if exists
  //
  std::vector<uint8_t> vdso;
  vdso.reserve(2 * 4096); /* XXX */
  {
    uint8_t byte;
    while (read(rfd, &byte, 1) > 0)
      vdso.push_back(byte);
  }

  //
  // close read end; we are done with it.
  //
  {
    int rc = close(rfd);
    assert(!(rc < 0));
  }

  if (int ret = await_process_completion(pid))
    return ret;

  if (vdso.empty()) {
    WithColor::error() << "no [vdso] found. bug?\n";
    return 1;
  }

  assert(vdso.size() % 4096 == 0);

  {
    char path[0x100];
    snprintf(path, sizeof(path), "%s/linux-vdso.so", tmpdir.c_str());

    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0666);
    ssize_t ret = robust_write(fd, &vdso[0], vdso.size());
    if (ret < 0) {
      WithColor::error() << llvm::formatv(
          "failed to write vdso to temporary path {0} ({1})\n", path,
          strerror(-ret));
      return 1;
    }

    close(fd);

    binary_paths.push_back(path);
  }

  std::string::size_type pos = 0;
  for (;;) {
    std::string::size_type arrow_pos = std::min(dynlink_stdout.find("\t/", pos),
                                                dynlink_stdout.find(" /", pos));

    if (arrow_pos == std::string::npos)
      break;

    pos = arrow_pos + strlen(" /") - 1;

    //
    // XXX XXX XXX we do not support DSO's whose path contains a space
    //
    std::string::size_type space_pos = dynlink_stdout.find(' ', pos);

    if (space_pos == std::string::npos)
      break;

    std::string path = dynlink_stdout.substr(pos, space_pos - pos);
    if (!fs::exists(path)) {
      WithColor::warning() << "path from dynamic linker '" << path << "' is bogus\n";
      continue;
    }

    std::string bin_path = fs::canonical(path).string();
    if (opts::Verbose)
      llvm::errs() << llvm::formatv("path = {0} bin_path = {1}\n", path, bin_path);

    if (std::find(binary_paths.begin(), binary_paths.end(), bin_path) != binary_paths.end())
      continue; /* duplicate */

    binary_paths.push_back(bin_path);
  }

  //
  // get the path to the dynamic linker (i.e. program interpreter)
  //
  fs::path rtld_path = fs::canonical(program_interpreter_of_executable(opts::Input.c_str()));

  if (opts::Verbose)
    WithColor::note() << llvm::formatv("rtld_path={0}\n", rtld_path.c_str());

  {
    unsigned Idx;
    for (Idx = 0; Idx < binary_paths.size(); ++Idx) {
      if (fs::equivalent(binary_paths[Idx], rtld_path)) {
        if (opts::Verbose)
          WithColor::note() << llvm::formatv("found rtld! idx={0} path={1} rtld_path={2}\n", Idx, binary_paths[Idx], rtld_path.c_str());
        goto Found;
      }
    }

    /* if we got here, we failed to find the dynamic linker */
    WithColor::error() << llvm::formatv("couldn't find rtld! {0}\n", rtld_path.c_str());
    return 1;

Found:

    if (opts::Verbose)
      WithColor::error() << llvm::formatv("rtld in binary_paths: idx={0}\n", Idx);

    if (Idx != 1) {
      //
      // modify binary_paths so that the dynamic linker is at index 1.
      //
      {
        auto it = binary_paths.begin();
        std::advance(it, Idx);
        binary_paths.erase(it);
      }

      {
        auto it = std::next(binary_paths.begin());
        binary_paths.insert(it, rtld_path.string()); /* just before vdso */
      }
    }
  }

  /* Line buffer to ensure lines are written atomically and immediately
     so that processes running in parallel do not intersperse their output.  */
  setvbuf(stdout, NULL, _IOLBF, 0);
  setvbuf(stderr, NULL, _IOLBF, 0);

  //
  // process the binaries, concurrently
  //
  for (const std::string& path : binary_paths)
    Q.push(path);

  spawn_workers();

  //
  // merge the intermediate decompilation files
  //
  decompilation_t final_decompilation;
  final_decompilation.Binaries.reserve(binary_paths.size());

  for (const std::string &path : binary_paths) {
    std::string jvfp = tmpdir + path + ".jv";
    if (!fs::exists(jvfp)) {
      WithColor::error() << "intermediate result " << jvfp << " not found" << '\n';
      return 1;
    }

    decompilation_t decompilation;
    {
      std::ifstream ifs(jvfp);

      boost::archive::text_iarchive ia(ifs);
      ia >> decompilation;
    }

    if (decompilation.Binaries.size() != 1) {
      WithColor::error() << "invalid intermediate result " << jvfp << '\n';
      return 1;
    }

    //
    // trivially combine decompilations
    //
    final_decompilation.Binaries.push_back(decompilation.Binaries.front());
  }

  final_decompilation.Binaries.at(0).IsExecutable = true;
  final_decompilation.Binaries.at(1).IsDynamicLinker = true;
  if (HasVDSO())
    final_decompilation.Binaries.at(2).IsVDSO = true;

  //
  // firmadyne janky hack
  //
  if (firmadyne) {
    for (binary_t &b : final_decompilation.Binaries) {
      if (b.Path.find("firmadyne") != std::string::npos) {
        b.IsDynamicallyLoaded = true;
        goto found;
      }
    }

    assert(false && "firmadyne DSO not found?");

found:
    ;
  }

  if (fs::exists(opts::Output)) {
    if (opts::Verbose)
      llvm::outs() << "output already exists, overwriting " << opts::Output
                   << '\n';

    if (fs::is_directory(opts::Output)) {
      fs::remove_all(opts::Output);
    } else {
      fs::remove(opts::Output);
    }
  }

  std::string final_output_path = opts::Output;
  if (opts::Git) {
    fs::create_directory(opts::Output);
    final_output_path += "/decompilation.jv";
  }

  {
    std::ofstream ofs(final_output_path);

    boost::archive::text_oarchive oa(ofs);
    oa << final_decompilation;
  }

  if (opts::Git) {
    pid_t pid;

    //
    // git init
    //
    pid = fork();
    if (!pid) {
      chdir(opts::Output.c_str());

      std::vector<const char *> arg_vec = {"/usr/bin/git", "init", nullptr};

      print_command(&arg_vec[0]);
      execve(arg_vec[0], const_cast<char **>(&arg_vec[0]), ::environ);

      /* if we get here, exec failed */
      int err = errno;
      WithColor::error() << llvm::formatv("failed to exec {0}: {1}\n",
                                          arg_vec[0],
                                          strerror(err));
      return 1;
    }

    if (int ret = await_process_completion(pid))
      return ret;

    //
    // Append '[diff "jv"]\n        textconv = jove-dump-x86_64' to .git/config
    //
    assert(fs::exists(opts::Output + "/.git/config"));
    {
      std::ofstream ofs(opts::Output + "/.git/config",
                        std::ios_base::out | std::ios_base::app);
      ofs << "\n[diff \"jv\"]\n        textconv = jove-dump";
    }

    //
    // Write '*.jv diff=jv' to .git/info/attributes
    //
    assert(!fs::exists(opts::Output + "/.git/info/attributes"));
    {
      std::ofstream ofs(opts::Output + "/.git/info/attributes");
      ofs << "*.jv diff=jv";
    }

    //
    // git add
    //
    pid = fork();
    if (!pid) {
      chdir(opts::Output.c_str());

      std::vector<const char *> arg_vec = {"/usr/bin/git", "add",
                                           "decompilation.jv", nullptr};

      print_command(&arg_vec[0]);
      execve(arg_vec[0], const_cast<char **>(&arg_vec[0]), ::environ);

      /* if we get here, exec failed */
      int err = errno;
      WithColor::error() << llvm::formatv("failed to exec {0}: {1}\n",
                                          arg_vec[0],
                                          strerror(err));
      return 1;
    }

    if (int ret = await_process_completion(pid))
      return ret;

    //
    // git commit
    //
    pid = fork();
    if (!pid) {
      chdir(opts::Output.c_str());

      std::vector<const char *> arg_vec = {
        "/usr/bin/git",
        "commit",
        ".",
        "-m",
        "initial commit",
        nullptr
      };

      print_command(&arg_vec[0]);
      execve(arg_vec[0], const_cast<char **>(&arg_vec[0]), ::environ);

      /* if we get here, exec failed */
      int err = errno;
      WithColor::error() << llvm::formatv("failed to exec {0}: {1}\n",
                                          arg_vec[0],
                                          strerror(err));
      return 1;
    }

    if (int ret = await_process_completion(pid))
      return ret;
  }

  return 0;
}

std::string program_interpreter_of_executable(const char *exepath) {
  std::string res;

  llvm::Expected<obj::OwningBinary<obj::Binary>> BinaryOrErr =
      obj::createBinary(exepath);

  if (!BinaryOrErr) {
    WithColor::error() << llvm::formatv("{0}: failed to open {1}\n", __func__,
                                        exepath);
    return res;
  }

  obj::Binary *B = BinaryOrErr.get().getBinary();
  if (!llvm::isa<ELFO>(B)) {
    WithColor::error() << llvm::formatv("{0}: invalid binary\n", __func__);
    return res;
  }

  const ELFO &O = *llvm::cast<ELFO>(B);
  const ELFF &E = *O.getELFFile();

  for (const Elf_Phdr &Phdr : unwrapOrError(E.program_headers())) {
    if (Phdr.p_type == llvm::ELF::PT_INTERP) {
      res = std::string(reinterpret_cast<const char *>(E.base() + Phdr.p_offset));
      break;
    }
  }

  return res;
}

bool HasVDSO(void) {
  bool res = false;

  FILE *fp;
  char *line = NULL;
  size_t len = 0;
  ssize_t read;

  fp = fopen("/proc/self/maps", "r");
  assert(fp);

  while ((read = getline(&line, &len, fp)) != -1) {
    int fields, dev_maj, dev_min, inode;
    uint64_t min, max, offset;
    char flag_r, flag_w, flag_x, flag_p;
    char path[512] = "";
    fields = sscanf(line,
                    "%" PRIx64 "-%" PRIx64 " %c%c%c%c %" PRIx64 " %x:%x %d"
                    " %512s",
                    &min, &max, &flag_r, &flag_w, &flag_x, &flag_p, &offset,
                    &dev_maj, &dev_min, &inode, path);

    if ((fields < 10) || (fields > 11)) {
      continue;
    }

    if (strcmp(path, "[vdso]") == 0) {
      res = true;
      break;
    }
  }

  free(line);
  fclose(fp);

  return res;
}

std::pair<void *, unsigned> GetVDSO(void) {
  struct {
    void *first;
    unsigned second;
  } res;

  res.first = nullptr;
  res.second = 0;

  FILE *fp;
  char *line = NULL;
  size_t len = 0;
  ssize_t read;

  fp = fopen("/proc/self/maps", "r");
  assert(fp);

  while ((read = getline(&line, &len, fp)) != -1) {
    int fields, dev_maj, dev_min, inode;
    uint64_t min, max, offset;
    char flag_r, flag_w, flag_x, flag_p;
    char path[512] = "";
    fields = sscanf(line,
                    "%" PRIx64 "-%" PRIx64 " %c%c%c%c %" PRIx64 " %x:%x %d"
                    " %512s",
                    &min, &max, &flag_r, &flag_w, &flag_x, &flag_p, &offset,
                    &dev_maj, &dev_min, &inode, path);

    if ((fields < 10) || (fields > 11)) {
      continue;
    }

    if (strcmp(path, "[vdso]") == 0) {
      res.first = (void *)min;
      res.second = max - min;
      break;
    }
  }

  free(line);
  fclose(fp);

  return std::make_pair(res.first, res.second);
}

unsigned GetVDSOSize(void) {
  FILE *fp;
  char *line = NULL;
  size_t len = 0;
  ssize_t read;

  fp = fopen("/proc/self/maps", "r");
  assert(fp);

  unsigned res = 0;

  while ((read = getline(&line, &len, fp)) != -1) {
    int fields, dev_maj, dev_min, inode;
    uint64_t min, max, offset;
    char flag_r, flag_w, flag_x, flag_p;
    char path[512] = "";
    fields = sscanf(line,
                    "%" PRIx64 "-%" PRIx64 " %c%c%c%c %" PRIx64 " %x:%x %d"
                    " %512s",
                    &min, &max, &flag_r, &flag_w, &flag_x, &flag_p, &offset,
                    &dev_maj, &dev_min, &inode, path);

    if ((fields < 10) || (fields > 11)) {
      continue;
    }

    if (strcmp(path, "[vdso]") == 0) {
      res = max - min;
      break;
    }
  }

  free(line);
  fclose(fp);

  return res;
}

template <bool IsRead>
static ssize_t robust_read_or_write(int fd, void *const buf, const size_t count) {
  uint8_t *const _buf = (uint8_t *)buf;

  unsigned n = 0;
  do {
    unsigned left = count - n;

    ssize_t ret = IsRead ? read(fd, &_buf[n], left) :
                          write(fd, &_buf[n], left);

    if (ret == 0)
      return -EIO;

    if (ret < 0) {
      int err = errno;

      if (err == EINTR)
        continue;

      return -err;
    }

    n += ret;
  } while (n != count);

  return n;
}


ssize_t robust_read(int fd, void *const buf, const size_t count) {
  return robust_read_or_write<true /* r */>(fd, buf, count);
}

ssize_t robust_write(int fd, const void *const buf, const size_t count) {
  return robust_read_or_write<false /* w */>(fd, const_cast<void *>(buf), count);
}

static std::mutex mtx;

static void worker(void) {
  auto pop_path = [](std::string &out) -> bool {
    std::lock_guard<std::mutex> lck(mtx);

    if (Q.empty()) {
      return false;
    } else {
      out = Q.front();
      Q.pop();
      return true;
    }
  };

  std::string path;
  while (pop_path(path)) {
    std::string jvfp = tmpdir + path + ".jv";
    fs::create_directories(fs::path(jvfp).parent_path());

    pid_t pid = fork();
    if (!pid) {
      std::vector<const char *> argv = {
        jove_add_path.c_str(),
        "-o", jvfp.c_str(),
        "-i", path.c_str(),
        nullptr
      };

      print_command(&argv[0]);

      std::string stdoutfp = tmpdir + path + ".txt";
      int outfd = open(stdoutfp.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0666);
      dup2(outfd, STDOUT_FILENO);
      //dup2(outfd, STDERR_FILENO);

      close(STDIN_FILENO);
      execve(argv[0], const_cast<char **>(&argv[0]), ::environ);

      int err = errno;
      WithColor::error() << llvm::formatv("execve of {0} failed: {1}\n",
                                          argv[0],
                                          strerror(err));
      exit(1);
    }

    if (int ret = await_process_completion(pid))
      WithColor::error() << llvm::formatv("jove-add -o {0} -i {1}\n", jvfp,
                                          path);
  }
}

void spawn_workers(void) {
  std::vector<std::thread> workers;

  unsigned N = opts::Threads;

  workers.reserve(N);
  for (unsigned i = 0; i < N; ++i)
    workers.push_back(std::thread(worker));

  for (std::thread &t : workers)
    t.join();
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

unsigned num_cpus(void) {
  cpu_set_t cpu_mask;
  if (sched_getaffinity(0, sizeof(cpu_mask), &cpu_mask) < 0) {
    WithColor::error() << "sched_getaffinity failed : " << strerror(errno)
                       << '\n';
    abort();
  }

  return CPU_COUNT(&cpu_mask);
}

void print_command(const char **argv) {
  std::string msg;

  for (const char **s = argv; *s; ++s) {
    msg.append(*s);
    msg.push_back(' ');
  }

  if (msg.empty())
    return;

  msg[msg.size() - 1] = '\n';

  llvm::outs() << msg;
}

} // namespace jove

void __warn(const char *file, int line) {
  WithColor::warning() << llvm::formatv("{0}:{1}\n", file, line);
}
