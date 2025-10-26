#pragma once
#include "fd.h"
#include "eintr.h"
#include "pidfd.h"

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <boost/interprocess/anonymous_shared_memory.hpp>
#include <boost/unordered/unordered_flat_set.hpp>
#include <boost/container/slist.hpp>
#include <boost/scope/defer.hpp>

#include <fcntl.h>
#include <unistd.h>
#include <linux/prctl.h>  /* Definition of PR_* constants */
#include <sys/prctl.h>
#include <sys/wait.h>
#include <poll.h>

namespace jove {

namespace process {
static inline void no_args(std::function<void(const char *)> Arg) {
  Arg(""); /* prevent "NULL argv" complaints in dmesg */
}
static inline void no_envs(std::function<void(const char *)>) {}
}

//
// This function is called *right before* the call to execve(2). Aim to avoid
// doing anything that might cause a deadlock, since this function is called
// in the child of the fork().
//
typedef std::function<void(const char **, const char **)> before_exec_t;

//
// Bells and whistles
//
enum class ExecOpt : uint32_t {
  None                = 0,
  DedupEnvByKey       = 1u << 0, // keep the first NAME=... by NAME (LHS of '=')
  DedupEnvExact       = 1u << 1, // keep the first exact "NAME=VALUE" string
  InheritParentEnv    = 1u << 2, // inherit environment
  MergeStderrToStdout = 1u << 3, // make STDERR point to STDOUT
  AppendRedirects     = 1u << 4, // O_APPEND instead of O_TRUNC when redirecting
  CloseStdin          = 1u << 5, // connect stdin to /dev/null
  // Slurp
};

constexpr std::underlying_type_t<ExecOpt>
to_underlying(ExecOpt e) noexcept {
  return static_cast<std::underlying_type_t<ExecOpt>>(e);
}

constexpr ExecOpt operator|(ExecOpt a, ExecOpt b) noexcept {
  return static_cast<ExecOpt>(to_underlying(a) | to_underlying(b));
}
constexpr ExecOpt operator&(ExecOpt a, ExecOpt b) noexcept {
  return static_cast<ExecOpt>(to_underlying(a) & to_underlying(b));
}
constexpr ExecOpt &operator|=(ExecOpt &a, ExecOpt b) noexcept { return a = a | b; }

template <ExecOpt Set, ExecOpt Flag>
inline constexpr bool has_flag_v =
    (to_underlying(Set) & to_underlying(Flag)) != 0;

[[nodiscard]] int WaitForProcessToExit(pid_t);

//
// Running an executable (the big function)
//
template <ExecOpt Opts = ExecOpt::DedupEnvByKey,
          typename ComputeArgs,
          typename ComputeEnvs>
[[nodiscard]] pid_t RunExecutable(
    const std::string &exe_path,
    ComputeArgs compute_args,
    ComputeEnvs compute_envs,
    const std::string &stdout_path = std::string(),
    const std::string &stderr_path = std::string(),
    before_exec_t before_exec = [](const char **, const char **) {}) {
  boost::container::slist<std::string> sl;

  std::vector<const char *> arg_vec;
  std::vector<const char *> env_vec;

  struct {
    std::conditional_t<has_flag_v<Opts, ExecOpt::DedupEnvExact>,
                       boost::unordered_flat_set<std::string_view>,
                       std::monostate>
        envs;
  } _dedup_env_exact;

  struct {
    std::conditional_t<has_flag_v<Opts, ExecOpt::DedupEnvByKey>,
                       boost::container::slist<std::string>,
                       std::monostate>
        keyl;
    std::conditional_t<has_flag_v<Opts, ExecOpt::DedupEnvByKey>,
                       boost::unordered_flat_set<std::string_view>,
                       std::monostate>
        keys;
  } _dedup_env_by_key;

  //
  // argv
  //
  compute_args([&](auto &&...xs) -> void {
    sl.emplace_front(std::forward<decltype(xs)>(xs)...);

    arg_vec.push_back(sl.front().c_str());
  });

  //
  // envp
  //
  if constexpr (has_flag_v<Opts, ExecOpt::InheritParentEnv>) {
    for (char **envp = environ; envp && *envp; ++envp) {
      char *const env = *envp;

      env_vec.push_back(env);

      if constexpr (has_flag_v<Opts, ExecOpt::DedupEnvExact>) {
        _dedup_env_exact.envs.insert(env);
      } else if constexpr (has_flag_v<Opts, ExecOpt::DedupEnvByKey>) {
        if (char *eqp = strchr(env, '=')) {
          auto &keyl = _dedup_env_by_key.keyl;
          auto &keys = _dedup_env_by_key.keys;

          {
            *eqp = '\0';
            BOOST_SCOPE_DEFER[&] { *eqp = '='; /* restore */ };

            keyl.emplace_front(eqp);
          }
          keys.insert(keyl.front());
        }
      }
    }
  }

  compute_envs([&](auto &&...xs) -> void {
    sl.emplace_front(std::forward<decltype(xs)>(xs)...);

    auto undo = [&](void) -> void { sl.pop_front(); };

    if constexpr (has_flag_v<Opts, ExecOpt::DedupEnvExact>) {
      auto &envs = _dedup_env_exact.envs;

      if (envs.contains(sl.front())) {
        undo();
        return;
      }

      envs.insert(sl.front());
    } else if constexpr (has_flag_v<Opts, ExecOpt::DedupEnvByKey>) {
      auto eq = sl.front().find('=');
      if (eq != std::string::npos) {
        auto &keyl = _dedup_env_by_key.keyl;
        auto &keys = _dedup_env_by_key.keys;

        {
          std::string key = sl.front().substr(0, eq);
          keyl.emplace_front(std::move(key));
        }

        if (keys.contains(keyl.front())) {
          keyl.pop_front();

          undo();
          return;
        }

        keys.insert(keyl.front());
      }
    }

    env_vec.push_back(sl.front().c_str());
  });

  arg_vec.push_back(nullptr);
  env_vec.push_back(nullptr);

  //
  // this is the way by which we inform the parent if the exec() failed.
  //
  boost::interprocess::mapped_region shared_mem(
      boost::interprocess::anonymous_shared_memory(sizeof(int)));
  int &shared_err = *static_cast<int *>(shared_mem.get_address());
  __atomic_store_n(&shared_err, 0, __ATOMIC_RELAXED);

  //
  // this is so we don't make progress in the parent until the child has exec'd
  //
  int pipefd[2] = {-1, -1};
  (void)::pipe(pipefd);

  scoped_fd rfd(pipefd[0]);
  scoped_fd wfd(pipefd[1]);

  const bool pipe_trick = rfd && wfd;

  //
  // there are issues with tbb concerning the use of fork(2), but since we are
  // calling execve(2) straight away there should be no chance of deadlocking.
  //
  scoped_fd our_pfd(pidfd_open(::getpid(), 0));
  const pid_t pid = ::fork();
  if (pid) {
    if (pipe_trick) {
      wfd.close(); /* unused in parent. */

      //
      // block until exec has happened
      //
      uint8_t byte;
      (void)sys::retry_eintr(::read, rfd.get(), &byte, 1);

      //
      // now we can check for bad errno
      //
      if (int err = __atomic_load_n(&shared_err, __ATOMIC_RELAXED)) {
        //
        // execve(2) failed. errno is in shared_err.
        //
        ignore_exception([&] {
          WaitForProcessToExit(pid); /* child will promptly exit. */
        });

        throw std::runtime_error("execve() failed: " + std::string(strerror(err)));
      }
    }

    return pid;
  }

  (void)::prctl(PR_SET_PDEATHSIG, SIGTERM);
  if (our_pfd) {
    const int poll_ret = ({
      struct pollfd pfd = {.fd = our_pfd.get(), .events = POLLIN};
      sys::retry_eintr(::poll, &pfd, 1, 0);
    });
    aassert(poll_ret >= 0);
    our_pfd.close();
    if (poll_ret != 0) {
      //
      // parent is already gone. this generally shouldn't happen, but if we do
      // happen to get here, just silently exit.
      //
      for (;;)
        _exit(0);
      __builtin_unreachable();
    }
  }

  before_exec(&arg_vec[0], &env_vec[0]);

  //
  // redirect standard output and/or standard error, if desired.
  //
  int AppendOrTrunc =
      has_flag_v<Opts, ExecOpt::AppendRedirects> ? O_APPEND : O_TRUNC;

  if (!stdout_path.empty()) {
    scoped_fd fd(sys::retry_eintr(::open, stdout_path.c_str(),
                                  O_CREAT | AppendOrTrunc | O_WRONLY, 0666));
    if (fd) {
      sys::retry_eintr(::dup2, fd.get(), STDOUT_FILENO);

      if constexpr (has_flag_v<Opts, ExecOpt::MergeStderrToStdout>)
        sys::retry_eintr(::dup2, fd.get(), STDERR_FILENO);
    }
  }

  if constexpr (!has_flag_v<Opts, ExecOpt::MergeStderrToStdout>) {
    if (!stderr_path.empty()) {
      scoped_fd fd(sys::retry_eintr(::open, stderr_path.c_str(),
                                    O_CREAT | AppendOrTrunc | O_WRONLY, 0666));
      if (fd)
        sys::retry_eintr(::dup2, fd.get(), STDERR_FILENO);
    }
  }

  if constexpr (has_flag_v<Opts, ExecOpt::CloseStdin>) {
    scoped_fd fd(sys::retry_eintr(::open, "/dev/null", O_RDONLY, 0));
    if (fd)
      sys::retry_eintr(::dup2, fd.get(), STDIN_FILENO);
  }

  if (pipe_trick) {
    rfd.close(); /* unused in child. */

    //
    // this little trick will allow us to block only until the exec has happened
    //
    (void)sys::retry_eintr(::fcntl, wfd.get(), F_SETFD, FD_CLOEXEC);
  }

  errno = 0; /* reset */

  ::execve(exe_path.c_str(),
           const_cast<char **>(&arg_vec[0]),
           const_cast<char **>(&env_vec[0]));

  //
  // if we got here, execve failed.
  //
  const int err = errno;
  aassert(err != 0);

  if (pipe_trick) {
    //
    // communicate error to parent
    //
    __atomic_store_n(&shared_err, err, __ATOMIC_RELAXED);

    wfd.close(); /* allow parent to make progress */
  }

  for (;;)
    _exit(err);

  __builtin_unreachable();
}

template <ExecOpt Opts = ExecOpt::None, typename... Args>
[[nodiscard]] static inline int RunExecutableToExit(Args &&...args) {
  pid_t pid = RunExecutable(std::forward<Args>(args)...);
  return WaitForProcessToExit(pid);
}

void InitWithEnviron(std::function<void(const char *)> Env);

// convenient for when environ should simply be inherited
template <ExecOpt Opts = ExecOpt::DedupEnvExact, typename ComputeArgs>
[[nodiscard]] static inline pid_t RunExecutable(
    const std::string &exe_path,
    ComputeArgs compute_args,
    const std::string &stdout_path = std::string(),
    const std::string &stderr_path = std::string(),
    before_exec_t before_exec = [](const char **, const char **) {}) {
  return RunExecutable<Opts>(exe_path, compute_args, InitWithEnviron,
                             stdout_path, stderr_path, before_exec);
}

}
