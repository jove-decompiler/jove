#pragma once
#include "fd.h"
#include "eintr.h"

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

#include <boost/unordered/unordered_flat_set.hpp>
#include <boost/container/slist.hpp>
#include <boost/scope/defer.hpp>

#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

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

//
// Running an executable (the big function)
//
template <ExecOpt Opts = ExecOpt::None,
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
  // there are issues with tbb concerning the use of fork(2), but since we are
  // calling execve(2) straight away there should be no chance of deadlocking.
  //
  pid_t pid = ::fork();
  if (pid)
    return pid;

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

  errno = 0; /* reset */

  ::execve(exe_path.c_str(),
           const_cast<char **>(&arg_vec[0]),
           const_cast<char **>(&env_vec[0]));

  int err = errno;
  throw std::runtime_error(std::string("execve of ") + exe_path + " failed: " + strerror(err));
}

[[nodiscard]] int WaitForProcessToExit(pid_t);

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
