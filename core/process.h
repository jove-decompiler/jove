#pragma once
#include "fd.h"
#include "eintr.h"

#include <functional>
#include <string>
#include <stdexcept>

#include <boost/unordered/unordered_flat_set.hpp>
#include <boost/container/slist.hpp>

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
// User-friendly function to fork and exec (i.e. spawning a process from an
// executable).
//
template <typename ComputeArgs, typename ComputeEnvs>
pid_t RunExecutable(const std::string &exe_path,
    ComputeArgs compute_args,
    ComputeEnvs compute_envs,
    const std::string &stdout_path = std::string(),
    const std::string &stderr_path = std::string(),
    before_exec_t before_exec = [](const char **, const char **) {}) {
  boost::unordered_flat_set<std::string_view> envs;

  boost::container::slist<std::string> sl;

  std::vector<const char *> arg_vec;
  std::vector<const char *> env_vec;

  compute_args([&](auto &&...xs) -> void {
    sl.emplace_front(std::forward<decltype(xs)>(xs)...);

    std::string &x = sl.front();
    arg_vec.push_back(x.c_str());
  });
  compute_envs([&](auto &&...xs) -> void {
    sl.emplace_front(std::forward<decltype(xs)>(xs)...);

    if (envs.contains(sl.front())) {
      sl.pop_front();
      return;
    }

    std::string &x = sl.front();
    envs.insert(x);
    env_vec.push_back(x.c_str());
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
  if (!stdout_path.empty()) {
    scoped_fd fd(sys::retry_eintr(::open, stdout_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0666));
    if (fd)
      sys::retry_eintr(::dup2, fd.get(), STDOUT_FILENO);
  }

  if (!stdout_path.empty()) {
    scoped_fd fd(sys::retry_eintr(::open, stderr_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0666));
    if (fd)
      sys::retry_eintr(::dup2, fd.get(), STDERR_FILENO);
  }

  errno = 0; /* reset */

  ::execve(exe_path.c_str(),
           const_cast<char **>(&arg_vec[0]),
           const_cast<char **>(&env_vec[0]));

  int err = errno;
  throw std::runtime_error(std::string("execve of ") + exe_path + " failed: " + strerror(err));
}

int WaitForProcessToExit(pid_t);

template <typename... Args>
static inline int RunExecutableToExit(Args &&...args) {
  pid_t pid = RunExecutable(std::forward<Args>(args)...);
  return WaitForProcessToExit(pid);
}

void InitWithEnviron(std::function<void(const char *)> Env);

template <typename ComputeArgs>
static inline pid_t RunExecutable(
    const std::string &exe_path, ComputeArgs compute_args,
    const std::string &stdout_path = std::string(),
    const std::string &stderr_path = std::string(),
    before_exec_t before_exec = [](const char **, const char **) {}) {
  return RunExecutable(exe_path, compute_args, InitWithEnviron, stdout_path,
                       stderr_path, before_exec);
}
}
