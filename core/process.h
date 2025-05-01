#pragma once
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

typedef std::function<void(const char **, const char **)> before_exec_t;

template <typename ComputeArgs, typename ComputeEnvs>
pid_t RunExecutable(const std::string &exe_path,
    ComputeArgs compute_args,
    ComputeEnvs compute_envs,
    const std::string &stdout_path = std::string(),
    const std::string &stderr_path = std::string(),
    before_exec_t before_exec = [](const char **, const char **) {}) {
  boost::unordered_flat_set<std::string_view> envs;

  boost::container::slist<std::string> arg_str_list;
  boost::container::slist<std::string> env_str_list;

  std::vector<const char *> arg_vec;
  std::vector<const char *> env_vec;

  compute_args([&](auto&&... xs) -> void {
    arg_str_list.emplace_front(std::forward<decltype(xs)>(xs)...);

    std::string &x = arg_str_list.front();
    arg_vec.push_back(x.c_str());
  });
  compute_envs([&](auto&&... xs) -> void {
    env_str_list.emplace_front(std::forward<decltype(xs)>(xs)...);

    if (envs.contains(env_str_list.front())) {
      env_str_list.pop_front();
      return;
    }

    std::string &x = env_str_list.front();
    envs.insert(x);
    env_vec.push_back(x.c_str());
  });

  arg_vec.push_back(nullptr);
  env_vec.push_back(nullptr);

  pid_t pid = ::fork();
  if (pid)
    return pid;

  //
  // we do this before messing with standard output streams
  //
  before_exec(&arg_vec[0], &env_vec[0]);

  if (!stdout_path.empty()) {
    //
    // redirect stdout
    //
    int fd = ::open(stdout_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0666);
    ::dup2(fd, STDOUT_FILENO);
    ::close(fd);
  }

  if (!stderr_path.empty()) {
    //
    // redirect stderr
    //
    int fd = ::open(stderr_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0666);
    ::dup2(fd, STDERR_FILENO);
    ::close(fd);
  }

  errno = 0;

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
inline pid_t RunExecutable(const std::string &exe_path,
                           ComputeArgs compute_args,
                           const std::string &stdout_path,
                           const std::string &stderr_path,
                           before_exec_t before_exec = [](const char **, const char **) {}) {
  return RunExecutable(
      exe_path,
      compute_args,
      [&](auto Env) { InitWithEnviron(Env); },
      stdout_path,
      stderr_path,
      before_exec);
}

}
