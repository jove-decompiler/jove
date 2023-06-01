#pragma once
#include <functional>
#include <string>

#include <sys/wait.h>

namespace jove {

typedef std::function<void(std::function<void(const std::string &)>)> compute_args_t;
typedef std::function<void(std::function<void(const std::string &)>)> compute_envs_t;
typedef std::function<void(const char **, const char **)> before_exec_t;

pid_t RunExecutable(const std::string &exe_path,
    compute_args_t,
    compute_envs_t,
    const std::string &stdout_path = std::string(),
    const std::string &stderr_path = std::string(),
    before_exec_t before_exec = [](const char **, const char **) {});

int WaitForProcessToExit(pid_t);

template <typename... Args>
static inline int RunExecutableToExit(Args &&...args) {
  pid_t pid = RunExecutable(std::forward<Args>(args)...);
  return WaitForProcessToExit(pid);
}

void InitWithEnviron(std::function<void(const std::string &)> Env);

inline pid_t RunExecutable(const std::string &exe_path,
                           compute_args_t compute_args,
                           const std::string &stdout_path,
                           const std::string &stderr_path,
                           before_exec_t before_exec) {
  return RunExecutable(
      exe_path,
      compute_args,
      [&](auto Env) { InitWithEnviron(Env); },
      stdout_path,
      stderr_path,
      before_exec);
}

}
