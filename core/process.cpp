#include "process.h"

#include <cassert>
#include <cstring>
#include <list>
#include <stdexcept>
#include <string>

#include <unistd.h>
#include <fcntl.h>

using namespace std;

namespace jove {

pid_t RunExecutable(const std::string &exe_path,
                    compute_args_t compute_args,
                    compute_envs_t compute_envs,
                    const string &stdout_path,
                    const string &stderr_path,
                    before_exec_t before_exec) {
  pid_t pid = ::fork();
  if (pid)
    return pid;

  list<string> arg_str_list;
  list<string> env_str_list;

  compute_args([&](const string &s) { arg_str_list.emplace_back(move(s)); });
  compute_envs([&](const string &s) { env_str_list.emplace_back(move(s)); });

  vector<const char *> arg_vec;
  vector<const char *> env_vec;

  arg_vec.reserve(arg_str_list.size() + 1);
  env_vec.reserve(env_str_list.size() + 1);

  for (const string &s : arg_str_list) arg_vec.push_back(s.c_str());
  for (const string &s : env_str_list) env_vec.push_back(s.c_str());

  arg_vec.push_back(nullptr);
  env_vec.push_back(nullptr);

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
  throw runtime_error(string("execve of ") + exe_path + " failed: " + strerror(err));
}

int WaitForProcessToExit(pid_t pid) {
  for (;;) {
    int wstatus = 0;
    if (::waitpid(pid, &wstatus, WUNTRACED | WCONTINUED) == -1) {
      int err = errno;

      if (err == EINTR)
        continue;

      if (err == ECHILD)
        return 0;

      throw runtime_error(string("WaitForProcessToExit: waitpid failed: ") +
                          strerror(err));
    }

    if (WIFEXITED(wstatus)) {
      return WEXITSTATUS(wstatus);
    } else if (WIFSIGNALED(wstatus)) {
      return 1;
    } else {
      assert(WIFSTOPPED(wstatus) || WIFCONTINUED(wstatus));
    }
  }

  abort();
}

void InitWithEnviron(std::function<void(const std::string &)> Env) {
  for (char **env = ::environ; *env; ++env)
    Env(*env);
}

}
