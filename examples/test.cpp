#include <dlfcn.h>
#include <string>
#include <unistd.h>
#include <limits.h>
#include <cassert>
#include <iostream>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>

using namespace std;

boost::filesystem::path program_dir() {
  char buff[PATH_MAX];

  ssize_t len = ::readlink("/proc/self/exe", buff, sizeof(buff) - 1);
  assert(len >= 0);

  buff[len] = '\0';

  boost::filesystem::path p(buff);
  return p.parent_path();
}

typedef void (*libmc2llvm_init_ty)(const char *binfp);
typedef void (*libmc2llvm_test_ty)(void);

int main(int argc, char **argv) {
  if (argc != 3)
    cout << "usage: test architecture binary" << endl;

  void *handle;
  libmc2llvm_init_ty libmc2llvm_init;
  boost::filesystem::path p(program_dir());

  handle = dlopen(
      (p / (boost::format("lib%s2llvm.so") % argv[1]).str()).string().c_str(),
      RTLD_LAZY);
  if (!handle) {
    cerr << dlerror() << endl;
    return 1;
  }
  libmc2llvm_init = (libmc2llvm_init_ty)dlsym(handle, "libmc2llvm_init");
  assert(libmc2llvm_init);
  libmc2llvm_test_ty libmc2llvm_test =
      (libmc2llvm_test_ty)dlsym(handle, "libmc2llvm_test");
  assert(libmc2llvm_test);

  libmc2llvm_init(argv[2]);
  libmc2llvm_test();

  return 0;
}
