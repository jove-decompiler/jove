#include <dlfcn.h>
#include <string>
#include <unistd.h>
#include <limits.h>
#include <cassert>
#include <iostream>
#include <sstream>
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

typedef void (*libmc2llvm_init_ty)(const char* binfp);
typedef void (*libmc2llvm_translate_ty)(uint64_t pc);

int main(int argc, char **argv) {
  if (argc != 4)
    cout << "usage: trans-block architecture binary address" << endl;

  uint64_t pc;
  stringstream ss;
  ss << hex << argv[3];
  ss >> pc;

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
  libmc2llvm_translate_ty libmc2llvm_translate =
      (libmc2llvm_translate_ty)dlsym(handle, "libmc2llvm_translate");
  assert(libmc2llvm_translate);

  cout << "libmc2llvm_init" << endl;
  libmc2llvm_init(argv[2]);
  libmc2llvm_translate(pc);

  return 0;
}
