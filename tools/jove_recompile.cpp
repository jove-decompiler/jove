#include "config-target.h"
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <cstdint>
#include <iostream>
#include <llvm/ADT/Triple.h>
#include <llvm/Bitcode/ReaderWriter.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Object/Binary.h>
#include <llvm/Object/ELF.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/Linker/Linker.h>
#include <llvm/Transforms/Utils/Cloning.h>

using namespace std;
using namespace llvm;
using namespace object;
namespace po = boost::program_options;
namespace fs = boost::filesystem;

namespace jove {

static tuple<fs::path, fs::path, bool>
parse_command_line_arguments(int argc, char **argv);

static void print_obj_info(const ObjectFile *);
static void needed_shared_libraries_of_binary(const ObjectFile *,
                                              vector<fs::path> &);
}

static const uint8_t helpers_bitcode_data[] = {
#include "helpers.cpp"
};

static const uint8_t thunk_bitcode_data[] = {
#include "thunk.cpp"
};

using namespace jove;

int main(int argc, char **argv) {
  fs::path ifp, ofp;
  bool noopt;

  tie(ifp, ofp, noopt) = parse_command_line_arguments(argc, argv);

  //
  // parse binary
  //
  fs::path bin_fp = *fs::directory_iterator(ifp / "binary");
  ErrorOr<OwningBinary<Binary>> BinaryOrErr = createBinary(bin_fp.string());
  if (error_code EC = BinaryOrErr.getError()) {
    cerr << "error loading binary: " << EC.message() << endl;
    return 1;
  }

  ObjectFile *O = dyn_cast<ObjectFile>(BinaryOrErr.get().getBinary());
  if (!O) {
    cerr << "error: provided file is not object" << endl;
    return 1;
  }

  print_obj_info(O);

  llvm::LLVMContext C;

  unique_ptr<Module> M;
  {
    ErrorOr<unique_ptr<MemoryBuffer>> MBOrEror(
        MemoryBuffer::getFile((ifp / "bitcode" / "decompilation").string()));

    if (std::error_code EC = MBOrEror.getError()) {
      cerr << "failed to read bitcode file " << EC.message() << endl;
      return 1;
    }
    M = move(*parseBitcodeFile(MBOrEror.get()->getMemBufferRef(), C));
  }

  vector<string> fns;
  for (Function& F : *M)
    if (F.getLinkage() == GlobalValue::ExternalLinkage && !F.isDeclaration())
      fns.push_back(F.getName().str());

  unique_ptr<Module> HelperM;
  {
    unique_ptr<MemoryBuffer> MB(MemoryBuffer::getMemBuffer(
        StringRef(reinterpret_cast<const char *>(&helpers_bitcode_data[0]),
                  sizeof(helpers_bitcode_data)),
        "", false));

    HelperM = move(*parseBitcodeFile(MB->getMemBufferRef(), C));
  }

  unique_ptr<Module> ThunkM;
  {
    unique_ptr<MemoryBuffer> MB(MemoryBuffer::getMemBuffer(
        StringRef(reinterpret_cast<const char *>(&thunk_bitcode_data[0]),
                  sizeof(thunk_bitcode_data)),
        "", false));

    ThunkM = move(*parseBitcodeFile(MB->getMemBufferRef(), C));
  }

  Linker lnk(*M);

  if (lnk.linkInModule(move(HelperM), Linker::LinkOnlyNeeded)) {
    cerr << "error linking bitcode" << endl;
    return 1;
  }

  if (lnk.linkInModule(move(ThunkM))) {
    cerr << "error linking bitcode" << endl;
    return 1;
  }

  Function &exported_template_fn =
      *M->getFunction("__jove_exported_template_fn");
  Function &exported_template_fn_impl =
      *M->getFunction("__jove_exported_template_fn_impl");

  for (const string& sym : fns) {
    Function& F = *M->getFunction(sym);

    ValueToValueMapTy VMap;
    Function& G = *CloneFunction(&exported_template_fn, VMap, false);
    M->getFunctionList().push_back(&G);

    G.takeName(&F);
    F.setName("__jove_impl_" + sym);
    F.setLinkage(GlobalValue::InternalLinkage);
    F.setCallingConv(CallingConv::C);

    auto user_of_impl = [&](void) -> Instruction * {
      for (User *U : exported_template_fn_impl.users()) {
        Instruction* Inst = dyn_cast<Instruction>(U);
        if (!Inst)
          continue;

        if (Inst->getParent()->getParent() == &G)
          return Inst;
      }

      return nullptr;
    };

    Instruction* Inst = user_of_impl();
    assert(Inst);

    auto operand_index_of_impl_user = [&](void) -> unsigned {
      for (unsigned i = 0; i < Inst->getNumOperands(); ++i) {
        if (Inst->getOperand(i) == &exported_template_fn_impl)
          return i;
      }

      return numeric_limits<unsigned>::max();
    };

    unsigned opidx = operand_index_of_impl_user();
    assert(opidx < Inst->getNumOperands());

    Inst->setOperand(opidx, &F);
  }

  assert(exported_template_fn.getNumUses() == 0);
  M->getFunctionList().remove(&exported_template_fn);
#if 0
  assert(exported_template_fn_impl.getNumUses() == 0);
  M->getFunctionList().remove(&exported_template_fn_impl);
#endif

  Function &JFn0 =
      *M->getFunction("__jove_thunk_out");
  Function &JFn1 =
      *M->getFunction("__jove_indirect_jump");
  Function &JFn2 =
      *M->getFunction("__jove_indirect_call");
  Function &JFn3 =
      *M->getFunction("__jove_call");

  JFn1.replaceAllUsesWith(&JFn0);
  JFn2.replaceAllUsesWith(&JFn0);
  JFn3.replaceAllUsesWith(&JFn0);

  JFn0.setLinkage(GlobalValue::InternalLinkage);

  M->dump();

  vector<fs::path> libs;
  needed_shared_libraries_of_binary(O, libs);

  for (fs::path lib : libs)
    cout << lib << endl;

  return 0;
}

namespace jove {

tuple<fs::path, fs::path, bool> parse_command_line_arguments(int argc,
                                                             char **argv) {
  fs::path ifp, ofp;
  bool noopt = false;

  try {
    po::options_description desc("Allowed options");
    desc.add_options()
      ("help,h", "produce help message")

      ("input,i", po::value<fs::path>(&ifp), "input binary")

      ("output,o", po::value<fs::path>(&ofp), "output bitcode file path")

      ("noopt,s", po::value<bool>(&noopt), "produce unoptimized LLVM");

    po::positional_options_description p;
    p.add("input", -1);

    po::variables_map vm;
    po::store(
        po::command_line_parser(argc, argv).options(desc).positional(p).run(),
        vm);
    po::notify(vm);

    if (vm.count("help") || !vm.count("input")) {
      cout << "Usage: jove-init-<arch> [-o output] binary\n";
      cout << desc;
      exit(1);
    }

    if (!fs::is_directory(ifp) &&
        !fs::is_directory(ifp.replace_extension("jv"))) {
      cerr << "given input " << ifp << " is not jove decompilation " << endl;
      exit(1);
    }
  } catch (exception &e) {
    cerr << e.what() << endl;
    abort();
  }

  return make_tuple(ifp, ofp, noopt);
}

void print_obj_info(const ObjectFile *Obj) {
  cout << "File: " << Obj->getFileName().str() << "\n";
  cout << "Format: " << Obj->getFileFormatName().str() << "\n";
  cout << "Arch: " << Triple::getArchTypeName((Triple::ArchType)Obj->getArch())
       << "\n";
  cout << "AddressSize: " << (8 * Obj->getBytesInAddress()) << "bit\n";
}

static void needed_shared_libraries_of_elf_binary(const ObjectFile *,
                                                  vector<fs::path> &);
static void needed_shared_libraries_of_coff_binary(const ObjectFile *,
                                                   vector<fs::path> &);

void needed_shared_libraries_of_binary(const ObjectFile *O,
                                       vector<fs::path> &libs) {
  if (O->isELF())
    return needed_shared_libraries_of_elf_binary(O, libs);
  else if (O->isCOFF())
    return needed_shared_libraries_of_coff_binary(O, libs);
}

template <class T> static T errorOrDefault(ErrorOr<T> Val, T Default = T()) {
  return Val ? *Val : Default;
}

template <class ELFT>
static bool compareAddr(uint64_t VAddr, const Elf_Phdr_Impl<ELFT> *Phdr) {
  return VAddr < Phdr->p_vaddr;
}

template <typename ELFT>
static void needed_shared_libraries_of_elf(const ELFFile<ELFT> *ELF,
                                           vector<fs::path> &libs) {
  typedef typename ELFFile<ELFT>::Elf_Shdr Elf_Shdr;
  typedef typename ELFFile<ELFT>::Elf_Sym Elf_Sym;
  typedef typename ELFFile<ELFT>::Elf_Rel Elf_Rel;
  typedef typename ELFFile<ELFT>::Elf_Rela Elf_Rela;
  typedef typename ELFFile<ELFT>::Elf_Phdr Elf_Phdr;
  typedef typename ELFFile<ELFT>::Elf_Dyn_Range Elf_Dyn_Range;

  const Elf_Phdr *DynamicProgHeader = nullptr;
  SmallVector<const Elf_Phdr *, 4> LoadSegments;

  for (const Elf_Phdr &Phdr : ELF->program_headers()) {
    switch (Phdr.p_type) {
    case ELF::PT_DYNAMIC:
      DynamicProgHeader = &Phdr;
      break;
    case ELF::PT_LOAD:
     if (Phdr.p_filesz == 0)
       break;
      LoadSegments.push_back(&Phdr);
      break;
    }
  }

  ErrorOr<Elf_Dyn_Range> dyntbl_ = ELF->dynamic_table(DynamicProgHeader);
  if (dyntbl_.getError())
    return;

  Elf_Dyn_Range dyntbl = *dyntbl_;

  const char *StringTableBegin = nullptr;
  uint64_t StringTableSize = 0;

  auto toMappedAddr = [&](uint64_t VAddr) -> const uint8_t * {
    const Elf_Phdr **I = upper_bound(LoadSegments.begin(), LoadSegments.end(),
                                     VAddr, compareAddr<ELFT>);
    if (I == LoadSegments.begin())
      return nullptr;
    --I;
    const Elf_Phdr &Phdr = **I;
    uint64_t Delta = VAddr - Phdr.p_vaddr;
    if (Delta >= Phdr.p_filesz)
      return nullptr;
    return ELF->base() + Phdr.p_offset + Delta;
  };

  for (const auto &Entry : dyntbl) {
    switch (Entry.d_tag) {
    case ELF::DT_STRTAB:
      StringTableBegin = StringTableBegin
                             ? StringTableBegin
                             : (const char *)toMappedAddr(Entry.getPtr());
      break;
    case ELF::DT_STRSZ:
      StringTableSize = Entry.getVal();
      break;
    }
  }


  if (!StringTableBegin)
    return;

  StringRef DynamicStringTable = StringRef(StringTableBegin, StringTableSize);

  for (const auto &Entry : dyntbl) {
    if (Entry.d_tag != ELF::DT_NEEDED)
      continue;

    if (Entry.d_un.d_val >= DynamicStringTable.size())
      continue;

    libs.push_back(
        StringRef(DynamicStringTable.data() + Entry.d_un.d_val).str());
  }
}

void needed_shared_libraries_of_elf_binary(const ObjectFile *O,
                                           vector<fs::path> &libs) {
  if (const ELF32LEObjectFile *ELFObj = dyn_cast<ELF32LEObjectFile>(O))
    needed_shared_libraries_of_elf(ELFObj->getELFFile(), libs);
  else if (const ELF32BEObjectFile *ELFObj = dyn_cast<ELF32BEObjectFile>(O))
    needed_shared_libraries_of_elf(ELFObj->getELFFile(), libs);
  else if (const ELF64LEObjectFile *ELFObj = dyn_cast<ELF64LEObjectFile>(O))
    needed_shared_libraries_of_elf(ELFObj->getELFFile(), libs);
  else if (const ELF64BEObjectFile *ELFObj = dyn_cast<ELF64BEObjectFile>(O))
    needed_shared_libraries_of_elf(ELFObj->getELFFile(), libs);
}

void needed_shared_libraries_of_coff_binary(const ObjectFile *,
                                                   vector<fs::path> &) {
}

}
