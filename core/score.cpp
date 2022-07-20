#include "score.h"
#include "elf.h"
#include <boost/format.hpp>

namespace obj = llvm::object;

namespace jove {

typedef boost::format fmt;

double compute_score(const decompilation_t &decompilation,
                     const binary_t &binary) {
  llvm::StringRef Buffer(reinterpret_cast<const char *>(&binary.Data[0]),
                         binary.Data.size());
  llvm::StringRef Identifier(binary.Path);

  llvm::Expected<std::unique_ptr<obj::Binary>> BinOrErr =
      obj::createBinary(llvm::MemoryBufferRef(Buffer, Identifier));
  if (!BinOrErr)
    throw std::runtime_error("failed to create binary from " + binary.Path);

  std::unique_ptr<obj::Binary> &BinRef = BinOrErr.get();

  if (!llvm::isa<ELFO>(BinRef.get()))
    throw std::runtime_error(binary.Path + " is not ELF of expected type\n");

  assert(llvm::isa<ELFO>(BinRef.get()));
  const ELFO &O = *llvm::cast<ELFO>(BinRef.get());
  const ELFF &E = *O.getELFFile();

  llvm::SmallVector<const Elf_Phdr *, 4> LoadSegments;

  auto ProgramHeadersOrError = E.program_headers();
  if (!ProgramHeadersOrError)
    throw std::runtime_error("failed to to get program headers from " + binary.Path);

  for (const Elf_Phdr &Phdr : *ProgramHeadersOrError)
    if (Phdr.p_type == llvm::ELF::PT_LOAD)
      LoadSegments.push_back(const_cast<Elf_Phdr *>(&Phdr));

  //
  // count the total number of executable bytes (N)
  //
  size_t N =
      std::accumulate(LoadSegments.begin(),
                      LoadSegments.end(), 0,
                      [&](size_t res, const Elf_Phdr *LoadSeg) -> size_t {
                        const Elf_Phdr &Phdr = *LoadSeg;

                        return res + (Phdr.p_flags & llvm::ELF::PF_X
                                          ? Phdr.p_filesz
                                          : 0);
                      });
  assert(N > 0);

  //
  // add up all the basic block lengths (M)
  //
  const icfg_t &ICFG = binary.Analysis.ICFG;
  icfg_t::vertex_iterator vi_begin, vi_end;
  std::tie(vi_begin, vi_end) = boost::vertices(ICFG);

  size_t M =
      std::accumulate(vi_begin,
                      vi_end, 0,
                      [&](size_t res, basic_block_t bb) -> size_t {
                        return res + ICFG[bb].Size;
                      });
  assert(M > 0);

  //
  // compute the ratio (M / N)
  //
  return static_cast<double>(M) / static_cast<double>(N);
}
}
