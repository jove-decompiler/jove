#include "score.h"
#include "B.h"
#include <boost/format.hpp>

namespace obj = llvm::object;

namespace jove {

typedef boost::format fmt;

double compute_score(const jv_t &jv,
                     const binary_t &binary) {
  auto Bin = B::Create(llvm::StringRef(binary.data()));

  //
  // count the total number of executable bytes (N)
  //
  size_t N = B::_X(
    *Bin,

    [&](ELFO &O) -> size_t {

  const ELFF &Elf = O.getELFFile();

  llvm::SmallVector<const Elf_Phdr *, 4> LoadSegments;

  auto ProgramHeadersOrError = Elf.program_headers();
  if (!ProgramHeadersOrError)
    throw std::runtime_error("failed to to get program headers from " + binary.path_str());

  for (const Elf_Phdr &Phdr : *ProgramHeadersOrError)
    if (Phdr.p_type == llvm::ELF::PT_LOAD)
      LoadSegments.push_back(&Phdr);

      return
      std::accumulate(LoadSegments.begin(),
                      LoadSegments.end(), 0,
                      [&](size_t res, const Elf_Phdr *LoadSeg) -> size_t {
                        const Elf_Phdr &Phdr = *LoadSeg;

                        return res + (Phdr.p_flags & llvm::ELF::PF_X
                                          ? Phdr.p_filesz
                                          : 0);
                      });
    },

    [&](COFFO &O) -> size_t {
      auto sects_itr = O.sections();
      return
      std::accumulate(sects_itr.begin(),
                      sects_itr.end(), 0,
                      [&](size_t res, const llvm::object::SectionRef &S) -> size_t {
                        const llvm::object::coff_section *Sect = O.getCOFFSection(S);

                        return res +
                               (Sect->Characteristics & llvm::COFF::IMAGE_SCN_MEM_EXECUTE
                                 ? Sect->SizeOfRawData
                                 : 0);
                      });
    }
  );

  if (N == 0)
    return 1.0;

  binary_t &b = const_cast<binary_t &>(binary);
  auto &ICFG = b.Analysis.ICFG;

  //
  // add up all the basic block lengths (M)
  //
  size_t M = ({
    ip_sharable_lock<ip_sharable_mutex> s_lck_bbmap(b.bbmap_mtx);

    std::accumulate(b.bbmap.cbegin(),
		    b.bbmap.cend(), 0,
                    [&](size_t res, const auto &pair) -> size_t {
                      const addr_intvl &intvl = pair.first;
                      return res + intvl.second;
                    });
  });

  //
  // compute the ratio (M / N)
  //
  return static_cast<double>(M) / static_cast<double>(N);
}

}
