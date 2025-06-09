#include "score.h"
#include "B.h"
#include <boost/format.hpp>

namespace obj = llvm::object;

namespace jove {

typedef boost::format fmt;

template <bool MT, bool MinSize>
double compute_score(const jv_base_t<MT, MinSize> &jv,
                     const binary_base_t<MT, MinSize> &b) {
  auto Bin = B::Create(llvm::StringRef(b.data()));

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
          throw std::runtime_error("failed to to get program headers from " +
                                   b.path_str());

        for (const Elf_Phdr &Phdr : *ProgramHeadersOrError)
          if (Phdr.p_type == llvm::ELF::PT_LOAD)
            LoadSegments.push_back(&Phdr);

        return std::accumulate(
            LoadSegments.begin(),
            LoadSegments.end(), 0,
            [&](size_t res, const Elf_Phdr *LoadSeg) -> size_t {
              const Elf_Phdr &Phdr = *LoadSeg;

              return res + (Phdr.p_flags & llvm::ELF::PF_X ? Phdr.p_filesz : 0);
            });
      },

      [&](COFFO &O) -> size_t {
        auto sects_itr = O.sections();
        return std::accumulate(
            sects_itr.begin(),
            sects_itr.end(), 0,
            [&](size_t res, const llvm::object::SectionRef &S) -> size_t {
              const llvm::object::coff_section *Sect = O.getCOFFSection(S);

              return res +
                     (Sect->Characteristics & llvm::COFF::IMAGE_SCN_MEM_EXECUTE
                          ? Sect->SizeOfRawData
                          : 0);
            });
      });

  if (N == 0)
    return 1.0;

  //
  // add up all the basic block lengths (M)
  //
  size_t M = ({
    auto s_lck_bbmap = b.BBMap.shared_access();

    std::accumulate(b.BBMap.map.cbegin(),
                    b.BBMap.map.cend(), 0,
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

#define VALUES_TO_INSTANTIATE_WITH1                                            \
    ((true))                                                                   \
    ((false))
#define VALUES_TO_INSTANTIATE_WITH2                                            \
    ((true))                                                                   \
    ((false))
#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)

#define DO_INSTANTIATE(r, product)                                             \
  template double compute_score(                                               \
      const jv_base_t<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),                \
                      GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))> &,             \
      const binary_base_t<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),            \
                          GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))> &);

BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_INSTANTIATE, (VALUES_TO_INSTANTIATE_WITH1)(VALUES_TO_INSTANTIATE_WITH2))

}
