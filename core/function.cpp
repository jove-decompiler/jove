#include "jove/jove.h"

#include <boost/preprocessor/seq/for_each.hpp>
#include <boost/preprocessor/seq/elem.hpp>
#include <boost/preprocessor/seq/seq.hpp>

namespace jove {

template <bool MT>
function_t::function_t(binary_base_t<MT> &b, function_index_t Idx)
    : BIdx(b.Idx /* could be invalid */), Idx(Idx),
      Callers(b.get_segment_manager()) {}

function_t::function_t(segment_manager_t *sm)
    : Callers(sm) {}

#define VALUES_TO_INSTANTIATE_WITH                                             \
    ((true))                                                                   \
    ((false))

#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)

#define DO_INSTANTIATE(r, data, elem)                                          \
  template function_t::function_t(binary_base_t<GET_VALUE(elem)> &,            \
                                  function_index_t Idx);
BOOST_PP_SEQ_FOR_EACH(DO_INSTANTIATE, void, VALUES_TO_INSTANTIATE_WITH)

}
