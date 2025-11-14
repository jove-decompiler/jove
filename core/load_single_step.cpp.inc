#ifndef JOVE_SINGLESTEP_OPCODE
#error
#endif

#undef JOVE_SINGLESTEP_MAP
#undef JOVE_SINGLESTEP_MAP_KEY_TYPE

#define JOVE_SINGLESTEP_MAP BOOST_PP_CAT(BOOST_PP_CAT(single_step_,JOVE_SINGLESTEP_OPCODE),_map)

#define JOVE_PARAM_TYPE(r, data, i, elem)                                      \
  BOOST_PP_COMMA_IF(i)                                                         \
  BOOST_PP_TUPLE_ELEM(2, 0, elem)

#define JOVE_SINGLESTEP_PARAMS_TYPES                                           \
  BOOST_PP_SEQ_FOR_EACH_I(JOVE_PARAM_TYPE, _, BOOST_PP_CAT(BOOST_PP_CAT(JOVE_SINGLESTEP_,JOVE_SINGLESTEP_OPCODE),_PARAMETERS))

#define JOVE_SINGLESTEP_MAP BOOST_PP_CAT(BOOST_PP_CAT(single_step_,JOVE_SINGLESTEP_OPCODE),_map)

using BOOST_PP_CAT(JOVE_SINGLESTEP_MAP,_t) = single_step_map_t<JOVE_SINGLESTEP_PARAMS_TYPES>;
#define JOVE_SINGLESTEP_MAP_KEY_TYPE BOOST_PP_CAT(JOVE_SINGLESTEP_MAP,_t)::key_type

#define JOVE_PARAM_DOMAIN_FROM_ELEM(r, data, i, elem)                          \
  (BOOST_PP_CAT(JOVE_PARAM_DOMAIN_, BOOST_PP_TUPLE_ELEM(2, 1, elem)))

#define JOVE_SINGLESTEP_PARAM_DOMAINS                                          \
  BOOST_PP_SEQ_FOR_EACH_I(JOVE_PARAM_DOMAIN_FROM_ELEM, _, BOOST_PP_CAT(BOOST_PP_CAT(JOVE_SINGLESTEP_,JOVE_SINGLESTEP_OPCODE),_PARAMETERS))

#define JOVE_MAP_ENTRY(r, product)                                             \
  {                                                                            \
    JOVE_SINGLESTEP_MAP_KEY_TYPE(BOOST_PP_SEQ_ENUM(product)),                  \
    &BOOST_PP_CAT(BOOST_PP_CAT(single_step_,JOVE_SINGLESTEP_OPCODE),_proc)<llvm::JOVE_LLVMINST_TARGET::JOVE_SINGLESTEP_OPCODE,BOOST_PP_SEQ_ENUM(product)>\
  },

static BOOST_PP_CAT(JOVE_SINGLESTEP_MAP,_t)
                    JOVE_SINGLESTEP_MAP = {
BOOST_PP_SEQ_FOR_EACH_PRODUCT(JOVE_MAP_ENTRY, JOVE_SINGLESTEP_PARAM_DOMAINS)
};
