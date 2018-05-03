#include <cstdint>
#include <boost/graph/adjacency_list.hpp>
//#include <boost/archive/text_oarchive.hpp>
//#include <boost/archive/text_iarchive.hpp>

namespace jove {

enum class terminator_inst_type : unsigned {
  UNCONDITIONAL_JUMP,
  CONDITIONAL_JUMP,
  CALL,
  INDIRECT_CALL,
  INDIRECT_JUMP,
  RETURN
};

struct basic_block_properties_t {
  std::uintptr_t Addr;
  std::ptrdiff_t Len;

  struct {
    terminator_inst_type Type;

    std::vector<std::uintptr_t> Callees;
  } Term;

  template <class Archive>
  void serialize(Archive &ar, const unsigned int) {
    ar &Addr &Len &Term.Type &Term.Callees;
  }
};

struct function_properties_t {
  struct {
    struct {
      std::set<std::pair<unsigned, unsigned>> Slots;
    } Stack;
  } Analysis;
};

typedef boost::adjacency_list<boost::setS, /* no parallel edges */
                              boost::listS,
                              boost::bidirectionalS, /* directed graph */
                              basic_block_properties_t,
                              struct {},
                              function_decompilation_properties_t>
    function_t;

struct decompilation_t {
  struct {
    std::string Name;
    std::string Arch;
  } Binary;

  std::map<std::uintptr_t, function_t> Functions;

  template <class Archive>
  void serialize(Archive &ar, const unsigned int) {
    ar &Binary.Name &Binary.Arch &Functions;
  }
};

}
