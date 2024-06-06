#include "serialize.h"
#include "xml.h"

#include <fstream>

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/xml_oarchive.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <boost/interprocess/containers/map.hpp>
#include <boost/interprocess/containers/set.hpp>
#include <boost/interprocess/containers/string.hpp>
#include <boost/interprocess/containers/vector.hpp>
#include <boost/serialization/bitset.hpp>
#include <boost/serialization/array.hpp>
#include <boost/serialization/collections_load_imp.hpp>
#include <boost/serialization/collections_save_imp.hpp>
#include <boost/serialization/item_version_type.hpp>
#include <boost/serialization/library_version_type.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/nvp.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/split_free.hpp>
#include <boost/serialization/vector.hpp>

#include <sys/stat.h>

namespace jove {

static std::unique_ptr<ip_void_allocator_t> pAlloc_hack; /* XXX */

}

namespace boost {
namespace serialization {

//
// interprocess string
//

template <class Archive, class Allocator>
static inline void
save(Archive &ar,
     const boost::container::basic_string<char, std::char_traits<char>, Allocator> &x,
     const unsigned int file_version) {
  std::string y;
  y.reserve(x.size());
  std::copy(x.begin(), x.end(), std::back_inserter(y));
  ar << BOOST_SERIALIZATION_NVP(y);
}

template <class Archive, class Allocator>
static inline void
load(Archive &ar,
     boost::container::basic_string<char, std::char_traits<char>, Allocator> &x,
     const unsigned int file_version) {
  std::string y;
  ar >> y;

  x.reserve(y.size());
  std::copy(y.begin(), y.end(), std::back_inserter(x));
}

template <class Archive, class Allocator>
static inline void
serialize(Archive &ar,
          boost::container::basic_string<char, std::char_traits<char>, Allocator> &t,
          const unsigned int file_version) {
  boost::serialization::split_free(ar, t, file_version);
}

//
// interprocess vector
//

template <class Archive, class T, class Allocator>
static inline void
save(Archive &ar,
     const boost::container::vector<T, Allocator> &x,
     const unsigned int file_version) {
  stl::save_collection<Archive, boost::container::vector<T, Allocator>>(ar, x);
}

template <class Archive, class T, class Allocator>
static inline void load(Archive &ar,
                 boost::container::vector<T, Allocator> &x,
                 const unsigned int file_version) {
  const boost::serialization::library_version_type library_version(
      ar.get_library_version());
  // retrieve number of elements
  item_version_type item_version(0);
  collection_size_type count;
  ar >> BOOST_SERIALIZATION_NVP(count);
  if (boost::serialization::library_version_type(3) < library_version) {
    ar >> BOOST_SERIALIZATION_NVP(item_version);
  }
  x.reserve(count);
  stl::collection_load_impl(ar, x, count, item_version);
}

template <class Archive, class T, class Allocator>
static inline void
serialize(Archive &ar,
          boost::container::vector<T, Allocator> &x,
          const unsigned int file_version) {
  boost::serialization::split_free(ar, x, file_version);
}

//
// interprocess deque
//

template <class Archive, class T, class Allocator>
static inline void
save(Archive &ar,
     const boost::container::deque<T, Allocator> &x,
     const unsigned int file_version) {
  stl::save_collection<Archive, boost::container::deque<T, Allocator>>(ar, x);
}

template <class Archive, class T, class Allocator>
static inline void load(Archive &ar,
                 boost::container::deque<T, Allocator> &x,
                 const unsigned int file_version) {
  const boost::serialization::library_version_type library_version(
      ar.get_library_version());
  // retrieve number of elements
  item_version_type item_version(0);
  collection_size_type count;
  ar >> BOOST_SERIALIZATION_NVP(count);
  if (boost::serialization::library_version_type(3) < library_version) {
    ar >> BOOST_SERIALIZATION_NVP(item_version);
  }
  stl::collection_load_impl(ar, x, count, item_version);
}

template <class Archive, class T, class Allocator>
static inline void
serialize(Archive &ar,
          boost::container::deque<T, Allocator> &x,
          const unsigned int file_version) {
  boost::serialization::split_free(ar, x, file_version);
}

//
// interprocess map
//

template <class Archive, class Type, class Key, class Compare, class Allocator>
static inline void save(Archive &ar,
                 const boost::container::map<Key, Type, Compare, Allocator> &t,
                 const unsigned int file_version) {
  stl::save_collection<Archive,
                       boost::container::map<Key, Type, Compare, Allocator>>(ar, t);
}

template <class Archive, class Type, class Key, class Compare, class Allocator>
static inline void load(Archive &ar,
                 boost::container::map<Key, Type, Compare, Allocator> &t,
                 const unsigned int file_version) {
  boost::serialization::load_map_collection(ar, t);
}

template <class Archive, class Type, class Key, class Compare, class Allocator>
static inline void
serialize(Archive &ar,
          boost::container::map<Key, Type, Compare, Allocator> &x,
          const unsigned int file_version) {
  boost::serialization::split_free(ar, x, file_version);
}

//
// interprocess flat_map
//

template <class Archive, class Type, class Key, class Compare, class Allocator>
static inline void save(Archive &ar,
                 const boost::container::flat_map<Key, Type, Compare, Allocator> &t,
                 const unsigned int file_version) {
  stl::save_collection<Archive,
                       boost::container::flat_map<Key, Type, Compare, Allocator>>(ar, t);
}

template <class Archive, class Type, class Key, class Compare, class Allocator>
static inline void load(Archive &ar,
                 boost::container::flat_map<Key, Type, Compare, Allocator> &t,
                 const unsigned int file_version) {
  boost::serialization::load_map_collection(ar, t);
}

template <class Archive, class Type, class Key, class Compare, class Allocator>
static inline void
serialize(Archive &ar,
          boost::container::flat_map<Key, Type, Compare, Allocator> &x,
          const unsigned int file_version) {
  boost::serialization::split_free(ar, x, file_version);
}

//
// interprocess set
//

template <class Archive, class Key, class Compare, class Allocator>
static inline void save(Archive &ar,
                        const boost::container::set<Key, Compare, Allocator> &t,
                        const unsigned int file_version) {
  stl::save_collection<Archive, boost::container::set<Key, Compare, Allocator>>(ar, t);
}

template <class Archive, class Key, class Compare, class Allocator>
static inline void load(Archive &ar,
                        boost::container::set<Key, Compare, Allocator> &t,
                        const unsigned int file_version) {
  boost::serialization::load_set_collection(ar, t);
}

template <class Archive, class Key, class Compare, class Allocator>
static inline void serialize(Archive &ar,
                             boost::container::set<Key, Compare, Allocator> &t,
                             const unsigned int file_version) {
  boost::serialization::split_free(ar, t, file_version);
}

} // namespace serialization
} // namespace boost

namespace boost {
namespace serialization {

//
// binary_t::Analysis_t::_Functions
//
template <class Archive>
static void serialize(Archive &ar, jove::binary_t::Analysis_t::_Functions &X,
                      const unsigned int) {
  ar &BOOST_SERIALIZATION_NVP(X._deque);
}

//
// binary_t::Analysis_t
//
template <class Archive>
static void serialize(Archive &ar, jove::binary_t::Analysis_t &A,
                      const unsigned int version) {
  ar &BOOST_SERIALIZATION_NVP(A.EntryFunction)
     &BOOST_SERIALIZATION_NVP(A.Functions)
     &BOOST_SERIALIZATION_NVP(A.ICFG)
     &BOOST_SERIALIZATION_NVP(A.RelocDynTargets)
     &BOOST_SERIALIZATION_NVP(A.IFuncDynTargets)
     &BOOST_SERIALIZATION_NVP(A.SymDynTargets);
}

//
// binary_t
//
template <class Archive>
static void serialize(Archive &ar, jove::binary_t &b,
                      const unsigned int version) {
  ar &BOOST_SERIALIZATION_NVP(b.Idx)
     &BOOST_SERIALIZATION_NVP(b.bbbmap)
     &BOOST_SERIALIZATION_NVP(b.bbmap)
     &BOOST_SERIALIZATION_NVP(b.fnmap)
     &BOOST_SERIALIZATION_NVP(b.Name)
     &BOOST_SERIALIZATION_NVP(b.Data)
     &BOOST_SERIALIZATION_NVP(b.Hash)
     &BOOST_SERIALIZATION_NVP(b.IsDynamicLinker)
     &BOOST_SERIALIZATION_NVP(b.IsExecutable)
     &BOOST_SERIALIZATION_NVP(b.IsVDSO)
     &BOOST_SERIALIZATION_NVP(b.IsPIC)
     &BOOST_SERIALIZATION_NVP(b.IsDynamicallyLoaded)
     &BOOST_SERIALIZATION_NVP(b.Analysis);

  for (jove::function_t &f : b.Analysis.Functions) { /* XXX */
    if (!f.b)
      f.b = &b;
  }
}

//
// function_t::Analysis_t
//
template <class Archive>
static void serialize(Archive &ar, jove::function_t::Analysis_t &A,
                      const unsigned int version) {
  ar &BOOST_SERIALIZATION_NVP(A.args)
     &BOOST_SERIALIZATION_NVP(A.rets)
     &BOOST_SERIALIZATION_NVP(A.Stale);
}

//
// function_t
//
template <class Archive>
static void serialize(Archive &ar, jove::function_t &f, const unsigned int version) {
  ar &BOOST_SERIALIZATION_NVP(f.Idx)
     &BOOST_SERIALIZATION_NVP(f.Entry)
     &BOOST_SERIALIZATION_NVP(f.Analysis)
     &BOOST_SERIALIZATION_NVP(f.IsABI)
     &BOOST_SERIALIZATION_NVP(f.IsSignalHandler)
     &BOOST_SERIALIZATION_NVP(f.Returns);
}

//
// basic_block_properties_t
//

template <class Archive>
static void serialize(Archive &ar, jove::basic_block_properties_t &bbprop,
                      const unsigned int version) {
  jove::dynamic_target_set DynTargets;
  if (bbprop.pDynTargets)
    DynTargets.insert(bbprop.dyn_targets_begin(), bbprop.dyn_targets_end());

  ar &BOOST_SERIALIZATION_NVP(bbprop.Addr)
     &BOOST_SERIALIZATION_NVP(bbprop.Size)
     &BOOST_SERIALIZATION_NVP(bbprop.Term.Addr)
     &BOOST_SERIALIZATION_NVP(bbprop.Term.Type)
     &BOOST_SERIALIZATION_NVP(bbprop.Term._call.Target)
     &BOOST_SERIALIZATION_NVP(bbprop.Term._call.Returns)
     &BOOST_SERIALIZATION_NVP(bbprop.Term._call.ReturnsOff)
     &BOOST_SERIALIZATION_NVP(bbprop.Term._indirect_jump.IsLj)
     &BOOST_SERIALIZATION_NVP(bbprop.Term._indirect_call.Returns)
     &BOOST_SERIALIZATION_NVP(bbprop.Term._indirect_call.ReturnsOff)
     &BOOST_SERIALIZATION_NVP(bbprop.Term._return.Returns)
     &BOOST_SERIALIZATION_NVP(DynTargets)
     &BOOST_SERIALIZATION_NVP(bbprop.DynTargetsComplete)
     &BOOST_SERIALIZATION_NVP(bbprop.Sj)
     &BOOST_SERIALIZATION_NVP(bbprop.Analysis.live.def)
     &BOOST_SERIALIZATION_NVP(bbprop.Analysis.live.use)
     &BOOST_SERIALIZATION_NVP(bbprop.Analysis.reach.def)
     &BOOST_SERIALIZATION_NVP(bbprop.Analysis.Stale);

  /* XXX */
  if (!DynTargets.empty() && jove::pAlloc_hack) {
    jove::ip_void_allocator_t &Alloc = *jove::pAlloc_hack;

    if (!bbprop.pDynTargets)
      bbprop.pDynTargets =
          Alloc.get_segment_manager()->construct<jove::ip_dynamic_target_set>(
              boost::interprocess::anonymous_instance)(Alloc);

    bbprop.pDynTargets->insert(DynTargets.begin(), DynTargets.end());
  }
}

//
// jv_t::_Binaries
//

template <class Archive>
static void serialize(Archive &ar, jove::jv_t::_Binaries &B, const unsigned int) {
  ar &BOOST_SERIALIZATION_NVP(B._deque);
}

//
// jv_t
//

template <class Archive>
static void serialize(Archive &ar, jove::jv_t &jv, const unsigned int) {
  ar &BOOST_SERIALIZATION_NVP(jv.Binaries)
     &BOOST_SERIALIZATION_NVP(jv.hash_to_binary)
     &BOOST_SERIALIZATION_NVP(jv.name_to_binaries);
}

} // namespace serialization
} // namespace boost

namespace boost {
namespace serialization {

template <class Archive>
static inline void load_construct_data(Archive &ar, jove::binary_t *t,
                                       const unsigned int file_version) {
  assert(jove::pAlloc_hack);
  ::new (t)jove::binary_t(*jove::pAlloc_hack);
}

template <class Archive>
static inline void load_construct_data(Archive &ar, jove::ip_string *t,
                                       const unsigned int file_version) {
  assert(jove::pAlloc_hack);
  ::new (t)jove::ip_string(*jove::pAlloc_hack);
}

template <class Archive>
static inline void load_construct_data(
    Archive &ar,
    std::pair<const jove::ip_string, jove::ip_dynamic_target_set> *t,
    const unsigned int file_version) {
  assert(jove::pAlloc_hack);
  ::new (t)std::pair<const jove::ip_string, jove::ip_dynamic_target_set>(*jove::pAlloc_hack, *jove::pAlloc_hack);
}

template <class Archive>
static inline void
load_construct_data(Archive &ar,
                    std::pair<const uint64_t, jove::ip_dynamic_target_set> *t,
                    const unsigned int file_version) {
  assert(jove::pAlloc_hack);
  ::new (t)std::pair<const uint64_t, jove::ip_dynamic_target_set>(0, *jove::pAlloc_hack);
}

template <class Archive>
static inline void load_construct_data(
    Archive &ar,
    std::pair<const jove::ip_string, jove::ip_binary_index_set> *t,
    const unsigned int file_version) {
  assert(jove::pAlloc_hack);
  ::new (t)std::pair<const jove::ip_string, jove::ip_binary_index_set>(*jove::pAlloc_hack, *jove::pAlloc_hack);
}

template <class Archive>
static inline void load_construct_data(
    Archive &ar,
    jove::ip_binary_index_set *t,
    const unsigned int file_version) {
  assert(jove::pAlloc_hack);
  ::new (t)jove::ip_binary_index_set(*jove::pAlloc_hack);
}

} // namespace serialization
} // namespace boost

namespace jove {

void SerializeJV(const jv_t &in, std::ostream &os, bool text) {
  try {
    if (text) {
      boost::archive::text_oarchive oa(os);
      oa << in;
    } else {
      boost::archive::binary_oarchive oa(os);
      oa << in;
    }
  } catch (...) {
    throw std::runtime_error("SerializeJV failed!");
  }
}

void SerializeJVToFile(const jv_t &in, const char *path, bool text) {
  std::ofstream ofs(path);
  if (!ofs.is_open())
    throw std::runtime_error("SerializeJVToFile: failed to open " +
                             std::string(path));

  SerializeJV(in, ofs, text);
}

void UnserializeJV(jv_t &out, std::istream &is, bool text) {
  /* FIXME */
  for (binary_t &b : out.Binaries)
    __builtin_memset(&b.Analysis.ICFG.m_property, 0, sizeof(b.Analysis.ICFG.m_property));

  pAlloc_hack.reset(new ip_void_allocator_t(out.get_allocator())); /* XXX */

  out.clear();

  try {
    if (text) {
      boost::archive::text_iarchive ia(is);
      ia >> out;
    } else {
      boost::archive::binary_iarchive ia(is);
      ia >> out;
    }
  } catch (...) {
    throw std::runtime_error("UnserializeJV failed!");
  }

  /* FIXME */
  for (binary_t &b : out.Binaries)
    __builtin_memset(&b.Analysis.ICFG.m_property, 0, sizeof(b.Analysis.ICFG.m_property));
}

void UnserializeJVFromFile(jv_t &out, const char *path, bool text) {
  std::ifstream ifs(path);
  if (!ifs.is_open())
    throw std::runtime_error("UnserializeJVFromFile: failed to open " +
                             std::string(path));

  UnserializeJV(out, ifs, text);
}

void jv2xml(const jv_t &jv, std::ostringstream &oss) {
  boost::archive::xml_oarchive oa(oss);

  oa << BOOST_SERIALIZATION_NVP(jv);
}

}
