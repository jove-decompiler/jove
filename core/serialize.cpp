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

static thread_local jv_file_t *pFile_hack = nullptr; /* XXX */
static thread_local bool IsMT_hack, IsMinSize_hack; /* for DynTargets_t */

}

namespace boost {
namespace serialization {

//
// std::atomic
//
template <class Archive, class T>
static void save(Archive &ar, const std::atomic<T> &t, const unsigned int) {
  const T value = t.load(std::memory_order_relaxed);
  ar << BOOST_SERIALIZATION_NVP(value);
}

template <class Archive, class T>
static void load(Archive &ar, std::atomic<T> &t, const unsigned int) {
  T value;
  ar >> value;
  t.store(value, std::memory_order_relaxed);
}

template <class Archive, class T>
static void serialize(Archive &ar, std::atomic<T> &t,
                      const unsigned int file_version) {
  boost::serialization::split_free(ar, t, file_version);
}

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

template <class Archive, class T, class Allocator, class Options>
static inline void
save(Archive &ar,
     const boost::container::deque<T, Allocator, Options> &x,
     const unsigned int file_version) {
  stl::save_collection<Archive, boost::container::deque<T, Allocator, Options>>(ar, x);
}

template <class Archive, class T, class Allocator, class Options>
static inline void load(Archive &ar,
                        boost::container::deque<T, Allocator, Options> &x,
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

template <class Archive, class T, class Allocator, class Options>
static inline void
serialize(Archive &ar,
          boost::container::deque<T, Allocator, Options> &x,
          const unsigned int file_version) {
  boost::serialization::split_free(ar, x, file_version);
}

//
// ip_deque
//
template <class Archive, class T, class Allocator, bool MT, bool Spin, bool PointUnique>
static inline void
serialize(Archive &ar,
          jove::ip_deque<T, Allocator, MT, Spin, PointUnique> &x,
          const unsigned int file_version) {
  ar &BOOST_SERIALIZATION_NVP(x.container());
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
// table_t
//
template <class Archive, typename T, std::size_t N>
static void
serialize(Archive &ar,
          jove::table_t<T, N> &table,
          const unsigned int version) {
  ar & BOOST_SERIALIZATION_NVP(table.len_)
     & boost::serialization::make_nvp("table.storage_", *static_cast<T(*)[N]>(static_cast<void *>(table.storage_)));
}

//
// ip_adjacency_list
//
template <class Archive, bool MT, bool Spin, bool PointUnique, typename... Args>
static void
serialize(Archive &ar,
          jove::ip_adjacency_list<MT, Spin, PointUnique, Args...> &ip_adj,
          const unsigned int version) {
  boost::serialization::split_free(ar, ip_adj, version);
}

template <class Archive, bool MT, bool Spin, bool PointUnique, typename... Args>
static inline void
save(Archive &ar,
     const jove::ip_adjacency_list<MT, Spin, PointUnique, Args...> &ip_adj,
     const unsigned int file_version) {
  auto e_lck = ip_adj.exclusive_access();

  auto &ip_adj_ = const_cast<
      jove::ip_adjacency_list<MT, Spin, PointUnique, Args...>::type &>(
      ip_adj.container());

  const unsigned num_verts = ip_adj.num_vertices();
  const unsigned num_verts_act = boost::num_vertices(ip_adj_);

  assert(num_verts_act >= num_verts);

  for (unsigned i = 0; i < num_verts_act - num_verts; ++i) {
    //
    // no need to call boost::remove_vertex since we are not using a named graph
    // (and so icfg_t::removing_vertex() is a no-op), and none of these vertices
    // have outgoing (or incoming) edges
    //
    ip_adj_.m_vertices.pop_back();
  }

  assert(boost::num_vertices(ip_adj_) == num_verts);

  ar << BOOST_SERIALIZATION_NVP(ip_adj.container());
}

template <class Archive, bool MT, bool Spin, bool PointUnique, typename... Args>
static inline void
load(Archive &ar,
     jove::ip_adjacency_list<MT, Spin, PointUnique, Args...> &ip_adj,
     const unsigned int file_version) {
  auto e_lck = ip_adj.exclusive_access();

  auto &ip_adj_ = ip_adj.container();

  ar >> ip_adj_;
  ip_adj._size.store(boost::num_vertices(ip_adj_), std::memory_order_relaxed);
}

//
// adds_binary_t
//
template <class Archive>
static void serialize(Archive &ar, jove::adds_binary_t &x,
                      const unsigned int version) {
  ar &BOOST_SERIALIZATION_NVP(x.BIdx);
}

//
// allocates_basic_block_t
//
template <class Archive>
static void serialize(Archive &ar, jove::allocates_basic_block_t &ab,
                      const unsigned int version) {
  ar &BOOST_SERIALIZATION_NVP(ab.BBIdx);
}

//
// allocates_function_t
//
template <class Archive>
static void serialize(Archive &ar, jove::allocates_function_t &af,
                      const unsigned int version) {
  ar &BOOST_SERIALIZATION_NVP(af.FIdx);
}

//
// binary_t
//
template <class Archive, bool MT, bool MinSize>
static void serialize(Archive &ar, jove::binary_base_t<MT, MinSize> &b,
                      const unsigned int version) {
  ar &BOOST_SERIALIZATION_NVP(b.Idx)
     &BOOST_SERIALIZATION_NVP(b.bbbmap)
     &BOOST_SERIALIZATION_NVP(b.BBMap.map)
     &BOOST_SERIALIZATION_NVP(b.fnmap)
     &BOOST_SERIALIZATION_NVP(b.Name)
     &BOOST_SERIALIZATION_NVP(b.Data)
     &BOOST_SERIALIZATION_NVP(b.Hash)
     &BOOST_SERIALIZATION_NVP(b.IsDynamicLinker)
     &BOOST_SERIALIZATION_NVP(b.IsExecutable)
     &BOOST_SERIALIZATION_NVP(b.IsVDSO)
     &BOOST_SERIALIZATION_NVP(b.IsPIC)
     &BOOST_SERIALIZATION_NVP(b.IsDynamicallyLoaded)
     &BOOST_SERIALIZATION_NVP(b.Analysis.EntryFunction)
     &BOOST_SERIALIZATION_NVP(b.Analysis.Functions)
     &BOOST_SERIALIZATION_NVP(b.Analysis.ICFG);
}

//
// function_t
//
template <class Archive>
static void serialize(Archive &ar, jove::function_t &f, const unsigned int version) {
  ar &BOOST_SERIALIZATION_NVP(f.Speculative)
     &BOOST_SERIALIZATION_NVP(f.BIdx)
     &BOOST_SERIALIZATION_NVP(f.Idx)
     &BOOST_SERIALIZATION_NVP(f.Entry)
     &BOOST_SERIALIZATION_NVP(f.ReverseCGVertIdxHolder.Idx)
     &BOOST_SERIALIZATION_NVP(f.IsABI)
     &BOOST_SERIALIZATION_NVP(f.IsSignalHandler)
     &BOOST_SERIALIZATION_NVP(f.Returns);
}

//
// DynTargets_t
//
template <bool MT, bool MinSize, class Archive>
static void serialize(Archive &ar, jove::DynTargets_t<MT, MinSize> &DynTargets,
                      const unsigned int version) {
  ar &BOOST_SERIALIZATION_NVP(DynTargets.set);
}

//
// bbprop_t
//
template <class Archive>
static void save(Archive &ar, const jove::bbprop_t &bbprop, const unsigned int) {
  ar &BOOST_SERIALIZATION_NVP(bbprop.pub.is)
     &BOOST_SERIALIZATION_NVP(bbprop.Speculative)
     &BOOST_SERIALIZATION_NVP(bbprop.Addr)
     &BOOST_SERIALIZATION_NVP(bbprop.Size)
     &BOOST_SERIALIZATION_NVP(bbprop.Term.Addr)
     &BOOST_SERIALIZATION_NVP(bbprop.Term.Type)
     &BOOST_SERIALIZATION_NVP(bbprop.Term._call.Target)
     &BOOST_SERIALIZATION_NVP(bbprop.Term._indirect_jump.IsLj)
     &BOOST_SERIALIZATION_NVP(bbprop.Term._return.Returns)
     &BOOST_SERIALIZATION_NVP(bbprop.Sj);

  assert(jove::pFile_hack);
  jove::jv_file_t &jv_file = *jove::pFile_hack;

#define MT_POSSIBILTIES                                                        \
    ((true))                                                                   \
    ((false))
#define MINSIZE_POSSIBILTIES                                                   \
    ((true))                                                                   \
    ((false))

#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)

#define DO_DYNTARGETS_CASE(r, product)                                         \
  if (jove::IsMT_hack      == GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)) &&      \
      jove::IsMinSize_hack == GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))) {      \
    auto MaybeDynTargets =                                                     \
        bbprop.getDynamicTargets<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),     \
                                 GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))>();  \
    if (MaybeDynTargets) {                                                     \
      auto &DynTargets = *MaybeDynTargets;                                     \
      ar &BOOST_SERIALIZATION_NVP(DynTargets);                                 \
    } else {                                                                   \
      jove::DynTargets_t<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),             \
                         GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))>             \
          DynTargets(jv_file.get_segment_manager());                           \
      ar &BOOST_SERIALIZATION_NVP(DynTargets);                                 \
    }                                                                          \
    return;                                                                    \
  }

  BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_DYNTARGETS_CASE,
                                (MT_POSSIBILTIES)(MINSIZE_POSSIBILTIES))

  assert(false);
}

template <class Archive>
static void load(Archive &ar, jove::bbprop_t &bbprop, const unsigned int) {
  ar &BOOST_SERIALIZATION_NVP(bbprop.pub.is)
     &BOOST_SERIALIZATION_NVP(bbprop.Speculative)
     &BOOST_SERIALIZATION_NVP(bbprop.Addr)
     &BOOST_SERIALIZATION_NVP(bbprop.Size)
     &BOOST_SERIALIZATION_NVP(bbprop.Term.Addr)
     &BOOST_SERIALIZATION_NVP(bbprop.Term.Type)
     &BOOST_SERIALIZATION_NVP(bbprop.Term._call.Target)
     &BOOST_SERIALIZATION_NVP(bbprop.Term._indirect_jump.IsLj)
     &BOOST_SERIALIZATION_NVP(bbprop.Term._return.Returns)
     &BOOST_SERIALIZATION_NVP(bbprop.Sj);

  assert(jove::pFile_hack);
  jove::jv_file_t &jv_file = *jove::pFile_hack;

#define MT_POSSIBILTIES                                                        \
    ((true))                                                                   \
    ((false))
#define MINSIZE_POSSIBILTIES                                                   \
    ((true))                                                                   \
    ((false))

#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)

#define DO_DYNTARGETS_CASE(r, product)                                         \
  if (jove::IsMT_hack      == GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)) &&      \
      jove::IsMinSize_hack == GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))) {      \
    using OurDynTargets_t =                                                    \
        jove::DynTargets_t<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),           \
                           GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))>;          \
    jove::ip_unique_ptr<OurDynTargets_t> TheDynTargets(                        \
        boost::interprocess::make_managed_unique_ptr(                          \
            jv_file.construct<OurDynTargets_t>(                                \
                boost::interprocess::anonymous_instance)(                      \
                jv_file.get_segment_manager()),                                \
            jv_file));                                                         \
    OurDynTargets_t &DynTargets = *TheDynTargets.get().get();                  \
    ar &DynTargets;                                                            \
    if (!DynTargets.empty()) {                                                 \
      TheDynTargets.release();                                                 \
      bbprop.pDynTargets.Store(&DynTargets, std::memory_order_relaxed);        \
    }                                                                          \
    return;                                                                    \
  }

  BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_DYNTARGETS_CASE,
                                (MT_POSSIBILTIES)(MINSIZE_POSSIBILTIES))
  assert(false);
}

template <class Archive>
static void serialize(Archive &ar, jove::bbprop_t &bbprop,
                      const unsigned int version) {
  boost::serialization::split_free(ar, bbprop, version);
}

//
// ip_call_graph_node_properties_t
//
template <class Archive>
static void serialize(Archive &ar, jove::ip_call_graph_node_properties_t &prop,
                      const unsigned int version) {
  ar &BOOST_SERIALIZATION_NVP(prop.X);
}

//
// jv_t
//

template <class Archive, bool MT, bool MinSize>
static void serialize(Archive &ar,
		      jove::jv_base_t<MT, MinSize> &jv,
                      const unsigned int) {
  ar &BOOST_SERIALIZATION_NVP(jv.Binaries)
     &BOOST_SERIALIZATION_NVP(jv.hash_to_binary)
     &BOOST_SERIALIZATION_NVP(jv.name_to_binaries)
     &BOOST_SERIALIZATION_NVP(jv.Analysis.ReverseCallGraph);
}

} // namespace serialization
} // namespace boost

namespace boost {
namespace serialization {

template <class Archive, bool MT, bool MinSize>
static void load_construct_data(Archive &ar,
                                jove::binary_base_t<MT, MinSize> *t,
                                const unsigned int file_version) {
  assert(jove::pFile_hack);
  ::new (t)jove::binary_base_t<MT, MinSize>(*jove::pFile_hack);
}

template <class Archive>
static inline void load_construct_data(Archive &ar, jove::function_t *t,
                                       const unsigned int file_version) {
  assert(jove::pFile_hack);
  ::new (t)jove::function_t(jove::pFile_hack->get_segment_manager());
}

template <class Archive>
static inline void load_construct_data(Archive &ar, jove::ip_string *t,
                                       const unsigned int file_version) {
  assert(jove::pFile_hack);
  ::new (t)jove::ip_string(jove::pFile_hack->get_segment_manager());
}

template <class Archive>
static inline void load_construct_data(
    Archive &ar,
    jove::ip_binary_index_set *t,
    const unsigned int file_version) {
  assert(jove::pFile_hack);
  ::new (t)jove::ip_binary_index_set(jove::pFile_hack->get_segment_manager());
}


} // namespace serialization
} // namespace boost

namespace jove {

template <bool MT, bool MinSize>
void SerializeJV(const jv_base_t<MT, MinSize> &in,
		 jv_file_t &jv_file,
                 std::ostream &os,
		 bool text) {
  pFile_hack = &jv_file;
  IsMT_hack = MT;
  IsMinSize_hack = MinSize;

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

template <bool MT, bool MinSize>
void SerializeJVToFile(const jv_base_t<MT, MinSize> &in,
		       jv_file_t &jv_file,
                       const char *path,
		       bool text) {
  std::ofstream ofs(path);
  if (!ofs.is_open())
    throw std::runtime_error("SerializeJVToFile: failed to open " +
                             std::string(path));

  SerializeJV(in, jv_file, ofs, text);
}

template <bool MT, bool MinSize>
void UnserializeJV(jv_base_t<MT, MinSize> &out,
		   jv_file_t &jv_file,
                   std::istream &is,
		   bool text) {
  pFile_hack = &jv_file;
  IsMT_hack = MT;
  IsMinSize_hack = MinSize;

  hack_interprocess_graphs(out); // XXX FIXME

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

  hack_interprocess_graphs(out); // XXX FIXME

  // XXX
  using bb_t = ip_icfg_base_t<MT>::vertex_descriptor;
  for_each_basic_block(std::execution::unseq, out,
                       [&](binary_base_t<MT, MinSize> &b, bb_t bb) {
                         auto &ICFG = b.Analysis.ICFG;
                         bbprop_t &bbprop = ICFG[bb];

                         assert(b.EmptyFIdxVec);
                         bbprop.Parents.template set<false>(*b.EmptyFIdxVec);
                       });
}

template <bool MT, bool MinSize>
void UnserializeJVFromFile(jv_base_t<MT, MinSize> &out,
			   jv_file_t &jv_file,
                           const char *path,
			   bool text) {
  std::ifstream ifs(path);
  if (!ifs.is_open())
    throw std::runtime_error("UnserializeJVFromFile: failed to open " +
                             std::string(path));

  UnserializeJV(out, jv_file, ifs, text);
}

template <bool MT, bool MinSize>
void jv2xml(const jv_base_t<MT, MinSize> &jv, std::ostringstream &oss) {
  boost::archive::xml_oarchive oa(oss);

  oa << BOOST_SERIALIZATION_NVP(jv);
}

#define VALUES_TO_INSTANTIATE_WITH1                                            \
    ((true))                                                                   \
    ((false))
#define VALUES_TO_INSTANTIATE_WITH2                                            \
    ((true))                                                                   \
    ((false))

#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)

#define DO_INSTANTIATE(r, product)                                             \
  template void SerializeJV(                                                   \
      const jv_base_t<GET_VALUE(BOOST_PP_SEQ_ELEM(1, product)),                \
                      GET_VALUE(BOOST_PP_SEQ_ELEM(0, product))> &in,           \
      jv_file_t &, std::ostream &os, bool text);                               \
  template void SerializeJVToFile(                                             \
      const jv_base_t<GET_VALUE(BOOST_PP_SEQ_ELEM(1, product)),                \
                      GET_VALUE(BOOST_PP_SEQ_ELEM(0, product))> &,             \
      jv_file_t &, const char *path, bool text);                               \
  template void UnserializeJV(                                                 \
      jv_base_t<GET_VALUE(BOOST_PP_SEQ_ELEM(1, product)),                      \
                GET_VALUE(BOOST_PP_SEQ_ELEM(0, product))> &out,                \
      jv_file_t &jv_file, std::istream &is, bool text);                        \
  template void UnserializeJVFromFile(                                         \
      jv_base_t<GET_VALUE(BOOST_PP_SEQ_ELEM(1, product)),                      \
                GET_VALUE(BOOST_PP_SEQ_ELEM(0, product))> &out,                \
      jv_file_t &jv_file, const char *path, bool text);                        \
  template void jv2xml(                                                        \
      const jv_base_t<GET_VALUE(BOOST_PP_SEQ_ELEM(1, product)),                \
                      GET_VALUE(BOOST_PP_SEQ_ELEM(0, product))> &jv,           \
      std::ostringstream &oss);

BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_INSTANTIATE, (VALUES_TO_INSTANTIATE_WITH1)(VALUES_TO_INSTANTIATE_WITH2))

}
