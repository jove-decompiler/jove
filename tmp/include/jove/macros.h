#pragma once

#define _DECLARE_SHARED_MEMORY_MAP(Name, KeyType, MappedType)                  \
  typedef KeyType##_hasher Name##_Hasher;                                      \
  typedef KeyType Name##_KeyType;                                              \
  typedef MappedType Name##_MappedType;                                        \
  typedef std::pair<const Name##_KeyType, Name##_MappedType> Name##_ValueType; \
  typedef boost::interprocess::allocator<                                      \
      Name##_ValueType,                                                        \
      boost::interprocess::managed_shared_memory::segment_manager>             \
      Name##_AllocType;                                                        \
  typedef boost::unordered_map<                                                \
      Name##_KeyType, Name##_MappedType, KeyType##_hasher,                     \
      std::equal_to<Name##_KeyType>, Name##_AllocType>                         \
      Name##_Type;                                                             \
  Name##_AllocType Name##_alloc;                                               \
  Name##_Type &Name;

#define _DECLARE_INTERPROCESS_MUTEX(Name)                                      \
  boost::interprocess::interprocess_mutex &Name;

#define _DEFINE_SHARED_MEMORY_MAP(Name, InitBuckets)                           \
  Name##_alloc(segment.get_segment_manager()),                                 \
  Name(*segment.find_or_construct<Name##_Type>(#Name)(                         \
    InitBuckets,                                                               \
    Name##_Hasher(),                                                           \
    std::equal_to<Name##_KeyType>(),                                           \
    Name##_alloc))

#define _DEFINE_INTERPROCESS_MUTEX(Name)                                       \
  Name(*segment.find_or_construct<boost::interprocess::interprocess_mutex>(#Name)())
