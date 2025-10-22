#ifndef IN_JOVE_H
#error "only to be included inline in jove/jove.h"
#endif

template <bool MT, bool Spin, bool PointUnique,
          class OutEdgeListS,
          class VertexListS,
          class DirectedS,
          class VertexProperty,
          class EdgeProperty,
          class GraphProperty,
          class EdgeListS>
struct ip_adjacency_list : public ip_base_rw_accessible<MT, Spin> {
  using type = boost::adjacency_list<OutEdgeListS, VertexListS, DirectedS,
                                     VertexProperty, EdgeProperty,
                                     GraphProperty, EdgeListS>;

  std::conditional_t<PointUnique, ip_unique_ptr<type>, type> _adjacency_list;

  const type &container(void) const {
    if constexpr (PointUnique)
      return *_adjacency_list;
    else
      return _adjacency_list;
  }
  type &container(void) {
    if constexpr (PointUnique)
      return *_adjacency_list;
    else
      return _adjacency_list;
  }

  using vertex_descriptor = type::vertex_descriptor;
  using edge_descriptor = type::edge_descriptor;
  using vertices_size_type = type::vertices_size_type;
  using vertex_iterator = type::vertex_iterator;
  using degree_size_type = type::degree_size_type;
  using adjacency_iterator = type::adjacency_iterator;
  using out_edge_iterator = type::out_edge_iterator;
  using in_edge_iterator = type::in_edge_iterator;
  using inv_adjacency_iterator = type::inv_adjacency_iterator;
  using vertex_property_type = type::vertex_property_type;

  ip_atomic<uint32_t> _size = 0;

  ip_adjacency_list(jv_file_t &jv_file)
    requires(PointUnique)
      : _adjacency_list(boost::interprocess::make_managed_unique_ptr(
            jv_file.construct<type>(boost::interprocess::anonymous_instance)(
                typename type::graph_property_type(),
                jv_file.get_segment_manager()),
            jv_file)) {}

  ip_adjacency_list(jv_file_t &jv_file)
    requires(!PointUnique)
      : _adjacency_list(typename type::graph_property_type(),
                        jv_file.get_segment_manager()) {}

  template <bool MT2, bool Spin2>
  ip_adjacency_list(
      ip_adjacency_list<MT2, Spin2, PointUnique, OutEdgeListS, VertexListS,
                        DirectedS, VertexProperty, EdgeProperty, GraphProperty,
                        EdgeListS> &&other) noexcept
      : _adjacency_list(std::move(other._adjacency_list)),
        _size(other._size.load(boost::memory_order_relaxed)) {
    other._size.store(0, boost::memory_order_relaxed);
  }

  template <bool MT2, bool Spin2>
  ip_adjacency_list &operator=(
      ip_adjacency_list<MT2, Spin2, PointUnique, OutEdgeListS, VertexListS,
                        DirectedS, VertexProperty, EdgeProperty, GraphProperty,
                        EdgeListS> &&other) noexcept {
    if constexpr (MT == MT2) {
      if (this == &other)
        return *this;
    }

    _adjacency_list = std::move(other._adjacency_list);
    _size.store(other._size.load(boost::memory_order_relaxed));
    other._size.store(0, boost::memory_order_relaxed);
    return *this;
  }

  template <bool MT2, bool Spin2>
  ip_adjacency_list(
      const ip_adjacency_list<
          MT2, Spin2, PointUnique, OutEdgeListS, VertexListS, DirectedS,
          VertexProperty, EdgeProperty, GraphProperty, EdgeListS> &) = delete;

  template <bool MT2, bool Spin2>
  ip_adjacency_list &
  operator=(const ip_adjacency_list<
            MT2, Spin2, PointUnique, OutEdgeListS, VertexListS, DirectedS,
            VertexProperty, EdgeProperty, GraphProperty, EdgeListS> &) = delete;

#define VERT_SHARED_ACCESS(ShouldLock, Mutex)                                  \
  typename std::conditional<ShouldLock && MT,                                  \
                            typename VertexProperty::mt_shared_lock_guard,     \
                            nop_t>::type                                       \
  UNIQUE_VAR_NAME(__s_lck)(Mutex)

#define VERT_EXCLUSIVE_ACCESS(ShouldLock, Mutex)                               \
  typename std::conditional<ShouldLock && MT,                                  \
                            typename VertexProperty::mt_exclusive_lock_guard,  \
                            nop_t>::type                                       \
  UNIQUE_VAR_NAME(__e_lck)(Mutex)

  template <typename... Args>
  vertices_size_type index_of_add_vertex(Args &&...args) {
    const vertices_size_type Idx =
        _size.fetch_add(1u, boost::memory_order_relaxed);

    if (unlikely(Idx >= actual_num_vertices())) {
      auto e_lck = this->exclusive_access();

      vertices_size_type actual_size = boost::num_vertices(container());
      if (Idx >= actual_size) {
        vertices_size_type desired = std::bit_ceil(Idx + 1);
        assert(desired > actual_size);
        for (unsigned i = 0; i < desired - actual_size; ++i)
          boost::add_vertex(container(), std::forward<Args>(args)...);
        assert(Idx < boost::num_vertices(container()));
      }
    }

    return Idx;
  }

  template <typename... Args>
  vertex_descriptor add_vertex(Args &&...args) {
    return vertex<false>(index_of_add_vertex(std::forward<Args>(args)...));
  }

  vertices_size_type actual_num_vertices(void) const {
    auto s_lck = this->shared_access();
    return boost::num_vertices(container());
  }

  vertices_size_type num_vertices(void) const {
    return _size.load(boost::memory_order_relaxed);
  }

  bool empty(void) const { return num_vertices() == 0; }

  vertex_property_type &at(vertex_descriptor V) {
    auto s_lck = this->shared_access();

    assert(index(V) < num_vertices());

    return container()[V];
  }

  const vertex_property_type &at(vertex_descriptor V) const {
    auto s_lck = this->shared_access();

    assert(index(V) < num_vertices());

    return container()[V];
  }

  vertex_property_type &operator[](vertex_descriptor V) {
    auto s_lck = this->shared_access();
    return container()[V];
  }

  const vertex_property_type &operator[](vertex_descriptor V) const {
    auto s_lck = this->shared_access();
    return container()[V];
  }

  template <bool Check = true>
  vertex_descriptor vertex(vertices_size_type Idx) const {
    if (Check)
      assert(Idx < num_vertices()); /* catch bugs */

    // for VertexList=vecS this is just identity map TODO static_assert
    return boost::vertex(Idx, container());
  }

  vertices_size_type index(vertex_descriptor V) const {
    // for VertexList=vecS this is just identity map TODO static_assert
    return boost::get(boost::vertex_index, container())[V];
  }

  template <class DFSVisitor>
  void depth_first_visit(vertex_descriptor V, DFSVisitor &vis) const {
    std::vector<boost::default_color_type> ColorVec(actual_num_vertices());
    auto ColorPropMap = boost::make_iterator_property_map(
        ColorVec.begin(), boost::get(boost::vertex_index, container()));

    auto s_lck = this->shared_access();

    boost::depth_first_visit(container(), V, vis, ColorPropMap);
  }

  template <bool L = true, class BFSVisitor>
  void breadth_first_search(vertex_descriptor V, BFSVisitor &vis) const {
    auto s_lck = this->shared_access();

    boost::breadth_first_search(container(), V, boost::visitor(vis));
  }

  template <bool L = true>
  degree_size_type out_degree(vertex_descriptor V) const {
    auto s_lck = this->shared_access();
    VERT_SHARED_ACCESS(L, container()[V].mtx);

    return boost::out_degree(V, container());
  }

  void clear(void) {
    auto e_lck = this->exclusive_access();

    container().clear();
  }

  template <bool L = true>
  void clear_out_edges(vertex_descriptor V) {
    auto s_lck = this->shared_access();

    VERT_EXCLUSIVE_ACCESS(L, container()[V].mtx);

    boost::clear_out_edges(V, container());
  }

  template <bool L = true>
  std::pair<edge_descriptor, bool> add_edge(vertex_descriptor V1,
                                            vertex_descriptor V2) {
    auto s_lck = this->shared_access();

    VERT_EXCLUSIVE_ACCESS(L, container()[V1].mtx);

    return boost::add_edge(V1, V2, container());
  }

  template <bool L = true>
  vertex_descriptor adjacent_front(vertex_descriptor V) const {
    VERT_SHARED_ACCESS(L, container()[V].mtx);

    return *adjacent_vertices(V).first;
  }

  // precondition: out_degree(V) >= N
  template <unsigned N, bool L = true>
  __attribute__((always_inline))
  std::array<vertex_descriptor, N> adjacent_n(vertex_descriptor V) const {
    std::array<vertex_descriptor, N> res;

    {
      VERT_SHARED_ACCESS(L, container()[V].mtx);

      adjacency_iterator it, it_end;
      std::tie(it, it_end) = adjacent_vertices(V);

#pragma clang loop unroll(full)
      for (unsigned i = 0; i < N; ++i)
        res[i] = *it++;
    }

    return res;
  }

  template <bool L = true>
  std::pair<vertex_iterator, vertex_iterator> vertices(void) const {
    auto res = boost::vertices(container());
    std::advance(res.second, -(actual_num_vertices() - num_vertices()));
    return res;
  }
  std::pair<adjacency_iterator, adjacency_iterator>
  adjacent_vertices(vertex_descriptor V) const {
    auto s_lck = this->shared_access();
    return boost::adjacent_vertices(V, container());
  }
  std::pair<inv_adjacency_iterator, inv_adjacency_iterator>
  inv_adjacent_vertices(vertex_descriptor V) const {
    auto s_lck = this->shared_access();
    return boost::inv_adjacent_vertices(V, container());
  }
  std::pair<out_edge_iterator, out_edge_iterator>
  out_edges(vertex_descriptor V) const {
    auto s_lck = this->shared_access();
    return boost::out_edges(V, container());
  }
  std::pair<in_edge_iterator, in_edge_iterator>
  in_edges(vertex_descriptor V) const {
    auto s_lck = this->shared_access();
    return boost::in_edges(V, container());
  }

  std::vector<vertex_descriptor>
  get_adjacent_vertices(vertex_descriptor V) const {
    std::vector<vertex_descriptor> res;

#if 0
    VERT_SHARED_ACCESS(L, container()[V].mtx);
#else
    auto s_lck = this->shared_access();
#endif

    res.reserve(boost::out_degree(V, container()));

    adjacency_iterator it, it_end;
    std::tie(it, it_end) = boost::adjacent_vertices(V, container());
    std::copy(it, it_end, std::back_inserter(res));

    return res;
  }

#undef VERT_SHARED_ACCESS
#undef VERT_EXCLUSIVE_ACCESS
};

//
// until we come up with a cleaner source code patch for boost-graph (to make it
// work with boost interprocess (stateful) allocators), we need to do this for
// now XXX FIXME
//
template <bool MT, bool Spin, bool PointUnique, typename... Args>
static inline void hack_interprocess_graph(
    ip_adjacency_list<MT, Spin, PointUnique, Args...> &ip_adj) {
  auto &x = ip_adj.container();

  __builtin_memset_inline(&x.m_property, 0, sizeof(x.m_property));
}
