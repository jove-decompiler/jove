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
  static_assert(!(MT && !std::is_same_v<VertexListS, boost::dequeS_ip>));

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
  using StoredVertex = type::StoredVertex;
  using StoredEdge = type::StoredEdge;
  using OutEdgeIter = type::OutEdgeIter;

  using edge_parallel_category = boost::parallel_edge_traits<OutEdgeListS>::type;

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

#define ARE_WE_CONST \
  std::is_const_v<std::remove_reference_t<decltype(*this)>>

#define ____stored_vert____(V, pvprop_nm, pstoredv_nm)                         \
  possibly_const<ARE_WE_CONST, VertexProperty> *const pvprop_nm = ({           \
    auto s_lck = this->shared_access();                                        \
    &this->container()[V];                                                     \
  });                                                                          \
  possibly_const<ARE_WE_CONST, StoredVertex> *const pstoredv_nm =              \
      reinterpret_cast<possibly_const<ARE_WE_CONST, StoredVertex> *>(          \
          JOVE_ADDRESS_CONTAINER_OF(pvprop_nm, StoredVertex, m_property));

#define ____shared_vert____(ShouldLock, Mutex)                                 \
  [[maybe_unused]]                                                             \
  typename std::conditional<ShouldLock && MT,                                  \
                            typename VertexProperty::mt_shared_lock_guard,     \
                            nop_t>::type                                       \
  UNIQUE_VAR_NAME(__s_lck)(Mutex)

#define ____exclusive_vert____(ShouldLock, Mutex)                              \
  [[maybe_unused]]                                                             \
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
    assert(index(V) < num_vertices());

    auto s_lck = this->shared_access();
    return container()[V];
  }

  const vertex_property_type &at(vertex_descriptor V) const {
    assert(index(V) < num_vertices());

    auto s_lck = this->shared_access();
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

    // for VertexList=vecS this is just identity map =>static_assert FIXME
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
    ____stored_vert____(V, pvp, psv);
    auto &oedges = psv->m_out_edges;

    ____shared_vert____(L, pvp->mtx);
    return oedges.size();
  }

  void clear(void) {
    auto e_lck = this->exclusive_access();

    // FIXME take all the locks?
    container().clear();
  }

  template <bool L = true>
  void clear_out_edges(vertex_descriptor V) {
    ____stored_vert____(V, pvp, psv);
    auto &oedges = psv->m_out_edges;

    auto φ = [&](void) -> void {
      ____exclusive_vert____(L, pvp->mtx);
      oedges.clear();
    };

    if constexpr (std::is_same_v<DirectedS, boost::directedS>) {
      φ();
    } else if constexpr (std::is_same_v<DirectedS, boost::bidirectional_simpleS>) {

      // FIXME (style: dup)
      std::vector<vertex_descriptor> adjvv;
      {
        ____shared_vert____(L, pvp->mtx);

        adjvv.reserve(oedges.size());

        auto end = oedges.end();
        for (auto it = oedges.begin(); it != end; ++it)
          adjvv.push_back((*it).m_target);
      }

      for (vertex_descriptor adj : adjvv) {
        ____stored_vert____(adj, padjvp, padjsv);
        auto &iedges = padjsv->m_in_edges;

        ____exclusive_vert____(L, padjvp->mtx);
        boost::detail::erase_from_incidence_list(iedges, V, edge_parallel_category());
      }

      φ();
    } else {
      __compiletime_unreachable();
    }
  }

  template <bool L = true>
  std::pair<edge_descriptor, bool> add_edge(vertex_descriptor V1,
                                            vertex_descriptor V2) {
    if constexpr (std::is_same_v<DirectedS, boost::directedS>) {
      ____stored_vert____(V1, pvp1, psv1);
      auto &oedges = psv1->m_out_edges;

      OutEdgeIter it;
      bool inserted;

      {
        ____exclusive_vert____(L, pvp1->mtx);
        boost::tie(it, inserted) = boost::graph_detail::push(oedges, StoredEdge(V2));
      }

      return std::make_pair(edge_descriptor(V1, V2, &it->get_property()), inserted);
    } else if constexpr (std::is_same_v<DirectedS, boost::bidirectional_simpleS>) {
      const bool Same = V1 == V2;

      OutEdgeIter it;
      bool inserted;
      if (Same) {
        ____stored_vert____(V1, pvp, psv);
        auto &oedges = psv->m_out_edges;
        auto &iedges = psv->m_in_edges;

        ____exclusive_vert____(L, pvp->mtx);
        boost::tie(it, inserted) =
            boost::graph_detail::push(oedges, StoredEdge(V2));
        if (inserted)
          boost::graph_detail::push(iedges, StoredEdge(V1));
      } else {
        OutEdgeIter it;
        bool inserted;
        {
          ____stored_vert____(V1, pvp1, psv1);
          auto &oedges = psv1->m_out_edges;

          ____exclusive_vert____(L, pvp1->mtx);
          boost::tie(it, inserted) =
              boost::graph_detail::push(oedges, StoredEdge(V2));

          if (inserted) {
            ____stored_vert____(V2, pvp2, psv2);
            auto &iedges = psv2->m_in_edges;

            ____exclusive_vert____(L, pvp2->mtx);
            boost::graph_detail::push(iedges, StoredEdge(V1));
          }
        }
      }
      return std::make_pair(edge_descriptor(V1, V2, &it->get_property()), inserted);
    } else {
      __compiletime_unreachable();
    }
  }

  template <bool L = true>
  vertex_descriptor adjacent_front(vertex_descriptor V) const {
    ____stored_vert____(V, pvp, psv);
    auto &oedges = psv->m_out_edges;

    ____shared_vert____(L, pvp->mtx);
    assert(oedges.begin() != oedges.end());
    return (*oedges.begin()).m_target;
  }

  // precondition: out_degree(V) >= N
  template <unsigned N, bool L = true>
  __attribute__((always_inline))
  std::array<vertex_descriptor, N> adjacent_n(vertex_descriptor V) const {
    ____stored_vert____(V, pvp, psv);
    auto &oedges = psv->m_out_edges;

    ____shared_vert____(L, pvp->mtx);

    std::array<vertex_descriptor, N> res;
    auto it = oedges.begin();

#pragma clang loop unroll(full)
    for (unsigned i = 0; i < N; ++i) {
      assert(it != oedges.end());
      res[i] = (*it++).m_target;
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

  template <bool L = true>
  std::vector<vertex_descriptor>
  get_adjacent_vertices(vertex_descriptor V) const {
    ____stored_vert____(V, pvp, psv);
    auto &oedges = psv->m_out_edges;

    ____shared_vert____(L, pvp->mtx);

    std::vector<vertex_descriptor> res;
    res.reserve(oedges.size());

    auto end = oedges.end();
    for (auto it = oedges.begin(); it != end; ++it)
      res.push_back((*it).m_target);

    return res;
  }

#undef ____shared_vert____
#undef ____exclusive_vert____
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
