#ifndef IN_JOVE_H
#error "only to be included inline in jove/jove.h"
#endif

typedef std::pair<taddr_t, taddr_t> addr_intvl; /* right open interval */

struct addr_intvl_cmp {
  using is_transparent = void;

  bool operator()(const addr_intvl &lhs, const addr_intvl &rhs) const {
    return lhs.first < rhs.first;
  }

  bool operator()(const addr_intvl &lhs, taddr_t rhs) const {
    return lhs.first < rhs;
  }

  bool operator()(taddr_t lhs, const addr_intvl &rhs) const {
    return lhs < rhs.first;
  }
};

typedef boost::container::flat_map<addr_intvl, binary_index_t, addr_intvl_cmp>
    address_space_t;

static inline std::string addr_intvl2str(addr_intvl intvl) {
  return "[" +
         taddr2str(intvl.first, false) + ", " +
         taddr2str(intvl.first + intvl.second, false) + ")";
}

constexpr addr_intvl right_open_addr_intvl(taddr_t lower, taddr_t upper) {
  assert(upper > lower);
  return addr_intvl(lower, upper - lower);
}

constexpr taddr_t addr_intvl_lower(addr_intvl intvl) {
  return intvl.first;
}

constexpr taddr_t addr_intvl_upper(addr_intvl intvl) {
  return intvl.first + intvl.second;
}

static constexpr addr_intvl
    empty_addr_intvl(std::numeric_limits<taddr_t>::max(), 0);

constexpr bool addr_intvl_contains(addr_intvl intvl, taddr_t Addr) {
  return Addr >= intvl.first && Addr < intvl.first + intvl.second;
}

constexpr bool addr_intvl_intersects(addr_intvl x, addr_intvl y) {
  taddr_t a = addr_intvl_lower(x), b = addr_intvl_upper(x);
  taddr_t c = addr_intvl_lower(y), d = addr_intvl_upper(y);

  if (b <= c || d <= a)
    return false;

  return true;
}

constexpr bool addr_intvl_intersects(addr_intvl intvl, taddr_t Addr) {
  return addr_intvl_contains(intvl, Addr);
}

constexpr bool addr_intvl_disjoint(addr_intvl x, addr_intvl y) {
  return !addr_intvl_intersects(x, y);
}

constexpr addr_intvl addr_intvl_hull(addr_intvl x, addr_intvl y) {
  taddr_t L_1 = addr_intvl_lower(x);
  taddr_t L_2 = addr_intvl_lower(y);

  taddr_t U_1 = addr_intvl_upper(x);
  taddr_t U_2 = addr_intvl_upper(y);

  return right_open_addr_intvl(std::min(L_1, L_2), std::max(U_1, U_2));
}

template <typename OrderedIntvlMap, typename T>
constexpr auto intvl_map_find(OrderedIntvlMap &map, T x) {
  if (unlikely(map.empty()))
    return map.end();

  auto it = map.upper_bound(x);

  if (it != map.end() && addr_intvl_intersects((*it).first, x))
    return it;

  if (it == map.begin())
    return map.end();

  --it;

  if (addr_intvl_intersects((*it).first, x))
    return it;

  return map.end();
}

template <typename OrderedIntvlMap, typename T>
constexpr bool intvl_map_contains(OrderedIntvlMap &map, T x) {
  return intvl_map_find(map, x) != map.end();
}

template <typename OrderedIntvlMap, typename Value>
constexpr auto intvl_map_add(OrderedIntvlMap &map,
                             addr_intvl intvl,
                             Value &&val) {
  auto x = map.insert(typename OrderedIntvlMap::value_type(intvl, std::move(val)));

  assert(x.second);
  return x.first;
}

template <typename OrderedIntvlMap>
constexpr void intvl_map_clear(OrderedIntvlMap &map, addr_intvl intvl) {
  const taddr_t L2 = addr_intvl_lower(intvl);
  const taddr_t U2 = addr_intvl_upper(intvl);

  for (;;) {
    auto it = intvl_map_find(map, intvl);
    if (it == map.end())
      break;

    auto val = (*it).second;

    const taddr_t L1 = addr_intvl_lower((*it).first);
    const taddr_t U1 = addr_intvl_upper((*it).first);

    map.erase(it);

    if (L1 >= L2 && U1 <= U2) {
      //
      //   {   [    ]   }
      //   L2  L1  U1   U2
      //
      ;
    } else if (L1 <= L2 && U1 >= U2) {
      //
      //   [   {    }   ]
      //   L1  L2   U2  U1
      //
      if (L2 > L1) {
        addr_intvl left_intvl = right_open_addr_intvl(L1, L2);
        intvl_map_add(map, left_intvl, val);
      }
      if (U1 > U2) {
        addr_intvl right_intvl = right_open_addr_intvl(U2, U1);
        intvl_map_add(map, right_intvl, val);
      }
    } else if (L1 < L2 && U1 > L2 && U1 <= U2) {
      //
      //   [   {    ]   }
      //   L1  L2   U1  U2
      //
      addr_intvl new_intvl = right_open_addr_intvl(L1, L2);
      intvl_map_add(map, new_intvl, val);
    } else if (L1 >= L2 && L1 < U2 && U1 > U2) {
      //
      //   {   [    }   ]
      //   L2  L1   U2  U1
      //
      addr_intvl new_intvl = right_open_addr_intvl(U2, U1);
      intvl_map_add(map, new_intvl, val);
    } else {
      abort();
    }
  }
}

template <typename OrderedIntvlMap>
constexpr void intvl_map_clear_all(OrderedIntvlMap &map, addr_intvl intvl) {
  for (;;) {
    auto it = intvl_map_find(map, intvl);
    if (it == map.end())
      break;
    else
      map.erase(it);
  }
}

template <typename OrderedIntvlSet, typename T>
constexpr auto intvl_set_find(OrderedIntvlSet &set, T x) {
  if (unlikely(set.empty()))
    return set.end();

  auto it = set.upper_bound(x);

  if (it != set.end() && addr_intvl_intersects(*it, x))
    return it;

  if (it == set.begin())
    return set.end();

  --it;

  if (addr_intvl_intersects(*it, x))
    return it;

  return set.end();
}

template <typename OrderedIntvlSet, typename T>
constexpr bool intvl_set_contains(OrderedIntvlSet &set, T x) {
  return intvl_set_find(set, x) != set.end();
}

template <typename OrderedIntvlSet, typename T>
constexpr void intvl_set_add(OrderedIntvlSet &set, T intvl) {
  auto h = intvl;
  for (;;) {
    auto it = intvl_set_find(set, intvl);
    if (it == set.end()) {
      break;
    } else {
      h = addr_intvl_hull(h, *it);
      set.erase(it);
    }
  }

  bool success = set.insert(h).second;
  (void)success;
}
