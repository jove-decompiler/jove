#if (defined(__x86_64__) || defined(__i386__)) &&                              \
    (defined(TARGET_X86_64) || defined(TARGET_I386))
#include "sideband.h"
#include <cstdio>
#include <cinttypes>
#include <tuple>
#include <boost/algorithm/string.hpp>
#include <boost/unordered/unordered_flat_map.hpp>
#include <boost/unordered/unordered_map.hpp>

namespace jove {
namespace perf {

template <bool TID, bool TIME, bool ID, bool STREAM_ID, bool CPU,
          bool IDENTIFIER>
static unsigned do_read_samples(const uint8_t *const begin,
                                struct pev_event &out,
                                const pev_config &the_pev_config) {
  auto &sample = out.sample;

  const uint8_t *pos = begin;
  if constexpr (TID) {
    sample.pid = reinterpret_cast<const uint32_t *>(&pos[0]);
    sample.tid = reinterpret_cast<const uint32_t *>(&pos[4]);
    pos += 8;
  }

  if constexpr (TIME) {
    sample.time = reinterpret_cast<const uint64_t *>(pos);
    pos += 8;

    int errcode = pev_time_to_tsc(&sample.tsc, *sample.time, &the_pev_config);
    assert(errcode == 0);
  }

  if constexpr (ID) {
    sample.id = reinterpret_cast<const uint64_t *>(pos);
    pos += 8;
  }

  if constexpr (STREAM_ID) {
    sample.stream_id = reinterpret_cast<const uint64_t *>(pos);
    pos += 8;
  }

  if constexpr (CPU) {
    sample.cpu = reinterpret_cast<const uint32_t *>(pos);
    pos += 8;
  }

  if constexpr (IDENTIFIER) {
    sample.identifier = reinterpret_cast<const uint64_t *>(pos);
    pos += 8;
  }

  return pos - begin;
};

typedef boost::unordered_flat_map<
    std::tuple<bool, bool, bool, bool, bool, bool>, read_samples_t>
    read_samples_map_t;

#define SAMPLES_PROC_ENTRY(...)                                                \
  read_samples_map_t::value_type(read_samples_map_t::key_type(__VA_ARGS__),    \
                                 do_read_samples<__VA_ARGS__>)

static const read_samples_map_t read_samples_map = {
    SAMPLES_PROC_ENTRY(true, true, true, true, true, true),
    SAMPLES_PROC_ENTRY(true, true, false, false, true, true)};

template <bool IDENTIFIER, bool IP, bool TID, bool TIME, bool ADDR, bool ID,
          bool STREAM, bool CPU, bool PERIOD, bool READ, bool CALLCHAIN,
          bool RAW>
static unsigned do_read_sample_samples(const uint8_t *const begin,
                                       struct pev_event &out,
                                       const pev_config &the_pev_config) {
  auto &sample = out.sample;
  const uint8_t *pos = begin;

  static_assert(IDENTIFIER, "read_sample_samples: bad (!IDENTIFIER)");
  if constexpr (IDENTIFIER) {
    sample.identifier = (const uint64_t *)pos;
    pos += 8;
  }

  if constexpr (IP) {
    sample.ip = (const uint64_t *)pos;
    pos += 8; /* skip */
  }

  if constexpr (TID) {
    sample.pid = (const uint32_t *)&pos[0];
    sample.tid = (const uint32_t *)&pos[4];
    pos += 8;
  }

  if constexpr (TIME) {
    sample.time = (const uint64_t *)pos;
    pos += 8;

    int errcode = pev_time_to_tsc(&sample.tsc, *sample.time, &the_pev_config);
    assert(errcode == 0);
  }

  if constexpr (ADDR) {
    pos += 8; /* skip */
  }

  if constexpr (ID) {
    sample.id = (const uint64_t *)pos;
    pos += 8;
  }

  if constexpr (STREAM) {
    sample.stream_id = (const uint64_t *)pos;
    pos += 8;
  }

  if constexpr (CPU) {
    sample.cpu = (const uint32_t *)pos;
    pos += 8;
  }

  if constexpr (PERIOD) {
    pos += 8; /* skip */
  }

  static_assert(!READ, "read_sample_samples: unimplemented (PERF_SAMPLE_READ)");

  if constexpr (CALLCHAIN) {
    pos += (*((const uint64_t *)pos) * 8); /* skip */
  }

  if constexpr (RAW) {
    const struct pev_record_raw *raw = (const struct pev_record_raw *)pos;
    out.record.raw = raw;
    pos += 4;
    pos += raw->size;
  }

  return pos - begin;
}

typedef boost::unordered_flat_map<
    std::tuple<bool, bool, bool, bool, bool, bool, bool, bool, bool, bool, bool,
               bool>,
    read_sample_samples_t>
    read_sample_samples_map_t;

#define SAMPLE_SAMPLES_PROC_ENTRY(...)                                         \
  read_sample_samples_map_t::value_type(                                       \
      read_sample_samples_map_t::key_type(__VA_ARGS__),                        \
      do_read_sample_samples<__VA_ARGS__>)

static const read_sample_samples_map_t read_sample_samples_map = {
    SAMPLE_SAMPLES_PROC_ENTRY(true, true, true, true, true, true, true, true,
                              true, false, true, true),
    SAMPLE_SAMPLES_PROC_ENTRY(true, true, true, true, false, false, false, true,
                              false, false, false, false),
    SAMPLE_SAMPLES_PROC_ENTRY(true, true, true, true, false, false, false, true,
                              true, false, false, true)};

sideband_parser::sideband_parser(const std::vector<std::string> &ptdump_args) {
  pev_config_init(&the_pev_config);

  for (unsigned idx = 0; idx < ptdump_args.size(); ++idx) {
    const std::string &arg = ptdump_args.at(idx++);
    const std::string &arga = ptdump_args.at(idx);

    if (arg[0] != '-' || arg[1] != '-')
      throw std::runtime_error("sideband_parser: unrecognized ptdump args");

    if (arg == "--pevent:sample-config") {
      std::vector<std::string> x;
      boost::algorithm::split(x, arga, boost::is_any_of(":"),
                              boost::token_compress_on);

      uint64_t id = std::stoull(x.at(0), nullptr, 0);
      uint64_t sample_type = std::stoull(x.at(1), nullptr, 0);
      std::string &name = x.at(2);

      if (id >= sb_info.stypes.size())
        sb_info.stypes.resize(id + 1);

      sb_sample_type_t &st = sb_info.stypes.at(id);
      st.identifier = id;
      st.sample_type = sample_type;
      st.name = std::move(name);
      try {
        st.read_sample_samples_proc =
            read_sample_samples_map.at(read_sample_samples_map_t::key_type(
                sample_type & PERF_SAMPLE_IDENTIFIER,
                sample_type & PERF_SAMPLE_IP,
                sample_type & PERF_SAMPLE_TID,
                sample_type & PERF_SAMPLE_TIME,
                sample_type & PERF_SAMPLE_ADDR,
                sample_type & PERF_SAMPLE_ID,
                sample_type & PERF_SAMPLE_STREAM_ID,
                sample_type & PERF_SAMPLE_CPU,
                sample_type & PERF_SAMPLE_PERIOD,
                sample_type & PERF_SAMPLE_READ,
                sample_type & PERF_SAMPLE_CALLCHAIN,
                sample_type & PERF_SAMPLE_RAW));
      } catch (const std::out_of_range) {
        fprintf(stderr, "%u %u %u %u %u %u %u %u %u %u %u %u\n",
              (unsigned)sample_type & PERF_SAMPLE_IDENTIFIER,
              (unsigned)sample_type & PERF_SAMPLE_IP,
              (unsigned)sample_type & PERF_SAMPLE_TID,
              (unsigned)sample_type & PERF_SAMPLE_TIME,
              (unsigned)sample_type & PERF_SAMPLE_ADDR,
              (unsigned)sample_type & PERF_SAMPLE_ID,
              (unsigned)sample_type & PERF_SAMPLE_STREAM_ID,
              (unsigned)sample_type & PERF_SAMPLE_CPU,
              (unsigned)sample_type & PERF_SAMPLE_PERIOD,
              (unsigned)sample_type & PERF_SAMPLE_READ,
              (unsigned)sample_type & PERF_SAMPLE_CALLCHAIN,
              (unsigned)sample_type & PERF_SAMPLE_RAW);
        exit(1);
      }

      try {
        st.read_samples_proc =
          read_samples_map.at(read_samples_map_t::key_type(
            sample_type & PERF_SAMPLE_TID,
            sample_type & PERF_SAMPLE_TIME,
            sample_type & PERF_SAMPLE_ID,
            sample_type & PERF_SAMPLE_STREAM_ID,
            sample_type & PERF_SAMPLE_CPU,
            sample_type & PERF_SAMPLE_IDENTIFIER));
      } catch (const std::out_of_range) {
        fprintf(stderr, "%u %u %u %u %u %u\n",
          (unsigned)sample_type & PERF_SAMPLE_TID,
          (unsigned)sample_type & PERF_SAMPLE_TIME,
          (unsigned)sample_type & PERF_SAMPLE_ID,
          (unsigned)sample_type & PERF_SAMPLE_STREAM_ID,
          (unsigned)sample_type & PERF_SAMPLE_CPU,
          (unsigned)sample_type & PERF_SAMPLE_IDENTIFIER);
        exit(1);
      }

#if 0
      fprintf(stderr, "sample-config(%" PRIu64 ", %" PRIx64 ", \"%s\")\n",
              st.identifier, st.sample_type, st.name.c_str());
#endif

      sb_info.sample_type = sample_type;
    } else if (arg == "--pevent:time-shift") {
      the_pev_config.time_shift = std::stoull(arga, nullptr, 0);
    } else if (arg == "--pevent:time-mult") {
      the_pev_config.time_mult = std::stoull(arga, nullptr, 0);
    } else if (arg == "--pevent:time-zero") {
      the_pev_config.time_zero = std::stoull(arga, nullptr, 0);
    } else {
      continue;
    }
  }
}

unsigned sideband_parser::handle_read_samples(const uint8_t *const begin,
                                              const uint8_t *const end,
                                              struct pev_event &out) const {
  auto &sample = out.sample;

  const uint64_t *pidentifier = nullptr;
  const uint8_t *pos = (end - sizeof(*pidentifier));

  assert(begin <= pos);
  pidentifier = reinterpret_cast<const uint64_t *>(pos);

  assert(pidentifier);
  //HumanOut() << "id=" << *pidentifier << '\n';
  const uint64_t id = *pidentifier;
  const sb_sample_type_t &the_sample_type = sb_info.stypes.at(id);

  return the_sample_type.read_samples_proc(begin, out, the_pev_config);
}

__attribute__((always_inline))
unsigned
sideband_parser::handle_read_sample_samples(const uint8_t *const begin,
                                            struct pev_event &out) const {
  auto &sample = out.sample;

  const uint64_t *const pidentifier =
      (const uint64_t *)begin; /* XXX assumes PERF_SAMPLE_IDENTIFIER */

  const uint64_t id = *pidentifier;
  const perf::sb_sample_type_t &the_sample_type = sb_info.stypes.at(id);
  if (unlikely(id != the_sample_type.identifier))
    throw std::runtime_error("bad sample type");

  out.name = the_sample_type.name.c_str();

  return the_sample_type.read_sample_samples_proc(begin, out, the_pev_config);
}

static int pev_strlen(const char *begin, const void *end_arg) {
  const char *pos, *end;

  end = (const char *)end_arg;
  assert(end >= begin);

  for (pos = begin; pos < end; ++pos) {
    if (!pos[0])
      return (int)(pos - begin) + 1;
  }

  return -1;
}

void sideband_parser::load(struct pev_event &out,
                           const struct perf_event_header &hdr) const {
  int slen;
#ifndef NDEBUG
  __builtin_memset(&out, 0, sizeof(out));
#endif

  unsigned type = hdr.type;

  out.type = type;
  out.misc = hdr.misc;

  const uint8_t *const begin = reinterpret_cast<const uint8_t *>(&hdr);
  const uint8_t *const end = begin + hdr.size;
  const uint8_t *pos = begin + sizeof(struct perf_event_header);

  //
  // we know better than the compiler.
  //
  static constexpr unsigned MAXNR = std::max({
  PERF_RECORD_MMAP,
  PERF_RECORD_MMAP2,
  PERF_RECORD_LOST,
  PERF_RECORD_COMM,
  PERF_RECORD_EXIT,
  PERF_RECORD_THROTTLE,
  PERF_RECORD_UNTHROTTLE,
  PERF_RECORD_FORK,
  PERF_RECORD_AUX,
  PERF_RECORD_ITRACE_START,
  PERF_RECORD_LOST_SAMPLES,
  PERF_RECORD_SWITCH,
  PERF_RECORD_SWITCH_CPU_WIDE,
  PERF_RECORD_SAMPLE});
  static constexpr unsigned SZ = 1 << 7;
  static_assert(SZ > MAXNR);

#define JUMP_TABLE_BASE_LABEL do_unknown
#if 1
#define REF(Name) &&do_##Name
#else
#define REF(Name)                                                              \
  static_cast<int>(reinterpret_cast<const uint8_t *>(&&do_##Name) -            \
                   reinterpret_cast<const uint8_t *>(&&JUMP_TABLE_BASE_LABEL))
#endif
#define ENTRY(Name) [PERF_RECORD_##Name] = REF(Name)

#if 1
  typedef void *const jumps_elem_t;
#else
  typedef int jumps_elem_t;
#endif

  static const jumps_elem_t jumps[SZ] = {
      [0 ... SZ - 1] = REF(unknown),
      ENTRY(MMAP),
      ENTRY(MMAP2),
      ENTRY(LOST),
      ENTRY(COMM),
      ENTRY(EXIT),
      ENTRY(THROTTLE),
      ENTRY(UNTHROTTLE),
      ENTRY(FORK),
      ENTRY(AUX),
      ENTRY(ITRACE_START),
      ENTRY(LOST_SAMPLES),
      ENTRY(SWITCH),
      ENTRY(SWITCH_CPU_WIDE),
      ENTRY(SAMPLE)
  };

#undef ENTRY

  assert(type < SZ);
  type &= (SZ - 1u);
#if 1
  goto *jumps[type];
#else
  int offset = jumps[type];
  const void *ptr = reinterpret_cast<const void *>(
      reinterpret_cast<const uint8_t *>(&&JUMP_TABLE_BASE_LABEL) + offset);
  goto *ptr;
#endif

do_unknown:
    return;

  do_MMAP:
    out.record.mmap = reinterpret_cast<const struct pev_record_mmap *>(pos);

    slen = pev_strlen(out.record.mmap->filename, end);
    assert(slen >= 0);
    slen = (slen + 7) & ~7;

    pos += sizeof(struct pev_record_mmap);
    pos += slen;
    pos += handle_read_samples(pos, end, out);
    goto out;

  do_MMAP2:
    out.record.mmap2 = reinterpret_cast<const struct pev_record_mmap2 *>(pos);

    slen = pev_strlen(out.record.mmap2->filename, end);
    assert(slen >= 0);
    slen = (slen + 7) & ~7;

    pos += sizeof(struct pev_record_mmap2);
    pos += slen;
    pos += handle_read_samples(pos, end, out);
    goto out;

  do_LOST:
    out.record.lost = reinterpret_cast<const struct pev_record_lost *>(pos);
    pos += sizeof(struct pev_record_lost);
    pos += handle_read_samples(pos, end, out);
    goto out;

  do_COMM:
    out.record.comm = reinterpret_cast<const struct pev_record_comm *>(pos);

    slen = pev_strlen(out.record.comm->comm, end);
    assert(slen >= 0);

    slen = (slen + 7) & ~7;

    pos += sizeof(struct pev_record_comm);
    pos += slen;
    pos += handle_read_samples(pos, end, out);
    goto out;

  do_EXIT:
    out.record.exit = reinterpret_cast<const struct pev_record_exit *>(pos);
    pos += sizeof(struct pev_record_exit);
    pos += handle_read_samples(pos, end, out);
    goto out;

  do_THROTTLE:
  do_UNTHROTTLE:
    out.record.throttle = reinterpret_cast<const struct pev_record_throttle *>(pos);

    pos += sizeof(struct pev_record_throttle);
    pos += handle_read_samples(pos, end, out);
    goto out;

  do_FORK:
    out.record.fork = reinterpret_cast<const struct pev_record_fork *>(pos);
    pos += sizeof(struct pev_record_fork);
    pos += handle_read_samples(pos, end, out);
    goto out;

  do_AUX:
    out.record.aux = reinterpret_cast<const struct pev_record_aux *>(pos);
    pos += sizeof(struct pev_record_aux);
    pos += handle_read_samples(pos, end, out);
    goto out;

  do_ITRACE_START:
    out.record.itrace_start = reinterpret_cast<const struct pev_record_itrace_start *>(pos);
    pos += sizeof(struct pev_record_itrace_start);
    pos += handle_read_samples(pos, end, out);
    goto out;

  do_LOST_SAMPLES:
    out.record.lost_samples = reinterpret_cast<const struct pev_record_lost_samples *>(pos);
    pos += sizeof(struct pev_record_lost_samples);
    pos += handle_read_samples(pos, end, out);
    goto out;

  do_SWITCH:
    pos += handle_read_samples(pos, end, out);
    goto out;

  do_SWITCH_CPU_WIDE:
    out.record.switch_cpu_wide = reinterpret_cast<const struct pev_record_switch_cpu_wide *>(pos);
    pos += sizeof(struct pev_record_switch_cpu_wide);
    pos += handle_read_samples(pos, end, out);
    goto out;

  do_SAMPLE:
    pos += handle_read_sample_samples(pos, out);
    assert(out.record.raw);
    goto out;

out:
  assert(pos - begin == hdr.size);
}

}
}
#endif /* x86 */
