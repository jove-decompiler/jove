#include "sideband.h"
#include <cstdio>
#include <cinttypes>
#include <boost/algorithm/string.hpp>

namespace jove {
namespace perf {

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

unsigned sideband_parser::read_samples(const uint8_t *const begin,
                                       const uint8_t *const end,
                                       struct pev_event &out) const {
  auto &sample = out.sample;

  const uint64_t *pidentifier = nullptr;
  const uint8_t *pos = (end - sizeof(*pidentifier));

  if (begin <= pos)
    pidentifier = reinterpret_cast<const uint64_t *>(pos);

  assert(pidentifier);
  //HumanOut() << "id=" << *pidentifier << '\n';
  const uint64_t id = *pidentifier;
  const sb_sample_type_t &the_sample_type = sb_info.stypes.at(id);
  const uint64_t sample_type = the_sample_type.identifier == id
                                   ? the_sample_type.sample_type
                                   : sb_info.sample_type;

  pos = begin;

  if (sample_type & PERF_SAMPLE_TID) {
    sample.pid = reinterpret_cast<const uint32_t *>(&pos[0]);
    sample.tid = reinterpret_cast<const uint32_t *>(&pos[4]);
    pos += 8;
  }

  if (sample_type & PERF_SAMPLE_TIME) {
    sample.time = reinterpret_cast<const uint64_t *>(pos);
    pos += 8;

    int errcode = pev_time_to_tsc(&sample.tsc, *sample.time, &the_pev_config);
    if (errcode < 0)
      throw std::runtime_error(__func__ +
                               std::string(": pev_time_to_tsc failed"));
  }

  if (sample_type & PERF_SAMPLE_ID) {
    sample.id = reinterpret_cast<const uint64_t *>(pos);
    pos += 8;
  }

  if (sample_type & PERF_SAMPLE_STREAM_ID) {
    sample.stream_id = reinterpret_cast<const uint64_t *>(pos);
    pos += 8;
  }

  if (sample_type & PERF_SAMPLE_CPU) {
    sample.cpu = reinterpret_cast<const uint32_t *>(pos);
    pos += 8;
  }

  if (sample_type & PERF_SAMPLE_IDENTIFIER) {
    sample.identifier = reinterpret_cast<const uint64_t *>(pos);
    pos += 8;
  }

  return pos - begin;
};

unsigned sideband_parser::read_sample_samples(const uint8_t *const begin,
                                              struct pev_event &out) const {
  auto &sample = out.sample;

  const uint64_t *const pidentifier =
      (const uint64_t *)begin; /* XXX assumes PERF_SAMPLE_IDENTIFIER */

  const uint64_t id = *pidentifier;
  const perf::sb_sample_type_t &the_sample_type = sb_info.stypes.at(id);
  if (id != the_sample_type.identifier)
    throw std::runtime_error("bad sample type");

  const uint64_t sample_type = the_sample_type.sample_type;
  out.name = the_sample_type.name.c_str();

  const uint8_t *pos = begin;

  if (sample_type & PERF_SAMPLE_IDENTIFIER) {
    sample.identifier = (const uint64_t *)pos;
    pos += 8;
  } else {
    throw std::runtime_error("bad sample");
  }

  if (sample_type & PERF_SAMPLE_IP) {
    sample.ip = (const uint64_t *)pos;
    pos += 8; /* skip */
  }

  if (sample_type & PERF_SAMPLE_TID) {
    sample.pid = (const uint32_t *)&pos[0];
    sample.tid = (const uint32_t *)&pos[4];
    pos += 8;
  }

  if (sample_type & PERF_SAMPLE_TIME) {
    sample.time = (const uint64_t *)pos;
    pos += 8;

    int errcode = pev_time_to_tsc(&sample.tsc, *sample.time, &the_pev_config);
    if (errcode < 0)
      throw std::runtime_error(__func__ +
                               std::string(": pev_time_to_tsc failed"));
  }

  if (sample_type & PERF_SAMPLE_ADDR) {
    pos += 8; /* skip */
  }

  if (sample_type & PERF_SAMPLE_ID) {
    sample.id = (const uint64_t *)pos;
    pos += 8;
  }

  if (sample_type & PERF_SAMPLE_STREAM_ID) {
    sample.stream_id = (const uint64_t *)pos;
    pos += 8;
  }

  if (sample_type & PERF_SAMPLE_CPU) {
    sample.cpu = (const uint32_t *)pos;
    pos += 8;
  }

  if (sample_type & PERF_SAMPLE_PERIOD) {
    pos += 8; /* skip */
  }

  if (sample_type & PERF_SAMPLE_READ) {
    throw std::runtime_error(
        "read_sample_samples: unimplemented (PERF_SAMPLE_READ)");
  }

  if (sample_type & PERF_SAMPLE_CALLCHAIN) {
    pos += (*((const uint64_t *)pos) * 8); /* skip */
  }

  if (sample_type & PERF_SAMPLE_RAW) {
    const struct pev_record_raw *raw = (const struct pev_record_raw *)pos;
    out.record.raw = raw;
    pos += 4;
    pos += raw->size;
  }

  return pos - begin;
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
  __builtin_memset(&out, 0, sizeof(out));

  auto type = hdr.type;

  out.type = type;
  out.misc = hdr.misc;

  const uint8_t *const begin = reinterpret_cast<const uint8_t *>(&hdr);
  const uint8_t *const end = begin + hdr.size;
  const uint8_t *pos = begin + sizeof(struct perf_event_header);

  switch (type) {
  case PERF_RECORD_MMAP: {
    const auto &rec = *(out.record.mmap = reinterpret_cast<const struct pev_record_mmap *>(pos));

    int slen = pev_strlen(rec.filename, end);
    assert(slen >= 0);
    slen = (slen + 7) & ~7;

    pos += sizeof(struct pev_record_mmap);
    pos += slen;
    pos += read_samples(pos, end, out);
    break;
  }
  case PERF_RECORD_MMAP2: {
    const auto &rec = *(out.record.mmap2 = reinterpret_cast<const struct pev_record_mmap2 *>(pos));

    int slen = pev_strlen(rec.filename, end);
    assert(slen >= 0);
    slen = (slen + 7) & ~7;

    pos += sizeof(struct pev_record_mmap2);
    pos += slen;
    pos += read_samples(pos, end, out);
    break;
  }

  case PERF_RECORD_LOST: {
    const auto &rec = *(out.record.lost = reinterpret_cast<const struct pev_record_lost *>(pos));
    pos += sizeof(struct pev_record_lost);
    pos += read_samples(pos, end, out);
    break;
  }

  case PERF_RECORD_COMM: {
    const auto &rec = *(out.record.comm = reinterpret_cast<const struct pev_record_comm *>(pos));

    int slen;

    slen = pev_strlen(rec.comm, end);
    assert(slen >= 0);

    slen = (slen + 7) & ~7;

    pos += sizeof(struct pev_record_comm);
    pos += slen;
    pos += read_samples(pos, end, out);
    break;
  }

  case PERF_RECORD_EXIT: {
    const auto &rec = *(out.record.exit = reinterpret_cast<const struct pev_record_exit *>(pos));
    pos += sizeof(struct pev_record_exit);
    pos += read_samples(pos, end, out);
    break;
  }

  case PERF_RECORD_THROTTLE: {
  case PERF_RECORD_UNTHROTTLE:
    const auto &rec = *(out.record.throttle = reinterpret_cast<const struct pev_record_throttle *>(pos));

    pos += sizeof(struct pev_record_throttle);
    pos += read_samples(pos, end, out);
    break;
  }

  case PERF_RECORD_FORK: {
    const auto &rec = *(out.record.fork = reinterpret_cast<const struct pev_record_fork *>(pos));
    pos += sizeof(struct pev_record_fork);
    pos += read_samples(pos, end, out);
    break;
  }

  case PERF_RECORD_AUX: {
    const auto &rec = *(out.record.aux = reinterpret_cast<const struct pev_record_aux *>(pos));
    pos += sizeof(struct pev_record_aux);
    pos += read_samples(pos, end, out);
    break;
  }

  case PERF_RECORD_ITRACE_START: {
    const auto &rec = *(out.record.itrace_start = reinterpret_cast<const struct pev_record_itrace_start *>(pos));
    pos += sizeof(struct pev_record_itrace_start);
    pos += read_samples(pos, end, out);
    break;
  }

  case PERF_RECORD_LOST_SAMPLES: {
    const auto &rec = *(out.record.lost_samples = reinterpret_cast<const struct pev_record_lost_samples *>(pos));
    pos += sizeof(struct pev_record_lost_samples);
    pos += read_samples(pos, end, out);
    break;
  }

  case PERF_RECORD_SWITCH: {
    pos += read_samples(pos, end, out);
    break;
  }

  case PERF_RECORD_SWITCH_CPU_WIDE: {
    const auto &rec = *(out.record.switch_cpu_wide = reinterpret_cast<const struct pev_record_switch_cpu_wide *>(pos));
    pos += sizeof(struct pev_record_switch_cpu_wide);
    pos += read_samples(pos, end, out);
    break;
  }

  case PERF_RECORD_SAMPLE: {
    pos += read_sample_samples(pos, out);
    assert(out.record.raw);
    break;
  }

  default:
    return;
  }

  if (pos - begin != hdr.size)
    throw std::runtime_error("invalid sideband");
}
}
}
