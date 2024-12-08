#pragma once
#include "perf.h"

extern "C" {
#include "pevent.h"
}

namespace jove {
namespace perf {

struct sb_sample_type_t {
  /* The sample identifier.
   *
   * This corresponds to the PERF_SAMPLE_IDENTIFIER sample that can be
   * found at the very end of the event record.
   */
  uint64_t identifier = UINT64_MAX;

  /* The sample type.
   *
   * At least PERF_SAMPLE_IDENTIFIER must be set.
   */
  uint64_t sample_type;

  std::string name;
};

struct sb_info_t {
  /* The respective field in struct perf_event_attr.
   *
   * We require sample_id_all in struct perf_event_attr to be set.
   *
   * This field is only valid if \@sample_config is NULL.
   */
  uint64_t sample_type = 0;

  /* An array of \@nstypes sample types. */
  std::vector<sb_sample_type_t> stypes;
};

class sideband_parser {
  sb_info_t sb_info;

public:
  sideband_parser(const std::vector<std::string> &ptdump_args);

  void load(struct pev_event &out, const struct perf_event_header &hdr) const;

private:
  unsigned read_samples(const uint8_t *const begin,
                        const uint8_t *const end, struct pev_event &out) const;
  unsigned read_sample_samples(const uint8_t *const begin,
                               struct pev_event &out) const;
};

}
}
