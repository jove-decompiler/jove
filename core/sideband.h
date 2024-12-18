#pragma once
#if defined(__x86_64__) && (defined(TARGET_X86_64) || defined(TARGET_I386))
#include "perf.h"

#include <functional>

extern "C" {
#include "pevent.h"
}

namespace jove {
namespace perf {

typedef unsigned (*read_sample_samples_t)(const uint8_t *const,
                                          struct pev_event &,
                                          const pev_config &);
typedef unsigned (*read_samples_t)(const uint8_t *const, struct pev_event &,
                                   const pev_config &);

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

  read_sample_samples_t read_sample_samples_proc;
  read_samples_t read_samples_proc;
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

  pev_config the_pev_config;

public:
  sideband_parser(const std::vector<std::string> &ptdump_args);

  void load(struct pev_event &out, const struct perf_event_header &hdr) const;

private:
  __attribute__((always_inline))
  unsigned handle_read_sample_samples(const uint8_t *const begin,
                                      struct pev_event &) const;
  unsigned handle_read_samples(const uint8_t *const begin,
                               const uint8_t *const end,
                               struct pev_event &out) const;
};

}
}
#endif /* x86 */
