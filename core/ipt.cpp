#if defined(__x86_64__) || defined(__i386__) /* x86 only */

#include "ipt.h"
#include <intel-pt.h>
#include <inttypes.h>
#if 0
#include <libipt-sb.h>
#endif

extern "C" {
#include "pt_last_ip.c" /* XXX why isn't this exported by libipt?? */
}

namespace jove {

IntelPT::IntelPT(jv_t &jv, void *begin, void *end) : jv(jv) {
  config = std::make_unique<struct pt_config>();
  pt_config_init(config.get());

  config->begin = reinterpret_cast<uint8_t *>(begin);
  config->end = reinterpret_cast<uint8_t *>(end);

#if 0
  //pt_cpu_errata(...);
  //pt_sb_init_decoders(&session);
#endif

  decoder = pt_pkt_alloc_decoder(config.get());

  last_ip = std::make_unique<struct pt_last_ip>();

#if 0
  session = pt_sb_alloc(NULL);
  if (!session)
    throw std::runtime_error("failed to allocate sideband session");
#endif
}

IntelPT::~IntelPT() {
  pt_pkt_free_decoder(decoder);
}

int IntelPT::visit_all(/*FIXME*/) {
  int errcode;

  if (0 /* options->no_sync */) {
    errcode = pt_pkt_sync_set(decoder, 0ull);
    if (errcode < 0)
      throw std::runtime_error(std::string("IntelPT: sync error: ") +
                               pt_errstr(pt_errcode(errcode)));
  } else {
    errcode = pt_pkt_sync_forward(decoder);
    if (errcode < 0) {
      if (errcode == -pte_eos)
        return 0;

      throw std::runtime_error(std::string("IntelPT: sync error: ") +
                               pt_errstr(pt_errcode(errcode)));
    }
  }

  for (;;) {
    errcode = visit_packets();
    if (unlikely(!errcode))
      break;

    errcode = pt_pkt_sync_forward(decoder);
    if (unlikely(errcode < 0)) {
      if (errcode == -pte_eos)
        return 0;

      throw std::runtime_error(std::string("IntelPT: sync error: ") +
                               pt_errstr(pt_errcode(errcode)));
    }

    //ptdump_tracking_reset(tracking);
  }

  return errcode;
}

int IntelPT::visit_packets(/*FIXME*/) {
  uint64_t offset;
  int errcode;

  offset = 0ull;
  for (;;) {
    struct pt_packet packet;

    errcode = pt_pkt_get_offset(decoder, &offset);
    if (unlikely(errcode < 0))
      throw std::runtime_error(
          std::string("IntelPT: error getting offset: ") +
          pt_errstr(pt_errcode(errcode)));

    errcode = pt_pkt_next(decoder, &packet, sizeof(packet));
    if (unlikely(errcode < 0)) {
      if (errcode == -pte_eos)
        return 0;

      throw std::runtime_error(
          std::string("IntelPT: error decoding packet: ") +
          pt_errstr(pt_errcode(errcode)));
    }

    errcode = process_packet(offset, &packet);
    if (unlikely(errcode < 0))
      return errcode;
  }

  return 0;
}

int IntelPT::process_packet(uint64_t offset, const struct pt_packet *packet) {
  switch (packet->type) {
  case ppt_unknown:
  case ppt_invalid:
  case ppt_psb:
  case ppt_psbend:
  case ppt_pad:
  case ppt_ovf:
  case ppt_stop:
    return 0;

  case ppt_fup:
  case ppt_tip:
  case ppt_tip_pge:
  case ppt_tip_pgd:
    track_last_ip(&packet->payload.ip, offset);
    return 0;

  case ppt_pip:
  case ppt_vmcs:
    return 0;

  case ppt_tnt_8:
  case ppt_tnt_64:
    return tnt_payload(&packet->payload.tnt);

  case ppt_mode: {
    const struct pt_packet_mode *mode;

    mode = &packet->payload.mode;
    switch (mode->leaf) {
    case pt_mol_exec:
    case pt_mol_tsx:
      return 0;
    }

    throw std::runtime_error(
        std::string("IntelPT: unknown mode leaf at offset ") +
        std::to_string(offset));
  }

  case ppt_tsc:
  case ppt_cbr:
  case ppt_tma:
  case ppt_mtc:
  case ppt_cyc:
  case ppt_mnt:
  case ppt_exstop:
  case ppt_mwait:
  case ppt_pwre:
  case ppt_pwrx:
  case ppt_ptw:
    return 0;

#if (LIBIPT_VERSION >= 0x201)
  case ppt_cfe:
  case ppt_evd:
    return 0;
#endif /* (LIBIPT_VERSION >= 0x201) */

#if (LIBIPT_VERSION >= 0x202)
  case ppt_trig:
    return 0;
#endif /* (LIBIPT_VERSION >= 0x202) */
  }

  throw std::runtime_error(
      std::string("IntelPT: unknown packet at offset ") +
      std::to_string(offset));
}

int IntelPT::tnt_payload(const struct pt_packet_tnt *packet) {
  assert(packet);

  uint64_t tnt = packet->payload;
  uint8_t bits = packet->bit_size;
  assert(bits > 0);

  do {
    bool Taken = !!(tnt & (1ull << (bits - 1)));

    const char *extra = bits > 1 ? " " : "";
    printf("%d%s", (int)Taken, extra); /* FIXME */
  } while (--bits);

  printf("\n"); /* FIXME */

  return 0;
}

int IntelPT::track_last_ip(const struct pt_packet_ip *packet, uint64_t offset) {
  uint64_t ip;
  int errcode;

  //print_field(buffer->tracking.id, "ip");

  errcode = pt_last_ip_update_ip(last_ip.get(), packet, NULL);
  if (unlikely(errcode < 0)) {
    //print_field(buffer->tracking.payload, "<unavailable>");

    throw std::runtime_error(
        std::string("IntelPT: error tracking last-ip at offset ") +
        std::to_string(offset));
  }

  errcode = pt_last_ip_query(&ip, last_ip.get());
  if (unlikely(errcode < 0)) {
    if (errcode == -pte_ip_suppressed) {
      //print_field(buffer->tracking.payload, "<suppressed>");
    } else {
      //print_field(buffer->tracking.payload, "<unavailable>");

      throw std::runtime_error(
          std::string("IntelPT: error tracking last-ip at offset ") +
          std::to_string(offset));
    }
  } else {
    //print_field(buffer->tracking.payload, "%016" PRIx64, ip);
    printf("%016" PRIx64 "\n", ip); /* FIXME */
  }

  return 0;
}
}

#endif /* x86 */
