#if defined(__x86_64__) && (defined(TARGET_X86_64) || defined(TARGET_I386))
#pragma once
#include "ipt.h"

namespace jove {

template <IPT_PARAMETERS_DCL> struct reference_ipt_t;

template <IPT_PARAMETERS_DCL>
struct ipt_traits<reference_ipt_t<IPT_PARAMETERS_DEF>> {
  using packet_type = struct pt_packet;
};

template <IPT_PARAMETERS_DCL>
struct reference_ipt_t
    : public ipt_t<IPT_PARAMETERS_DEF, reference_ipt_t<IPT_PARAMETERS_DEF>> {
#define IsVerbose() (Verbosity >= 1)
#define IsVeryVerbose() (Verbosity >= 2)

  typedef ipt_t<IPT_PARAMETERS_DEF, reference_ipt_t<IPT_PARAMETERS_DEF>> Base;

  using packet_type = Base::packet_type;

  struct pt_packet_decoder *decoder = NULL;

  template <typename... Args>
  reference_ipt_t(Args &&...args) : Base(std::forward<Args>(args)...) {
    decoder = pt_pkt_alloc_decoder(&this->config);
  }

  ~reference_ipt_t() { pt_pkt_free_decoder(decoder); }

  int ptdump_print_error(int errcode, const char *filename, uint64_t offset) {
    if (errcode >= 0 && false /* !options->print_sb_warnings */)
      return 0;

    if (!filename)
      filename = "<unknown>";

    const char *errstr = errcode < 0
                             ? pt_errstr(pt_errcode(errcode))
                             : pt_sb_errstr((enum pt_sb_error_code)errcode);

    if (!errstr)
      errstr = "<unknown error>";

    fprintf(stderr, "[%s:%016" PRIx64 " sideband error: %s]\n", filename,
            offset, errstr);

    return 0;
  }

  void packet_sync(packet_type &) {
    int errcode = pt_pkt_sync_forward(decoder);
    if (unlikely(errcode < 0)) {
      if (errcode == -pte_eos)
        throw end_of_trace_exception();

      throw std::runtime_error(std::string("reference_ipt: sync error: ") +
                               pt_errstr(pt_errcode(errcode)));
    }

    this->ptdump_tracking_reset();
  }

  uint64_t next_packet(packet_type &out) {
    uint64_t offset;

    int errcode = pt_pkt_get_offset(decoder, &offset);
    if (unlikely(errcode < 0))
      throw std::runtime_error(
          std::string("reference_ipt: error getting offset: ") +
          pt_errstr(pt_errcode(errcode)));

    errcode = pt_pkt_next(decoder, &out, sizeof(out));
    if (unlikely(errcode < 0)) {
      if (errcode == -pte_eos)
        throw end_of_trace_exception();

      if constexpr (IsVerbose())
        fprintf(stderr, "reference_ipt: error decoding packet: %s\n",
                pt_errstr(pt_errcode(errcode)));
      throw error_decoding_exception();
    }

    return offset;
  }

  template <bool IsEngaged>
  void process_packets(uint64_t offset, packet_type &packet) {
    auto type = packet.type;

#if 0
    if constexpr (!IsVerbose())
      fprintf(stdout, "%016" PRIx64 "\t%u\n", offset, (unsigned)type);
#endif

    switch (type) {
    case ppt_unknown:
    case ppt_invalid:
      break;

    case ppt_psb:
      if (1 /* options->track_time */) {
        int errcode;

        errcode = pt_tcal_update_psb(&this->tracking.tcal, &this->config);
        if (unlikely(errcode < 0)) {
          if constexpr (IsVerbose())
            fprintf(stderr, "%s: error calibrating time", __PRETTY_FUNCTION__);
        }
      }

      this->tracking.in_header = 1;
      break;

    case ppt_psbend:
      this->tracking.in_header = 0;
      break;

    case ppt_pad:
      break;

    case ppt_ovf:
      if (0 /* options->keep_tcal_on_ovf */) {
        int errcode;

        errcode = pt_tcal_update_ovf(&this->tracking.tcal, &this->config);
        if (unlikely(errcode < 0)) {
          if constexpr (IsVerbose())
            fprintf(stderr, "%s: error calibrating time", __PRETTY_FUNCTION__);
        }
      } else {
        pt_tcal_init(&this->tracking.tcal);
      }
      break;

    case ppt_stop:
      break;

    case ppt_fup:
    case ppt_tip:
    case ppt_tip_pge:
    case ppt_tip_pgd: {
      uint64_t IP = this->track_ip(offset, packet.payload.ip);
      if constexpr (IsEngaged) {
        if (likely(IP))
          this->on_ip(IP, offset);
        else
          this->CurrPoint.Invalidate();
      } else {
        if constexpr (IsVeryVerbose())
          if (this->RightProcess())
            fprintf(stderr, "%016" PRIx64 "\t__IP %016" PRIx64 "\n", offset,
                    (uint64_t)IP);
      }
      break;
    }

    case ppt_pip: /* we'll never see this in userspace */
    case ppt_vmcs:
      break;

    case ppt_tnt_8:
    case ppt_tnt_64:
      if constexpr (IsEngaged)
        tnt_payload(packet.payload.tnt, offset);
      break;

    case ppt_mode:
      this->handle_mode(packet.payload.mode, offset);
      IPT_PROCESS_GTFO_IF_ENGAGED_CHANGED(IsEngaged);
      break;

    case ppt_tsc:
      this->track_tsc(offset, &packet.payload.tsc);
      IPT_PROCESS_GTFO_IF_ENGAGED_CHANGED(IsEngaged);
      break;

    case ppt_cbr:
      this->track_cbr(offset, &packet.payload.cbr);
      IPT_PROCESS_GTFO_IF_ENGAGED_CHANGED(IsEngaged);
      break;

    case ppt_tma:
      this->track_tma(offset, &packet.payload.tma);
      IPT_PROCESS_GTFO_IF_ENGAGED_CHANGED(IsEngaged);
      break;

    case ppt_mtc:
      this->track_mtc(offset, &packet.payload.mtc);
      IPT_PROCESS_GTFO_IF_ENGAGED_CHANGED(IsEngaged);
      break;

    case ppt_cyc:
      this->track_cyc(offset, &packet.payload.cyc);
      IPT_PROCESS_GTFO_IF_ENGAGED_CHANGED(IsEngaged);
      break;

    case ppt_mnt:
    case ppt_exstop:
    case ppt_mwait:
    case ppt_pwre:
    case ppt_pwrx:
    case ppt_ptw:
    case ppt_cfe:
    case ppt_evd:
    case ppt_trig:
      break;

    default:
      throw std::runtime_error(
          std::string("reference_ipt: unknown packet at offset ") +
          std::to_string(offset));
    }

    __attribute__((musttail)) return process_packets<IsEngaged>(
        next_packet(packet), packet);
  }

  void process_packets_engaged(uint64_t offset, packet_type &packet) {
    __attribute__((musttail)) return process_packets<true>(offset, packet);
  }

  void process_packets_unengaged(uint64_t offset, packet_type &packet) {
    __attribute__((musttail)) return process_packets<false>(offset, packet);
  }

  int tnt_payload(const struct pt_packet_tnt &packet, const uint64_t offset) {
    if (unlikely(!this->CurrPoint.Valid())) {
      if constexpr (IsVeryVerbose())
        fprintf(stderr, "%" PRIx64 "\tunhandled tnt\n", offset);
      return 1;
    }

    auto Saved = this->CurrPoint;
    try {
      this->TNTAdvance(packet.payload, packet.bit_size);

      assert(this->CurrPoint.Valid());
      return 1;
    } catch (const tnt_error &) {
      if constexpr (IsVerbose())
        fprintf(stderr, "tnt error from %s+%" PRIx64 "\n",
                Saved.Binary().Name.c_str(),
                static_cast<uint64_t>(Saved.GetAddr()));
    } catch (const infinite_loop_exception &) {
      if constexpr (IsVerbose())
        fprintf(stderr, "tnt error (infinite loop) from %s+%" PRIx64 "\n",
                Saved.Binary().Name.c_str(),
                static_cast<uint64_t>(Saved.GetAddr()));
    }

    this->CurrPoint.Invalidate();
    return 1;
  }

  int print_time(uint64_t offset) {
    uint64_t tsc;
    int errcode;

    errcode = pt_time_query_tsc(&tsc, NULL, NULL, &this->tracking.time);
    if (errcode < 0) {
      switch (-errcode) {
      case pte_no_time:
        if (0 /* options->no_wall_clock */)
          break;

      default:
        // diag("error printing time", offset, errcode);
        return errcode;
      }
    }

    fprintf(stderr, "tsc=%016" PRIx64 "\n", tsc);

    return 0;
  }

#undef IsVerbose
#undef IsVeryVerbose
};
} // namespace jove

#endif /* x86 */
