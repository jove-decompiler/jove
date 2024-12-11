#if defined(__x86_64__) && (defined(TARGET_X86_64) || defined(TARGET_I386))
#pragma once
#include "ipt.h"

extern "C" {
#include "pt_last_ip.h"
#include "pt_time.h"
// #include "pt_last_ip.c"
// #include "pt_time.c"
}

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

  struct pt_config config;
  struct pt_packet_decoder *decoder = NULL;

  struct {
    struct pt_last_ip last_ip;
    struct pt_time_cal tcal;
    struct pt_time time;

    uint64_t tsc = 0ull; /* The last estimated TSC. */
    uint64_t fcr = 0ull; /* The last calibration value. */

    uint32_t in_header = 0; /* Header vs. normal decode. */
  } tracking;

  template <typename... Args>
  reference_ipt_t(Args &&...args) : Base(std::forward<Args>(args)...) {
    setvbuf(stderr, NULL, _IOLBF, 0); /* automatically flush on new-line */

    pt_config_init(&config);
    ptdump_tracking_init();

    if (process_args(this->ptdump_argc, this->ptdump_argv) != 0)
      throw std::runtime_error("failed to process ptdump arguments");

    if (config.cpu.vendor) {
      int errcode = pt_cpu_errata(&config.errata, &config.cpu);
      if (errcode < 0)
        throw std::runtime_error("failed to determine errata");

      std::vector<uint8_t> zeros(sizeof(config.errata), 0);
      if (memcmp(&config.errata, &zeros[0], sizeof(config.errata)) != 0) {
        fprintf(stderr, "WARNING! CPU errata detected:");

#define __ERRATA(x)                                                            \
  do {                                                                         \
    if (config.errata.x)                                                       \
      fprintf(stderr, " " #x);                                                 \
  } while (false)

        __ERRATA(bdm70);
        __ERRATA(bdm64);
        __ERRATA(skd007);
        __ERRATA(skd022);
        __ERRATA(skd010);
        __ERRATA(skl014);
        __ERRATA(apl12);
        __ERRATA(apl11);
        __ERRATA(skl168);
        __ERRATA(skz84);

#undef __ERRATA

        fprintf(stderr, "\n");
      }
    }

    config.begin = const_cast<uint8_t *>(this->aux_begin);
    config.end = const_cast<uint8_t *>(this->aux_end);

    decoder = pt_pkt_alloc_decoder(&config);
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

  void packet_sync(void) {
    int errcode = pt_pkt_sync_forward(decoder);
    if (unlikely(errcode < 0)) {
      if (errcode == -pte_eos)
        throw end_of_trace_exception();

      throw std::runtime_error(std::string("reference_ipt: sync error: ") +
                               pt_errstr(pt_errcode(errcode)));
    }

    ptdump_tracking_reset();
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
#define GTFO_IF_ENGAGED_CHANGED()                                              \
  do {                                                                         \
    if constexpr (IsEngaged) {                                                 \
      if (!this->Engaged)                                                      \
        return;                                                                \
    } else {                                                                   \
      if (this->Engaged)                                                       \
        return;                                                                \
    }                                                                          \
  } while (false)

    switch (packet.type) {
    case ppt_unknown:
    case ppt_invalid:
      break;

    case ppt_psb:
      if (1 /* options->track_time */) {
        int errcode;

        errcode = pt_tcal_update_psb(&tracking.tcal, &config);
        if (unlikely(errcode < 0)) {
          if constexpr (IsVerbose())
            fprintf(stderr, "%s: error calibrating time", __PRETTY_FUNCTION__);
        }
      }

      tracking.in_header = 1;
      break;

    case ppt_psbend:
      tracking.in_header = 0;
      break;

    case ppt_pad:
      break;

    case ppt_ovf:
      if (0 /* options->keep_tcal_on_ovf */) {
        int errcode;

        errcode = pt_tcal_update_ovf(&tracking.tcal, &config);
        if (unlikely(errcode < 0)) {
          if constexpr (IsVerbose())
            fprintf(stderr, "%s: error calibrating time", __PRETTY_FUNCTION__);
        }
      } else {
        pt_tcal_init(&tracking.tcal);
      }
      break;

    case ppt_stop:
      break;

    case ppt_fup:
    case ppt_tip:
    case ppt_tip_pge:
    case ppt_tip_pgd: {
      int errcode;
      uint64_t IP;

      errcode =
          pt_last_ip_update_ip(&tracking.last_ip, &packet.payload.ip, &config);
      if (unlikely(errcode < 0))
        throw std::runtime_error(
            std::string("reference_ipt: error tracking last-ip at offset ") +
            std::to_string(offset));

      errcode = pt_last_ip_query(&IP, &tracking.last_ip);
      if (unlikely(errcode < 0)) {
        if (errcode == -pte_ip_suppressed) {
          if constexpr (IsEngaged) {
            if constexpr (IsVeryVerbose())
              fprintf(stderr, "<suppressed>\n");

            this->CurrPoint.Invalidate();
          }
        } else {
          throw std::runtime_error(
              std::string("reference_ipt: error tracking last-ip at offset ") +
              std::to_string(offset));
        }
      } else {
        if constexpr (IsEngaged) {
          this->on_ip(IP, offset);
        } else {
          if constexpr (IsVeryVerbose())
            if (this->RightProcess())
              fprintf(stderr, "%016" PRIx64 "\t__IP %016" PRIx64 "\n", offset,
                      (uint64_t)IP);
        }
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

    case ppt_mode: {
      const struct pt_packet_mode *mode = &packet.payload.mode;
      switch (mode->leaf) {
      case pt_mol_exec: {
        const auto SavedExecBits = this->Curr.ExecBits;
        switch (pt_get_exec_mode(&mode->bits.exec)) {
        case ptem_64bit:
          this->Curr.ExecBits = 64;
          break;

        case ptem_32bit:
          this->Curr.ExecBits = 32;
          break;

        case ptem_16bit:
          this->Curr.ExecBits = 16;
          break;

        case ptem_unknown:
          this->Curr.ExecBits = ~0u;
          break;
        }

        if constexpr (IsVeryVerbose())
          if (this->Curr.ExecBits != SavedExecBits)
            fprintf(stderr, "%016" PRIx64 "\tbits %u -> %u\n", offset,
                    SavedExecBits, this->Curr.ExecBits);

#if 0
      if (CheckEngaged()) {
      int errcode;

      //
      // look ahead and, if IP packet, deal with it but don't examine IP,
      // because IIRC (from reading libipt) whatever it is would have been
      // reachable anyway without examining the trace- plus it might be BOGUS.
      //
      offset = next_packet(packet);
      if (packet.type == ppt_fup) {
          errcode = pt_last_ip_update_ip(&tracking.last_ip,
                                         &packet.payload.ip, &config);
          if (unlikely(errcode < 0))
            throw std::runtime_error(
                std::string("reference_ipt: error tracking last-ip at offset ") +
                std::to_string(offset));

          if constexpr (IsVeryVerbose()) {
            uint64_t IP;
            if (pt_last_ip_query(&IP, &tracking.last_ip) >= 0)
              fprintf(stderr, "%016" PRIx64 "\tskipping IP %016" PRIx64 "\n", offset, (uint64_t)IP);
          }

          CurrPoint.Invalidate();
          break;
      }

      // process normally
      __attribute__((musttail)) return process_packets(offset, packet);
      } else
#endif
        break;
      }

      case pt_mol_tsx:
        // assuming this is followed by a mode.exec, there's nothing we need to
        // do
        break;

      default:
        throw std::runtime_error(
            std::string("reference_ipt: unknown mode leaf at offset ") +
            std::to_string(offset));
      }

      GTFO_IF_ENGAGED_CHANGED();
      break;
    }

    case ppt_tsc:
      track_tsc(offset, &packet.payload.tsc);
      GTFO_IF_ENGAGED_CHANGED();
      break;

    case ppt_cbr:
      track_cbr(offset, &packet.payload.cbr);
      GTFO_IF_ENGAGED_CHANGED();
      break;

    case ppt_tma:
      track_tma(offset, &packet.payload.tma);
      GTFO_IF_ENGAGED_CHANGED();
      break;

    case ppt_mtc:
      track_mtc(offset, &packet.payload.mtc);
      GTFO_IF_ENGAGED_CHANGED();
      break;

    case ppt_cyc:
      track_cyc(offset, &packet.payload.cyc);
      GTFO_IF_ENGAGED_CHANGED();
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

#undef GTFO_IF_ENGAGED_CHANGED

    __attribute__((musttail)) return process_packets<IsEngaged>(
        next_packet(packet), packet);
  }

  void process_packets_while_engaged(uint64_t offset, packet_type &packet) {
    __attribute__((musttail)) return process_packets<true>(offset, packet);
  }

  void process_packets_while_not_engaged(uint64_t offset, packet_type &packet) {
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

  void ptdump_tracking_init(void) {
    pt_last_ip_init(&tracking.last_ip);
    pt_tcal_init(&tracking.tcal);
    pt_time_init(&tracking.time);

    tracking.tsc = 0ull;
    tracking.fcr = 0ull;
    tracking.in_header = 0;
  }

  void ptdump_tracking_reset(void) {
    pt_last_ip_init(&tracking.last_ip);
    pt_tcal_init(&tracking.tcal);
    pt_time_init(&tracking.time);

    tracking.tsc = 0ull;
    tracking.fcr = 0ull;
    tracking.in_header = 0;
  }

  int print_time(uint64_t offset) {
    uint64_t tsc;
    int errcode;

    errcode = pt_time_query_tsc(&tsc, NULL, NULL, &tracking.time);
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

  int track_tsc(uint64_t offset, const struct pt_packet_tsc *packet) {
    int errcode;

    if (1 /* !options->no_tcal */) {
      errcode = tracking.in_header
                    ? pt_tcal_header_tsc(&tracking.tcal, packet, &config)
                    : pt_tcal_update_tsc(&tracking.tcal, packet, &config);
      if (unlikely(errcode < 0)) {
        if constexpr (IsVerbose())
          fprintf(stderr, "%s: error calibrating time\n", __PRETTY_FUNCTION__);
      }
    }

    errcode = pt_time_update_tsc(&tracking.time, packet, &config);
    assert(errcode == 0);

    assert(tracking.time.have_tsc);
    this->track_time(offset, tracking.time.tsc);

    return 0;
  }

  int track_cbr(uint64_t offset, const struct pt_packet_cbr *packet) {
    int errcode;

    if (1 /* !options->no_tcal */) {
      errcode = tracking.in_header
                    ? pt_tcal_header_cbr(&tracking.tcal, packet, &config)
                    : pt_tcal_update_cbr(&tracking.tcal, packet, &config);
      if (unlikely(errcode < 0)) {
        if constexpr (IsVerbose())
          fprintf(stderr, "%s: error calibrating time\n", __PRETTY_FUNCTION__);
      }
    }

    errcode = pt_time_update_cbr(&tracking.time, packet, &config);
    if (unlikely(errcode < 0)) {
      if constexpr (IsVerbose())
        fprintf(stderr, "%s: error updating time\n", __PRETTY_FUNCTION__);
    }

    if (likely(tracking.time.have_tsc))
      this->track_time(offset, tracking.time.tsc);
    return 0;
  }

  int track_tma(uint64_t offset, const struct pt_packet_tma *packet) {
    int errcode;

    if (1 /* !options->no_tcal */) {
      errcode = pt_tcal_update_tma(&tracking.tcal, packet, &config);
      if (unlikely(errcode < 0)) {
        if constexpr (IsVerbose())
          fprintf(stderr, "%s: error calibrating time\n", __PRETTY_FUNCTION__);
      }
    }

    errcode = pt_time_update_tma(&tracking.time, packet, &config);
    if (unlikely(errcode < 0)) {
      if constexpr (IsVerbose())
        fprintf(stderr, "%s: error updating time\n", __PRETTY_FUNCTION__);
    }

    if (likely(tracking.time.have_tsc))
      this->track_time(offset, tracking.time.tsc);
    return 0;
  }

  int track_mtc(uint64_t offset, const struct pt_packet_mtc *packet) {
    int errcode;

    if (1 /* !options->no_tcal */) {
      errcode = pt_tcal_update_mtc(&tracking.tcal, packet, &config);
      if (unlikely(errcode < 0)) {
        if constexpr (IsVerbose())
          fprintf(stderr, "%s: error calibrating time: %s\n",
                  __PRETTY_FUNCTION__, pt_errstr(pt_errcode(errcode)));
      }
    }

    errcode = pt_time_update_mtc(&tracking.time, packet, &config);
    if (unlikely(errcode < 0)) {
      if constexpr (IsVerbose())
        fprintf(stderr, "%s: error updating time: %s\n", __PRETTY_FUNCTION__,
                pt_errstr(pt_errcode(errcode)));
    }

    if (likely(tracking.time.have_tsc))
      this->track_time(offset, tracking.time.tsc);
    return 0;
  }

  int track_cyc(uint64_t offset, const struct pt_packet_cyc *packet) {
    uint64_t fcr;
    int errcode;

    /* Initialize to zero in case of calibration errors. */
    fcr = 0ull;

    if (1 /* !options->no_tcal */) {
      errcode = pt_tcal_fcr(&fcr, &tracking.tcal);

      if (unlikely(errcode < 0)) {
#if 0
			if constexpr (IsVerbose())
                                fprintf(stderr, "%s: calibration error (1): %s\n",
                                        __func__,
                                        pt_errstr(pt_errcode(errcode)));
#endif
      }

      errcode = pt_tcal_update_cyc(&tracking.tcal, packet, &config);
      if (unlikely(errcode < 0)) {
        if constexpr (IsVerbose())
          fprintf(stderr, "%s: error calibrating time (2): %s\n", __func__,
                  pt_errstr(pt_errcode(errcode)));
      }
    }

    errcode = pt_time_update_cyc(&tracking.time, packet, &config, fcr);

    if (unlikely(errcode < 0)) {
      if constexpr (IsVerbose())
        fprintf(stderr, "%s: error updating time (3): %s\n", __func__,
                pt_errstr(pt_errcode(errcode)));
    } else if (!fcr) {
#if 0
		if constexpr (IsVerbose())
                        fprintf(stderr,
                                "%s: error updating time (4): no calibration\n",
                                __func__);
#endif
    }

    if (likely(tracking.time.have_tsc))
      this->track_time(offset, tracking.time.tsc);
    return 0;
  }

  static int pt_parse_sample_config(struct pt_sb_pevent_config *pevent,
                                    const char *arg) {
    struct pev_sample_config *sample_config;
    uint64_t identifier, sample_type;
    uint8_t nstypes;
    char *rest;
    const char *name;

    if (!pevent || !arg)
      return -pte_internal;

    errno = 0;
    identifier = strtoull(arg, &rest, 0);
    if (errno || (rest == arg))
      return -pte_invalid;

    arg = rest;
    if (arg[0] != ':')
      return -pte_invalid;

    arg += 1;
    sample_type = strtoull(arg, &rest, 0);
    if (errno)
      return -pte_invalid;

    arg = rest;
    if (arg[0] != ':')
      return -pte_invalid;

    arg += 1;
    name = arg;

    sample_config = pevent->sample_config;
    if (!sample_config) {
      sample_config =
          (struct pev_sample_config *)malloc(sizeof(*sample_config));
      if (!sample_config)
        return -pte_nomem;

      memset(sample_config, 0, sizeof(*sample_config));
      pevent->sample_config = sample_config;
    }

    nstypes = sample_config->nstypes;
    sample_config = (struct pev_sample_config *)realloc(
        sample_config, sizeof(*sample_config) +
                           ((nstypes + 1) * sizeof(struct pev_sample_type)));
    if (!sample_config)
      return -pte_nomem;

    sample_config->stypes[nstypes].identifier = identifier;
    sample_config->stypes[nstypes].sample_type = sample_type;
    sample_config->nstypes = nstypes + 1;

    strncpy(sample_config->stypes[nstypes].name, name,
            sizeof(sample_config->stypes[nstypes].name));

    pevent->sample_config = sample_config;

    return 0;
  }

  static int pt_cpu_parse(struct pt_cpu *cpu, const char *s) {
    const char sep = '/';
    char *endptr;
    long family, model, stepping;

    if (!cpu || !s)
      return -pte_invalid;

    family = strtol(s, &endptr, 0);
    if (s == endptr || *endptr == '\0' || *endptr != sep)
      return -pte_invalid;

    if (family < 0 || family > USHRT_MAX)
      return -pte_invalid;

    /* skip separator */
    s = endptr + 1;

    model = strtol(s, &endptr, 0);
    if (s == endptr || (*endptr != '\0' && *endptr != sep))
      return -pte_invalid;

    if (model < 0 || model > UCHAR_MAX)
      return -pte_invalid;

    if (*endptr == '\0')
      /* stepping was omitted, it defaults to 0 */
      stepping = 0;
    else {
      /* skip separator */
      s = endptr + 1;

      stepping = strtol(s, &endptr, 0);
      if (*endptr != '\0')
        return -pte_invalid;

      if (stepping < 0 || stepping > UCHAR_MAX)
        return -pte_invalid;
    }

    cpu->vendor = pcv_intel;
    cpu->family = (uint16_t)family;
    cpu->model = (uint8_t)model;
    cpu->stepping = (uint8_t)stepping;

    return 0;
  }

  static int get_arg_uint64(uint64_t *value, const char *option,
                            const char *arg, const char *prog) {
    char *rest;

    if (!value || !option || !prog) {
      fprintf(stderr, "%s: internal error.\n", prog ? prog : "?");
      return 0;
    }

    if (!arg || arg[0] == 0 || (arg[0] == '-' && arg[1] == '-')) {
      fprintf(stderr, "%s: %s: missing argument.\n", prog, option);
      return 0;
    }

    errno = 0;
    *value = strtoull(arg, &rest, 0);
    if (errno || *rest) {
      fprintf(stderr, "%s: %s: bad argument: %s.\n", prog, option, arg);
      return 0;
    }

    return 1;
  }

  static int get_arg_uint32(uint32_t *value, const char *option,
                            const char *arg, const char *prog) {
    uint64_t val;

    if (!get_arg_uint64(&val, option, arg, prog))
      return 0;

    if (val > UINT32_MAX) {
      fprintf(stderr, "%s: %s: value too big: %s.\n", prog, option, arg);
      return 0;
    }

    *value = (uint32_t)val;

    return 1;
  }

  static int get_arg_uint16(uint16_t *value, const char *option,
                            const char *arg, const char *prog) {
    uint64_t val;

    if (!get_arg_uint64(&val, option, arg, prog))
      return 0;

    if (val > UINT16_MAX) {
      fprintf(stderr, "%s: %s: value too big: %s.\n", prog, option, arg);
      return 0;
    }

    *value = (uint16_t)val;

    return 1;
  }

  static int get_arg_uint8(uint8_t *value, const char *option, const char *arg,
                           const char *prog) {
    uint64_t val;

    if (!get_arg_uint64(&val, option, arg, prog))
      return 0;

    if (val > UINT8_MAX) {
      fprintf(stderr, "%s: %s: value too big: %s.\n", prog, option, arg);
      return 0;
    }

    *value = (uint8_t)val;

    return 1;
  }

  int process_args(int argc, char **argv) {
    struct pt_sb_pevent_config pevent;
    int idx, errcode;

    memset(&pevent, 0, sizeof(pevent));
    pevent.size = sizeof(pevent);
    pevent.time_mult = 1;

    for (idx = 1; idx < argc; ++idx) {
      if (strcmp(argv[idx], "--pevent:sample-type") == 0) {
        if (!get_arg_uint64(&pevent.sample_type, "--pevent:sample-type",
                            argv[++idx], argv[0]))
          return -1;
      } else if (strcmp(argv[idx], "--pevent:sample-config") == 0) {
        errcode = pt_parse_sample_config(&pevent, argv[++idx]);
        if (errcode < 0) {
          fprintf(stderr, "%s: bad sample config %s: %s.\n", argv[0],
                  argv[idx - 1], pt_errstr(pt_errcode(errcode)));
          return -1;
        }
      } else if (strcmp(argv[idx], "--pevent:time-zero") == 0) {
        if (!get_arg_uint64(&pevent.time_zero, "--pevent:time-zero",
                            argv[++idx], argv[0]))
          return -1;
      } else if (strcmp(argv[idx], "--pevent:time-shift") == 0) {
        if (!get_arg_uint16(&pevent.time_shift, "--pevent:time-shift",
                            argv[++idx], argv[0]))
          return -1;
      } else if (strcmp(argv[idx], "--pevent:time-mult") == 0) {
        if (!get_arg_uint32(&pevent.time_mult, "--pevent:time-mult",
                            argv[++idx], argv[0]))
          return -1;
      } else if (strcmp(argv[idx], "--pevent:tsc-offset") == 0) {
        if (!get_arg_uint64(&pevent.tsc_offset, "--pevent:tsc-offset",
                            argv[++idx], argv[0]))
          return -1;
      } else if (strcmp(argv[idx], "--pevent:kernel-start") == 0) {
        if (!get_arg_uint64(&pevent.kernel_start, "--pevent:kernel-start",
                            argv[++idx], argv[0]))
          return -1;
      } else if (strcmp(argv[idx], "--cpu") == 0) {
        const char *arg;

        arg = argv[++idx];
        if (!arg) {
          fprintf(stderr, "%s: --cpu: missing argument.\n", argv[0]);
          return -1;
        }

        if (strcmp(arg, "none") == 0) {
          memset(&config.cpu, 0, sizeof(config.cpu));
          continue;
        }

        errcode = pt_cpu_parse(&config.cpu, arg);
        if (errcode < 0) {
          fprintf(stderr, "%s: cpu must be specified as f/m[/s]\n", argv[0]);
          return -1;
        }
      } else if (strcmp(argv[idx], "--mtc-freq") == 0) {
        if (!get_arg_uint8(&config.mtc_freq, "--mtc-freq", argv[++idx],
                           argv[0]))
          return -1;
      } else if (strcmp(argv[idx], "--nom-freq") == 0) {
        if (!get_arg_uint8(&config.nom_freq, "--nom-freq", argv[++idx],
                           argv[0]))
          return -1;
      } else if (strcmp(argv[idx], "--cpuid-0x15.eax") == 0) {
        if (!get_arg_uint32(&config.cpuid_0x15_eax, "--cpuid-0x15.eax",
                            argv[++idx], argv[0]))
          return -1;
      } else if (strcmp(argv[idx], "--cpuid-0x15.ebx") == 0) {
        if (!get_arg_uint32(&config.cpuid_0x15_ebx, "--cpuid-0x15.ebx",
                            argv[++idx], argv[0]))
          return -1;
      } else {
        throw std::runtime_error(std::string("unknown option \"") + argv[idx] +
                                 std::string("\""));
      }
    }

    return 0;
  }

#undef IsVerbose
#undef IsVeryVerbose
};
} // namespace jove

#endif /* x86 */
