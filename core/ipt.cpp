#if defined(__x86_64__) || defined(__i386__) /* x86 only */

#include "ipt.h"
#include "explore.h"

#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/algorithm/string.hpp>

#include <intel-pt.h>
#include <libipt-sb.h>
#include <inttypes.h>

extern "C" {
#include "pt_last_ip.c" /* XXX why isn't this exported by libipt?? */
#include "pt_time.c" /* XXX why isn't this exported by libipt?? */
}

namespace fs = boost::filesystem;

namespace jove {

typedef boost::format fmt;

IntelPT::IntelPT(int ptdump_argc, char **ptdump_argv, jv_t &jv,
                 explorer_t &explorer, unsigned cpu,
                 const address_space_t &AddressSpace, void *begin, void *end,
                 bool ignore_trunc_aux)
    : jv(jv), explorer(explorer), state(jv), AddressSpace(AddressSpace),
      ignore_trunc_aux(ignore_trunc_aux) {
  our.cpu = cpu;

  for_each_binary(std::execution::par_unseq, jv, [&](binary_t &b) {
    binary_state_t &x = state.for_binary(b);

    x.Bin = B::Create(b.data());

    auto &SectsStartAddr = x.SectsStartAddr;
    auto &SectsEndAddr   = x.SectsEndAddr;
    std::tie(SectsStartAddr, SectsEndAddr) = B::bounds_of_binary(*x.Bin);
  });

  config = std::make_unique<struct pt_config>();

  pt_config_init(config.get());

  tracking.last_ip = std::make_unique<struct pt_last_ip>();
  tracking.tcal = std::make_unique<struct pt_time_cal>();
  tracking.time = std::make_unique<struct pt_time>();

  ptdump_tracking_init();

  tracking.session = pt_sb_alloc(NULL);
  if (!tracking.session)
    throw std::runtime_error("failed to allocate sideband session");

  pt_sb_notify_error(
      tracking.session,
      [](int errcode, const char *filename, uint64_t offset, void *priv) {
        assert(priv);
        return ((IntelPT *)priv)->ptdump_print_error(errcode, filename, offset);
      },
      this);

  if (process_args(ptdump_argc, ptdump_argv) != 0)
    throw std::runtime_error("failed to process ptdump arguments");

  if (config->cpu.vendor) {
    int errcode = pt_cpu_errata(&config->errata, &config->cpu);
#if 0
    if (unlikely(errcode < 0))
      diag("failed to determine errata", 0ull, errcode);
#endif
  }

  int errcode = pt_sb_init_decoders(tracking.session);
  if (errcode < 0) {
    throw std::runtime_error(
        std::string("error initializing sideband decoders: ") +
        pt_errstr(pt_errcode(errcode)));
  }

  config->begin = reinterpret_cast<uint8_t *>(begin);
  config->end = reinterpret_cast<uint8_t *>(end);

  decoder = pt_pkt_alloc_decoder(config.get());

  sb.os = open_memstream(&sb.ptr, &sb.len);
  if (!sb.os)
    throw std::runtime_error(std::string("open_memstream() failed: ") +
                             strerror(errno));
}

IntelPT::~IntelPT() {
  pt_pkt_free_decoder(decoder);

#if 0
  int errcode = pt_sb_dump(tracking.session, stdout, sb_dump_flags, UINT64_MAX);
#endif

#if 0
  if (unlikely(errcode < 0))
    return diag("sideband dump error", UINT64_MAX, errcode);
#endif

  pt_sb_free(tracking.session);

  fclose(sb.os);
  free(sb.ptr);
}

int IntelPT::ptdump_print_error(int errcode, const char *filename,
                                uint64_t offset) {
  if (errcode >= 0 && false /* !options->print_sb_warnings */)
    return 0;

  if (!filename)
    filename = "<unknown>";

  const char *errstr = errcode < 0
                           ? pt_errstr(pt_errcode(errcode))
                           : pt_sb_errstr((enum pt_sb_error_code)errcode);

  if (!errstr)
    errstr = "<unknown error>";

  fprintf(stderr, "[%s:%016" PRIx64 " sideband error: %s]\n", filename, offset,
          errstr);

  return 0;
}

void IntelPT::examine_sb(void) {
  fflush(sb.os);

  char *ptr = sb.ptr;
  char *const end = ptr + sb.len;

  assert(ptr);

  char *eol;
  do {
    const unsigned left = end - ptr;
    if (!left)
      break;
    assert(ptr < end);

    char *const line = ptr;

    {
      eol = (char *)memchr(ptr, '\n', left);
      assert(eol);
      ptr = eol + 1;
    }
    *eol = '\0';

    static const char sb_line_prefix[] = "PERF_RECORD_";
    constexpr unsigned sb_line_prefix_len = sizeof(sb_line_prefix)-1;

    if (unlikely(strncmp(line, sb_line_prefix, sb_line_prefix_len) != 0)) {
      assert(strncmp(line, "UNKNOWN", sizeof("UNKNOWN")-1) == 0);
      continue;
    }

#define MATCHES_REST(x)                                                        \
  (strncmp(rest, x "  ", (sizeof(x) - 1) + 2) == 0 && ({                       \
     rest += ((sizeof(x) - 1) + 2);                                            \
     assert(rest < eol);                                                       \
     true;                                                                     \
   }))

    char *rest = line + sb_line_prefix_len;

    auto do_comm = [&](void) -> void {
      if (!Right.ExecMode)
        return;

      unsigned pid, tid;
      char comm[64];
      comm[0] = '\0';

      sscanf(rest, "%x/%x, %63s", &pid, &tid, &comm[0]);

      if (boost::algorithm::ends_with(jv.Binaries.at(0).Name.c_str(), comm)) {
        our.pid = pid;
        our.tid = tid;

        fprintf(stderr, "our tid is %x\n", tid);
      }
    };

    struct {
      unsigned pid, tid;
      uint64_t time;
      uint64_t id;
      unsigned cpu;
      uint64_t stream_id;
      uint64_t identifier;
    } _;

    auto unexpected_rest = [&](void) -> void {
      fprintf(stderr, "unexpected rest=\"%s\"\n", rest);
      fflush(stderr);
      assert(false);
    };

    switch (rest[0]) {
    case 'A':
      if (likely(MATCHES_REST("AUX"))) {
        ;
      } else if (MATCHES_REST("AUX.TRUNCATED")) {
        if (!ignore_trunc_aux)
          throw truncated_aux_exception();
      } else {
        unexpected_rest();
      }
      break;

    case 'C':
      if (MATCHES_REST("COMM.EXEC")) {
        do_comm();
      } else if (MATCHES_REST("COMM")) {
        do_comm();
      } else {
        unexpected_rest();
      }
      break;

    case 'I':
      if (likely(MATCHES_REST("ITRACE_START"))) {
        ;
      } else {
        unexpected_rest();
      }
      break;

    case 'F':
      if (likely(MATCHES_REST("FORK"))) {
        ;
      } else {
        unexpected_rest();
      }
      break;

    case 'E':
      if (likely(MATCHES_REST("EXIT"))) {
        ;
      } else {
        unexpected_rest();
      }
      break;

    case 'S':
      if (MATCHES_REST("SWITCH_CPU_WIDE.OUT")) {
        unsigned next_pid, next_tid;
        sscanf(rest, "%x/%x"
                     "  { %x/%x %" PRIx64 " cpu-%x %" PRIx64 " }",
               &next_pid, &next_tid,
               &_.pid, &_.tid, &_.time, &_.cpu, &_.identifier);

        if (_.cpu == our.cpu)
          Right.Thread = next_tid == our.tid;
      } else if (MATCHES_REST("SWITCH.OUT")) {
        sscanf(rest, "  { %x/%x %" PRIx64 " cpu-%x %" PRIx64 " }",
               &_.pid, &_.tid, &_.time, &_.cpu, &_.identifier);

        /* XXX? */
#if 0
        if (_.cpu == our.cpu)
          Right.Thread = next_tid == our.tid;
#endif
      } else if (MATCHES_REST("SWITCH_CPU_WIDE.IN")) {
        unsigned prev_pid, prev_tid;
        sscanf(rest, "%x/%x"
                     "  { %x/%x %" PRIx64 " cpu-%x %" PRIx64 " }",
               &prev_pid, &prev_tid,
               &_.pid, &_.tid, &_.time, &_.cpu, &_.identifier);

        if (_.cpu == our.cpu)
          Right.Thread = _.tid == our.tid;
      } else if (MATCHES_REST("SWITCH.IN")) {
        sscanf(rest, "  { %x/%x %" PRIx64 " cpu-%x %" PRIx64 " }",
               &_.pid, &_.tid, &_.time, &_.cpu, &_.identifier);

        if (_.cpu == our.cpu)
          Right.Thread = _.tid == our.tid;
      } else {
        unexpected_rest();
      }

      CheckEngaged();
      break;

    case 'M':
      if (likely(MATCHES_REST("MMAP2"))) {
        if (!Engaged)
          continue;

        unsigned pid, tid;
        uint64_t addr, len, pgoff;
        unsigned maj, min;
        uint64_t ino, ino_generation;
        unsigned prot, flags;
        char filename[4096];
        filename[0] = '\0';

        sscanf(rest, "%x/%x, %" PRIx64
                     ", %" PRIx64 ", %" PRIx64 ", %x, %x, %" PRIx64
                     ", %" PRIx64 ", %x, %x, %4095s"

                     "  { %x/%x %" PRIx64 " cpu-%x %" PRIx64 " }",

                     &pid, &tid, &addr,
                     &len, &pgoff, &maj, &min, &ino,
                     &ino_generation, &prot, &flags, &filename[0],

                     &_.pid, &_.tid, &_.time, &_.cpu, &_.identifier);

        if (intvl_map_find(AddressSpace, addr) != AddressSpace.end()) {
          //fprintf(stderr, "previous mapping exists at 0x%" PRIx64 "\n", addr);
          continue;
        }

        assert(strlen(filename) > 0);

        if (filename[0] == '[' || strcmp(filename, "//anon") == 0)
          continue;

        if (!fs::exists(filename)) {
          fprintf(stderr, "\"%s\" does not exist!(%s)\n", filename, rest);
          continue;
        }

        binary_index_t BIdx;
        bool IsNew;

        std::tie(BIdx, IsNew) = jv.AddFromPath(explorer, filename);
        if (!is_binary_index_valid(BIdx))
          continue;

        binary_t &b = jv.Binaries.at(BIdx);
        if (IsNew)
          state.update();
        binary_state_t &x = state.for_binary(b);
        if (IsNew)
          x.Bin = B::Create(b.data());

        if (!B::is_elf(*x.Bin))
          continue; /* FIXME */

        if (is_binary_index_valid(BIdx)) {
          binary_t &b = jv.Binaries.at(BIdx);
          binary_state_t &x = state.for_binary(b);

          intvl_map_add(AddressSpace, addr_intvl(addr, len), BIdx);
          if (updateVariable(x.LoadAddr, std::min(x.LoadAddr, static_cast<taddr_t>(addr))))
            x.LoadOffset = pgoff;
        }
      } else {
        unexpected_rest();
      }
      break;

    default:
      fprintf(stderr, "examine_sb: \"%s\" (TODO)\n", line);
      break;
    }
  } while (likely(ptr != end));
}

int IntelPT::explore(/*FIXME*/) {
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
    errcode = explore_packets();
    if (unlikely(!errcode))
      break;

    errcode = pt_pkt_sync_forward(decoder);
    if (unlikely(errcode < 0)) {
      if (errcode == -pte_eos)
        return 0;

      throw std::runtime_error(std::string("IntelPT: sync error: ") +
                               pt_errstr(pt_errcode(errcode)));
    }

    ptdump_tracking_reset();
  }

  return errcode;
}

int IntelPT::explore_packets() {
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

#if 0
      throw std::runtime_error(
          std::string("IntelPT: error decoding packet: ") +
          pt_errstr(pt_errcode(errcode)));
#else
      return errcode;
#endif
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
    return 0;

  case ppt_psb:
    if (1 /* options->track_time */) {
      int errcode;

      errcode = pt_tcal_update_psb(tracking.tcal.get(), config.get());
#if 0
      if (unlikely(errcode < 0))
        diag("error calibrating time", offset, errcode);
#endif
    }

    tracking.in_header = 1;
    return 0;

  case ppt_psbend:
    tracking.in_header = 0;
    return 0;

  case ppt_pad:
    return 0;

  case ppt_ovf:
    if (0 /* options->keep_tcal_on_ovf */) {
      int errcode;

      errcode = pt_tcal_update_ovf(tracking.tcal.get(), config.get());
#if 0
      if (unlikely(errcode < 0))
        diag("error calibrating time", offset, errcode);
#endif
    } else {
      pt_tcal_init(tracking.tcal.get());
    }
    return 0;

  case ppt_stop:
    return 0;

  case ppt_fup:
  case ppt_tip:
  case ppt_tip_pge:
  case ppt_tip_pgd:
    track_last_ip(&packet->payload.ip, offset);
    return 0;

  case ppt_pip: /* we'll never see this in userspace */
  case ppt_vmcs:
    return 0;

  case ppt_tnt_8:
  case ppt_tnt_64:
    return tnt_payload(&packet->payload.tnt);

  case ppt_mode: {
    const struct pt_packet_mode *mode = &packet->payload.mode;
    switch (mode->leaf) {
    case pt_mol_exec: {
      const char *desc = NULL;
      switch (pt_get_exec_mode(&mode->bits.exec)) {
      case ptem_64bit:
        desc = "64-bit";
        Right.ExecMode = !IsTarget32;
        break;

      case ptem_32bit:
        desc = "32-bit";
        Right.ExecMode = IsTarget32;
        break;

      case ptem_16bit:
        desc = "16-bit";
        Right.ExecMode = false;
        break;

      case ptem_unknown:
        desc = "unknown";
        Right.ExecMode = false;
        break;
      }

      //printf("[exec mode: %s]\n", desc);
      CheckEngaged();
      return 0;
    }

    case pt_mol_tsx:
      return 0;
    }

    throw std::runtime_error(
        std::string("IntelPT: unknown mode leaf at offset ") +
        std::to_string(offset));
  }

  case ppt_tsc:
    track_tsc(offset, &packet->payload.tsc);
    return 0;

  case ppt_cbr:
    track_cbr(offset, &packet->payload.cbr);
    return 0;

  case ppt_tma:
    track_tma(offset, &packet->payload.tma);
    return 0;

  case ppt_mtc:
    track_mtc(offset, &packet->payload.mtc);
    return 0;

  case ppt_cyc:
    track_cyc(offset, &packet->payload.cyc);
    return 0;

  case ppt_mnt:
  case ppt_exstop:
  case ppt_mwait:
  case ppt_pwre:
  case ppt_pwrx:
  case ppt_ptw:
  case ppt_cfe:
  case ppt_evd:
  case ppt_trig:
    return 0;
  }

  throw std::runtime_error(
      std::string("IntelPT: unknown packet at offset ") +
      std::to_string(offset));
}

int IntelPT::tnt_payload(const struct pt_packet_tnt *packet) {
  return 0;
  if (!Engaged)
    return 0;

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

  errcode = pt_last_ip_update_ip(tracking.last_ip.get(), packet, NULL);
  if (unlikely(errcode < 0)) {
    //print_field(buffer->tracking.payload, "<unavailable>");

    throw std::runtime_error(
        std::string("IntelPT: error tracking last-ip at offset ") +
        std::to_string(offset));
  }

  errcode = pt_last_ip_query(&ip, tracking.last_ip.get());
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
    on_ip(ip);
  }

  return 0;
}

int IntelPT::on_ip(const uint64_t ip) {
  if (!Engaged)
    return 0;

  auto it = intvl_map_find(AddressSpace, ip);
  if (it == AddressSpace.end() || !is_binary_index_valid((*it).second)) {
    //printf("unknown ip %016" PRIx64 "\n", ip); /* FIXME */
    //throw std::runtime_error("unknown ip " + (fmt("%016" PRIx64) % ip).str());
    return 0;
  }

  const addr_intvl &intvl = (*it).first;

  binary_t &b = jv.Binaries.at((*it).second);
  binary_state_t &x = state.for_binary(b);

  uint64_t Addr = B::_X(
      *x.Bin,
      [&](ELFO &O) -> uint64_t {
        const taddr_t LoadAddr = x.LoadAddr;
        assert(ip >= LoadAddr);

        uint64_t off = ip - (LoadAddr - x.LoadOffset);
        try {
        return elf::va_of_offset(O, off);
        } catch (...) {
        std::string as(addr_intvl2str((*it).first));
        fprintf(stderr, "WTF? %" PRIx64 " in %s %" PRIx64 " %" PRIx64 "\t\t%s\n", ip,
                as.c_str(), (uint64_t)LoadAddr, (uint64_t)x.LoadOffset, b.Name.c_str());
        assert(false);
        }
      },
      [&](COFFO &O) -> uint64_t {
        assert(ip >= intvl.first);
        uint64_t RVA = ip - intvl.first;
        if (RVA >= 0xffffffff) {
        fprintf(stderr, "WTF? %" PRIx64 " %" PRIx64 "\n", ip,
                RVA);
        assert(false);
        }
        return coff::va_of_rva(O, RVA);
      });

  //printf("%016" PRIx64 " E %016" PRIx64 "\t\t\t%s\n", ip, Addr, b.Name.c_str()); /* FIXME */
  try {
    explorer.explore_basic_block(b, *x.Bin, Addr);
  } catch (const invalid_control_flow_exception &e) {
    printf("BADIP!!! %016" PRIx64 " E %016" PRIx64 "\t\t\t%s\n", ip, Addr,
           b.Name.c_str()); /* FIXME */
    fflush(stdout);
  }

  return 0;
}

void IntelPT::ptdump_tracking_init(void)
{
  pt_last_ip_init(tracking.last_ip.get());
  pt_tcal_init(tracking.tcal.get());
  pt_time_init(tracking.time.get());

  tracking.session = NULL;
  tracking.tsc = 0ull;
  tracking.fcr = 0ull;
  tracking.in_header = 0;
}

void IntelPT::ptdump_tracking_reset(void) {
  pt_last_ip_init(tracking.last_ip.get());
  pt_tcal_init(tracking.tcal.get());
  pt_time_init(tracking.time.get());

  tracking.tsc = 0ull;
  tracking.fcr = 0ull;
  tracking.in_header = 0;
}

int IntelPT::sb_track_time(uint64_t offset)
{
	uint64_t tsc;
	int errcode;

#if 0
	if (!tracking || !options)
		return diag("time tracking error", offset, -pte_internal);
#endif

	errcode = pt_time_query_tsc(&tsc, NULL, NULL, tracking.time.get());
	if (unlikely((errcode < 0) && (errcode != -pte_no_time)))
#if 0
		return diag("time tracking error", offset, errcode);
#else
		return errcode;
#endif

        rewind(sb.os);
        errcode = pt_sb_dump(tracking.session, sb.os, sb_dump_flags, tsc);
        if (unlikely(errcode < 0))
#if 0
		return diag("sideband dump error", offset, errcode);
#else
		return errcode;
#endif
        examine_sb();
        return 0;
}

int IntelPT::track_time(uint64_t offset) {
#if 0
	if (!tracking || !options)
		return diag("error tracking time", offset, -pte_internal);
#endif

#if 0
	if (options->show_tcal && !buffer->skip_tcal)
		print_tcal(buffer, tracking, offset, options);
#endif

#if 0
	if (options->show_time && !buffer->skip_time)
		print_time(buffer, tracking, offset, options);
#endif

	return sb_track_time(offset);
}

int IntelPT::track_tsc(uint64_t offset, const struct pt_packet_tsc *packet) {
        int errcode;

#if 0
	if (!buffer || !tracking || !options)
		return diag("error tracking time", offset, -pte_internal);
#endif

	if (1 /* !options->no_tcal */) {
		errcode = tracking.in_header ?
			pt_tcal_header_tsc(tracking.tcal.get(), packet, config.get()) :
			pt_tcal_update_tsc(tracking.tcal.get(), packet, config.get());
#if 0
		if (unlikely(errcode < 0))
			diag("error calibrating time", offset, errcode);
#endif
	}

	errcode = pt_time_update_tsc(tracking.time.get(), packet, config.get());
#if 0
	if (unlikely(errcode < 0))
		diag("error updating time", offset, errcode);
#endif

	return track_time(offset);
}

int IntelPT::track_cbr(uint64_t offset, const struct pt_packet_cbr *packet) {
        int errcode;

#if 0
	if (!buffer || !tracking || !options)
		return diag("error tracking time", offset, -pte_internal);
#endif

	if (1 /* !options->no_tcal */) {
		errcode = tracking.in_header ?
			pt_tcal_header_cbr(tracking.tcal.get(), packet, config.get()) :
			pt_tcal_update_cbr(tracking.tcal.get(), packet, config.get());
#if 0
		if (unlikely(errcode < 0))
			diag("error calibrating time", offset, errcode);
#endif
	}

	errcode = pt_time_update_cbr(tracking.time.get(), packet, config.get());
#if 0
	if (unlikely(errcode < 0))
		diag("error updating time", offset, errcode);
#endif

#if 0
	/* There is no timing update at this packet. */
	skip_time = 1;
#endif

	return track_time(offset);
}

int IntelPT::track_tma(uint64_t offset, const struct pt_packet_tma *packet) {
        int errcode;

#if 0
	if (!buffer || !tracking || !options)
		return diag("error tracking time", offset, -pte_internal);
#endif

	if (1 /* !options->no_tcal */) {
		errcode = pt_tcal_update_tma(tracking.tcal.get(), packet, config.get());
#if 0
		if (unlikely(errcode < 0))
			diag("error calibrating time", offset, errcode);
#endif
	}

	errcode = pt_time_update_tma(tracking.time.get(), packet, config.get());
#if 0
	if (unlikely(errcode < 0))
		diag("error updating time", offset, errcode);
#endif

#if 0
	/* There is no calibration update at this packet. */
	skip_tcal = 1;
#endif

	return track_time(offset);
}

int IntelPT::track_mtc(uint64_t offset, const struct pt_packet_mtc *packet) {
        int errcode;

#if 0
	if (!buffer || !tracking || !options)
		return diag("error tracking time", offset, -pte_internal);
#endif

	if (1 /* !options->no_tcal */) {
		errcode = pt_tcal_update_mtc(tracking.tcal.get(), packet, config.get());
#if 0
		if (unlikely(errcode < 0))
			diag("error calibrating time", offset, errcode);
#endif
	}

	errcode = pt_time_update_mtc(tracking.time.get(), packet, config.get());
#if 0
	if (unlikely(errcode < 0))
		diag("error updating time", offset, errcode);
#endif

	return track_time(offset);
}

int IntelPT::track_cyc(uint64_t offset, const struct pt_packet_cyc *packet) {
  uint64_t fcr;
  int errcode;

#if 0
	if (!buffer || !tracking || !options)
		return diag("error tracking time", offset, -pte_internal);
#endif

	/* Initialize to zero in case of calibration errors. */
	fcr = 0ull;

	if (1 /* !options->no_tcal */) {
		errcode = pt_tcal_fcr(&fcr, tracking.tcal.get());
#if 0
		if (errcode < 0)
			diag("calibration error", offset, errcode);
#endif

		errcode = pt_tcal_update_cyc(tracking.tcal.get(), packet, config.get());
#if 0
		if (errcode < 0)
			diag("error calibrating time", offset, errcode);
#endif
	}

	errcode = pt_time_update_cyc(tracking.time.get(), packet, config.get(), fcr);
#if 0
	if (errcode < 0)
		diag("error updating time", offset, errcode);
	else if (!fcr)
		diag("error updating time: no calibration", offset, 0);
#endif

#if 0
	/* There is no calibration update at this packet. */
	skip_tcal = 1;
#endif

	return track_time(offset);
}

static int parse_range(const char *arg, uint64_t *begin, uint64_t *end)
{
	char *rest;

	if (!arg || !*arg)
		return 0;

	errno = 0;
	*begin = strtoull(arg, &rest, 0);
	if (errno)
		return -1;

	if (!*rest)
		return 1;

	if (*rest != '-')
		return -1;

	*end = strtoull(rest+1, &rest, 0);
	if (errno || *rest)
		return -1;

	return 2;
}

/* Preprocess a filename argument.
 *
 * A filename may optionally be followed by a file offset or a file range
 * argument separated by ':'.  Split the original argument into the filename
 * part and the offset/range part.
 *
 * If no end address is specified, set @size to zero.
 * If no offset is specified, set @offset to zero.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int preprocess_filename(char *filename, uint64_t *offset, uint64_t *size)
{
	uint64_t begin, end;
	char *range;
	int parts;

	if (!filename || !offset || !size)
		return -pte_internal;

	/* Search from the end as the filename may also contain ':'. */
	range = strrchr(filename, ':');
	if (!range) {
		*offset = 0ull;
		*size = 0ull;

		return 0;
	}

	/* Let's try to parse an optional range suffix.
	 *
	 * If we can, remove it from the filename argument.
	 * If we can not, assume that the ':' is part of the filename, e.g. a
	 * drive letter on Windows.
	 */
	parts = parse_range(range + 1, &begin, &end);
	if (parts <= 0) {
		*offset = 0ull;
		*size = 0ull;

		return 0;
	}

	if (parts == 1) {
		*offset = begin;
		*size = 0ull;

		*range = 0;

		return 0;
	}

	if (parts == 2) {
		if (end <= begin)
			return -pte_invalid;

		*offset = begin;
		*size = end - begin;

		*range = 0;

		return 0;
	}

	return -pte_internal;
}

int IntelPT::ptdump_sb_pevent(char *filename,
                              const struct pt_sb_pevent_config *conf,
                              const char *prog) {
        struct pt_sb_pevent_config config;
	uint64_t foffset, fsize, fend;
	int errcode;

#if 0
	if (!conf || !prog) {
		fprintf(stderr, "%s: internal error.\n", prog ? prog : "");
		return -1;
	}
#endif

	errcode = preprocess_filename(filename, &foffset, &fsize);
	if (errcode < 0) {
#if 0
		fprintf(stderr, "%s: bad file %s: %s.\n", prog, filename,
			pt_errstr(pt_errcode(errcode)));
#endif
		return -1;
	}

	if (SIZE_MAX < foffset) {
#if 0
		fprintf(stderr,
			"%s: bad offset: 0x%" PRIx64 ".\n", prog, foffset);
#endif
		return -1;
	}

	config = *conf;
	config.filename = filename;
	config.begin = (size_t) foffset;
	config.end = 0;

	if (fsize) {
		fend = foffset + fsize;
		if ((fend <= foffset) || (SIZE_MAX < fend)) {
#if 0
			fprintf(stderr,
				"%s: bad range: 0x%" PRIx64 "-0x%" PRIx64 ".\n",
				prog, foffset, fend);
#endif
			return -1;
		}

		config.end = (size_t) fend;
	}

	errcode = pt_sb_alloc_pevent_decoder(tracking.session, &config);
	if (unlikely(errcode < 0)) {
#if 0
		fprintf(stderr, "%s: error loading %s: %s.\n", prog, filename,
			pt_errstr(pt_errcode(errcode)));
#endif
		return -1;
	}

	return 0;
}

static int pt_parse_sample_config(struct pt_sb_pevent_config *pevent,
                                  const char *arg) {
        struct pev_sample_config *sample_config;
	uint64_t identifier, sample_type;
	uint8_t nstypes;
	char *rest;

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
	if (errno || *rest)
		return -pte_invalid;

	sample_config = pevent->sample_config;
	if (!sample_config) {
		sample_config = (struct pev_sample_config *)malloc(sizeof(*sample_config));
		if (!sample_config)
			return -pte_nomem;

		memset(sample_config, 0, sizeof(*sample_config));
		pevent->sample_config = sample_config;
	}

	nstypes = sample_config->nstypes;
	sample_config = (struct pev_sample_config *)realloc(sample_config,
				sizeof(*sample_config) +
				((nstypes + 1) *
				 sizeof(struct pev_sample_type)));
	if (!sample_config)
		return -pte_nomem;

	sample_config->stypes[nstypes].identifier = identifier;
	sample_config->stypes[nstypes].sample_type = sample_type;
	sample_config->nstypes = nstypes + 1;

	pevent->sample_config = sample_config;

	return 0;
}

static int pt_cpu_parse(struct pt_cpu *cpu, const char *s)
{
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
	cpu->family = (uint16_t) family;
	cpu->model = (uint8_t) model;
	cpu->stepping = (uint8_t) stepping;

	return 0;
}

static int get_arg_uint64(uint64_t *value, const char *option, const char *arg,
			  const char *prog)
{
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
		fprintf(stderr, "%s: %s: bad argument: %s.\n", prog, option,
			arg);
		return 0;
	}

	return 1;
}

static int get_arg_uint32(uint32_t *value, const char *option, const char *arg,
			  const char *prog)
{
	uint64_t val;

	if (!get_arg_uint64(&val, option, arg, prog))
		return 0;

	if (val > UINT32_MAX) {
		fprintf(stderr, "%s: %s: value too big: %s.\n", prog, option,
			arg);
		return 0;
	}

	*value = (uint32_t) val;

	return 1;
}


static int get_arg_uint16(uint16_t *value, const char *option, const char *arg,
			  const char *prog)
{
	uint64_t val;

	if (!get_arg_uint64(&val, option, arg, prog))
		return 0;

	if (val > UINT16_MAX) {
		fprintf(stderr, "%s: %s: value too big: %s.\n", prog, option,
			arg);
		return 0;
	}

	*value = (uint16_t) val;

	return 1;
}

static int get_arg_uint8(uint8_t *value, const char *option, const char *arg,
			 const char *prog)
{
	uint64_t val;

	if (!get_arg_uint64(&val, option, arg, prog))
		return 0;

	if (val > UINT8_MAX) {
		fprintf(stderr, "%s: %s: value too big: %s.\n", prog, option,
			arg);
		return 0;
	}

	*value = (uint8_t) val;

	return 1;
}


int IntelPT::process_args(int argc, char **argv)
{
	struct pt_sb_pevent_config pevent;
	int idx, errcode;

	memset(&pevent, 0, sizeof(pevent));
	pevent.size = sizeof(pevent);
	pevent.time_mult = 1;

	for (idx = 1; idx < argc; ++idx) {
		     if ((strcmp(argv[idx], "--pevent") == 0) ||
			 (strcmp(argv[idx], "--pevent:primary") == 0) ||
			 (strcmp(argv[idx], "--pevent:secondary") == 0)) {
			char *arg;

			arg = argv[++idx];
			if (!arg) {
#if 0
				fprintf(stderr,
					"%s: %s: missing argument.\n",
					argv[0], argv[idx-1]);
#endif
				return -1;
			}

                        errcode = ptdump_sb_pevent(arg, &pevent, argv[0]);
                        if (errcode < 0)
				return -1;
		} else if (strcmp(argv[idx], "--pevent:sample-type") == 0) {
			if (!get_arg_uint64(&pevent.sample_type,
					    "--pevent:sample-type",
					    argv[++idx], argv[0]))
				return -1;
		} else if (strcmp(argv[idx], "--pevent:sample-config") == 0) {
			errcode = pt_parse_sample_config(&pevent, argv[++idx]);
			if (errcode < 0) {
#if 0
				fprintf(stderr,
					"%s: bad sample config %s: %s.\n",
					argv[0], argv[idx-1],
					pt_errstr(pt_errcode(errcode)));
#endif
				return -1;
			}
		} else if (strcmp(argv[idx], "--pevent:time-zero") == 0) {
			if (!get_arg_uint64(&pevent.time_zero,
					    "--pevent:time-zero",
					    argv[++idx], argv[0]))
				return -1;
		} else if (strcmp(argv[idx], "--pevent:time-shift") == 0) {
			if (!get_arg_uint16(&pevent.time_shift,
					    "--pevent:time-shift",
					    argv[++idx], argv[0]))
				return -1;
		} else if (strcmp(argv[idx], "--pevent:time-mult") == 0) {
			if (!get_arg_uint32(&pevent.time_mult,
					    "--pevent:time-mult",
					    argv[++idx], argv[0]))
				return -1;
		} else if (strcmp(argv[idx], "--pevent:tsc-offset") == 0) {
			if (!get_arg_uint64(&pevent.tsc_offset,
					    "--pevent:tsc-offset",
					    argv[++idx], argv[0]))
				return -1;
		} else if (strcmp(argv[idx], "--pevent:kernel-start") == 0) {
			if (!get_arg_uint64(&pevent.kernel_start,
					    "--pevent:kernel-start",
					    argv[++idx], argv[0]))
				return -1;
		} else if (strcmp(argv[idx], "--cpu") == 0) {
			const char *arg;

			arg = argv[++idx];
			if (!arg) {
#if 0
				fprintf(stderr,
					"%s: --cpu: missing argument.\n",
					argv[0]);
#endif
				return -1;
			}

			if (strcmp(arg, "none") == 0) {
				memset(&config->cpu, 0, sizeof(config->cpu));
				continue;
			}

			errcode = pt_cpu_parse(&config->cpu, arg);
			if (errcode < 0) {
#if 0
				fprintf(stderr,
					"%s: cpu must be specified as f/m[/s]\n",
					argv[0]);
#endif
				return -1;
			}
		} else if (strcmp(argv[idx], "--mtc-freq") == 0) {
			if (!get_arg_uint8(&config->mtc_freq, "--mtc-freq",
					   argv[++idx], argv[0]))
				return -1;
		} else if (strcmp(argv[idx], "--nom-freq") == 0) {
			if (!get_arg_uint8(&config->nom_freq, "--nom-freq",
					   argv[++idx], argv[0]))
				return -1;
		} else if (strcmp(argv[idx], "--cpuid-0x15.eax") == 0) {
			if (!get_arg_uint32(&config->cpuid_0x15_eax,
					    "--cpuid-0x15.eax", argv[++idx],
					    argv[0]))
				return -1;
		} else if (strcmp(argv[idx], "--cpuid-0x15.ebx") == 0) {
			if (!get_arg_uint32(&config->cpuid_0x15_ebx,
					    "--cpuid-0x15.ebx", argv[++idx],
					    argv[0]))
				return -1;
		} else
                        throw std::runtime_error(
                            std::string("unknown option \"") + argv[idx] +
                            std::string("\""));
        }

	return 0;
}


}

#endif /* x86 */
