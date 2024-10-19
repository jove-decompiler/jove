#if (defined(__x86_64__) || defined(__i386__)) &&                              \
    (defined(TARGET_X86_64) || defined(TARGET_I386))

#include "ipt.h"
#include "explore.h"
#include "objdump.h"

#include "syscall_nrs.hpp"

#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/preprocessor/variadic/size.hpp>

#include <intel-pt.h>
#include <libipt-sb.h>
#include <inttypes.h>

#include <type_traits>

extern "C" {
#include "pt_last_ip.c"
#include "pt_time.c"
}

namespace fs = boost::filesystem;

namespace jove {

//
// <from linux/tools/perf/util/bpf_skel/augmented_raw_syscalls.bpf.c>
//
template <typename UIntType>
struct syscall_enter_args {
  UIntType common_tp_fields;
  std::make_signed_t<UIntType> syscall_nr;
  UIntType args[6];
};

template <typename UIntType>
struct syscall_exit_args {
  UIntType common_tp_fields;
  std::make_signed_t<UIntType> syscall_nr;
  std::make_signed_t<UIntType> ret;
};

// Type aliases for 64-bit and 32-bit versions
using syscall_enter_args64 = syscall_enter_args<uint64_t>;
using syscall_enter_args32 = syscall_enter_args<uint32_t>;
using syscall_exit_args64 = syscall_exit_args<uint64_t>;
using syscall_exit_args32 = syscall_exit_args<uint32_t>;
//
// </>
//

typedef boost::format fmt;

// XXX
#define IsVerbose() (Verbosity >= 1)
#define IsVeryVerbose() (Verbosity >= 2)

template <unsigned Verbosity, bool Caching>
IntelPT<Verbosity, Caching>::IntelPT(int ptdump_argc, char **ptdump_argv,
                                     jv_t &jv, explorer_t &explorer,
                                     unsigned cpu,
                                     const address_space_t &AddressSpaceInit,
                                     void *begin, void *end, unsigned verbose,
                                     bool ignore_trunc_aux)
    : jv(jv), explorer(explorer), state(jv),
      IsCOFF(B::is_coff(*state.for_binary(jv.Binaries.at(0)).Bin)),
      AddressSpaceInit(AddressSpaceInit), CurrPoint(jv.Binaries.at(0)),
      ignore_trunc_aux(ignore_trunc_aux) {
  setvbuf(stderr, NULL, _IOLBF, 0); /* automatically flush on new-line */

  Our.cpu = cpu;

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
    if (errcode < 0)
      throw std::runtime_error("failed to determine errata");

    std::vector<uint8_t> zeros(sizeof(config->errata), 0);
    if (memcmp(&config->errata, &zeros[0], sizeof(config->errata)) != 0) {
      fprintf(stderr, "WARNING! CPU errata detected:");

#define __ERRATA(x)                                                            \
  do {                                                                         \
    if (config->errata.x)                                                      \
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

  int errcode = pt_sb_init_decoders(tracking.session);
  if (errcode < 0) {
    throw std::runtime_error(
        std::string("error initializing sideband decoders: ") +
        pt_errstr(pt_errcode(errcode)));
  }

  config->begin = reinterpret_cast<uint8_t *>(begin);
  config->end = reinterpret_cast<uint8_t *>(end);

  decoder = pt_pkt_alloc_decoder(config.get());

  sideband.os = open_memstream(&sideband.ptr, &sideband.len);
  if (!sideband.os)
    throw std::runtime_error(std::string("open_memstream() failed: ") +
                             strerror(errno));

  for (const auto &pair : AddressSpaceInit) {
    binary_index_t BIdx = pair.second;
    if (is_binary_index_valid(BIdx))
      state.for_binary(jv.Binaries.at(BIdx))._coff.LoadAddr =
          addr_intvl_lower(pair.first);
  }
}

template <unsigned Verbosity, bool Caching>
IntelPT<Verbosity, Caching>::~IntelPT() {
  pt_pkt_free_decoder(decoder);

#if 0
  int errcode = pt_sb_dump(tracking.session, stderr, sb_dump_flags, UINT64_MAX);
#endif

#if 0
  if (unlikely(errcode < 0))
    return diag("sideband dump error", UINT64_MAX, errcode);
#endif

  pt_sb_free(tracking.session);

  fclose(sideband.os);
  free(sideband.ptr);
}

template <unsigned Verbosity, bool Caching>
int IntelPT<Verbosity, Caching>::ptdump_print_error(int errcode,
                                                    const char *filename,
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

#if 0
static void hexdump(FILE *stream, const void *ptr, int buflen) {
  const unsigned char *buf = (const unsigned char*)ptr;
  int i, j;
  for (i=0; i<buflen; i+=16) {
    fprintf(stream, "%06x: ", i);
    for (j=0; j<16; j++)
      if (i+j < buflen)
        fprintf(stream, "%02x ", buf[i+j]);
      else
        fprintf(stream, "   ");
    printf(" ");
    for (j=0; j<16; j++)
      if (i+j < buflen)
        fprintf(stream, "%c", isprint(buf[i+j]) ? buf[i+j] : '.');
    fprintf(stream, "\n");
  }
}
#endif

template <unsigned Verbosity, bool Caching>
void IntelPT<Verbosity, Caching>::examine_sb(void) {
  fflush(sideband.os);

  char *ptr = sideband.ptr;
  char *const end = ptr + sideband.len;

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

#if 0
    if (IsVeryVerbose())
      fprintf(stderr, "%s\n", line);
#endif

    static const char sb_line_prefix[] = "PERF_RECORD_";
    constexpr unsigned sb_line_prefix_len = sizeof(sb_line_prefix)-1;

    if (unlikely(strncmp(line, sb_line_prefix, sb_line_prefix_len) != 0)) {
      if (likely(strncmp(line, "UNKNOWN", sizeof("UNKNOWN")-1) == 0))
        continue;

      fprintf(stderr, "unrecognized sideband line: \"%s\"\n", line);
      assert(false);
    }

#define MATCHES_REST(x)                                                        \
  (strncmp(rest, x "  ", (sizeof(x) - 1) + 2) == 0 && ({                       \
     rest += ((sizeof(x) - 1) + 2);                                            \
     assert(rest < eol);                                                       \
     true;                                                                     \
   }))

    char *rest = line + sb_line_prefix_len;

    struct {
      unsigned pid, tid;
      uint64_t time;
//    uint64_t id;
      unsigned cpu;
//    uint64_t stream_id;
      uint64_t identifier;
    } _; /* common to all records */

#define sscanf_rest(fmt, ...) do {                                             \
    int rc = sscanf(rest, fmt "  { %x/%x %" PRIx64 " cpu-%x %" PRIx64 " }",    \
                    __VA_ARGS__ __VA_OPT__(,)                                  \
                    &_.pid, &_.tid, &_.time, &_.cpu, &_.identifier);           \
    assert(rc != EOF);                                                         \
    assert(rc == BOOST_PP_VARIADIC_SIZE(__VA_ARGS__) + 5);                     \
  } while(0)

    auto do_comm_exec = [&](void) -> void {
      AddressSpace.clear();

      unsigned pid, tid;
      char comm[65];
      comm[0] = '\0';

      sscanf_rest("%x/%x, %64s", &pid, &tid, &comm[0]);

      if (boost::algorithm::ends_with(jv.Binaries.at(0).Name.c_str(), comm) ||
          Our.pid == pid) {
        if (IsVerbose())
          fprintf(stderr, "comm=%s\n", comm);

        if (IsCOFF) {
          if (Our.pid != pid)
            _wine.ExecCount = 1;
          else
            ++_wine.ExecCount;

          if (IsVerbose() && RightWineExecCount())
            fprintf(stderr, "second exec (%x)\n", static_cast<unsigned>(pid));
        }

        if (IsVerbose() && Our.pid != pid)
          fprintf(stderr, "our pid is %x\n", static_cast<unsigned>(pid));

        Our.pid = pid;
      }
    };

#define unexpected_rest()                                                      \
  do {                                                                         \
    fprintf(stderr, "unexpected rest=\"%s\"\n", rest);                         \
    assert(false);                                                             \
  } while (0)

    switch (rest[0]) {
    case 'A':
      if (likely(MATCHES_REST("AUX"))) {
        ;
      } else if (MATCHES_REST("AUX.TRUNCATED")) {
        uint64_t aux_offset, aux_size, aux_flags;
        sscanf_rest("%" PRIx64 ", %" PRIx64 ", %" PRIx64,
                    &aux_offset, &aux_size, &aux_flags);

        if (_.cpu == Our.cpu) {
          if (!ignore_trunc_aux)
            throw truncated_aux_exception();
        }
      } else {
        unexpected_rest();
      }
      break;

    case 'C':
      if (MATCHES_REST("COMM.EXEC")) {
        do_comm_exec();
      } else if (MATCHES_REST("COMM")) {
        //do_comm();
      } else {
        unexpected_rest();
      }
      CheckEngaged();
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
        sscanf_rest("%x/%x", &next_pid, &next_tid);

        if (_.cpu == Our.cpu) {
          Curr.pid = ~0u;
          Engaged = false;
        }
      } else if (MATCHES_REST("SWITCH.OUT")) {
        sscanf_rest("");

        if (_.cpu == Our.cpu) {
          Curr.pid = ~0u;
          Engaged = false;
        }
      } else if (MATCHES_REST("SWITCH_CPU_WIDE.IN")) {
        unsigned prev_pid, prev_tid;
        sscanf_rest("%x/%x", &prev_pid, &prev_tid);

        if (_.cpu == Our.cpu)
          Curr.pid = _.pid;

        CheckEngaged();
      } else if (MATCHES_REST("SWITCH.IN")) {
        sscanf_rest("");

        if (_.cpu == Our.cpu)
          Curr.pid = _.pid;

        CheckEngaged();
      } else if (MATCHES_REST("SAMPLE.RAW")) {
        std::string &hexbytes = this->__buff.s1;
        hexbytes.resize(4097);
        hexbytes[0] = '\0';

        char name[33];
        name[0] = '\0';

        sscanf_rest("%32[^,], %4096[0-9a-f]", &name[0], &hexbytes[0]);

        if (!IsRightProcess(_.pid))
          continue;

        {
          unsigned hexbytes_len = strlen(hexbytes.c_str());
          assert(hexbytes_len > 0);
          hexbytes.resize(hexbytes_len);
        }

        std::vector<uint8_t> &bytes = this->__buff.u8v;
        bytes.resize(hexbytes.size() / 2);
        for (unsigned i = 0; i < bytes.size(); ++i) {
          char hexbyte[3];
          hexbyte[0] = hexbytes[2*i];
          hexbyte[1] = hexbytes[2*i+1];
          hexbyte[2] = '\0';

          bytes[i] = strtol(hexbyte, nullptr, 16);
        }

        auto &state = syscall_state_map[_.tid];

        if (strcmp(name, "raw_syscalls:sys_exit") == 0) {
          long nr;
          taddr_t ret;

          auto syscall_exit_extract = [&]<typename UIntType>(void) -> bool {
            if (bytes.size() >= sizeof(syscall_exit_args<UIntType>)) {
              auto *p = (const syscall_exit_args<UIntType> *)bytes.data();
              nr = p->syscall_nr;
              ret = p->ret;
              return true;
            }

            return false;
          };

          if (!syscall_exit_extract.template operator()<uint64_t>() &&
              !syscall_exit_extract.template operator()<uint32_t>())
            unexpected_rest();

          bool two_consecutive_exits = state.dir != 0;
          bool mismatched_nr = nr != state.nr;

          if (unlikely(two_consecutive_exits || mismatched_nr)) {
            if (two_consecutive_exits) {
              if (mismatched_nr)
                fprintf(stderr, "two syscall exits in a row!\n");
              else
                fprintf(stderr, "two syscall exits in a row! (%ld)\n", nr);
            }
            if (mismatched_nr)
              fprintf(stderr, "mismatched syscall exit! (%ld != %ld)\n", nr,
                      state.nr);
            state.dir = state.nr = -1;
            break;
          }

          state.dir = 1;

          /* on syscall return */
          if (state.nr == syscalls::NR::munmap) {
            if (ret != 0)
              continue; /* failed */

            taddr_t addr = state.args[0];
            taddr_t len = state.args[1];

            const addr_intvl intvl(addr, len);

            if constexpr (IsVeryVerbose()) {
              std::string as(addr_intvl2str(intvl));

              fprintf(stderr, "[munmap] @ %s\n", as.c_str());
            }

            intvl_map_clear(AddressSpace, intvl);
          } else if (state.nr == syscalls::NR::mmap) {
            if (ret >= (taddr_t)-4095)
              continue; /* failed */

            taddr_t addr = state.args[0];
            taddr_t len = state.args[1];
            unsigned prot = state.args[2];
            unsigned flags = state.args[3];
            int fd = state.args[4];
            taddr_t off = state.args[5];

            if (prot & PROT_EXEC)
              continue; /* we will see PERF_RECORD_MMAP2 */

            const bool anon = fd < 0;

            if (IsCOFF) {
              const addr_intvl intvl(ret, len);

              if constexpr (IsVeryVerbose()) {
                std::string as(addr_intvl2str(intvl));

                fprintf(stderr, "[mmap]   @ %s in %s\n", as.c_str(),
                        anon ? "\"//anon\"" : nullptr);
              }

              intvl_map_clear(AddressSpace, intvl);

              auto it = intvl_map_find(AddressSpaceInit, intvl);
              if (it != AddressSpaceInit.end())
                intvl_map_add(AddressSpace, intvl, std::make_pair((*it).second, ~0UL));
            }
          } else {
            fprintf(stderr, "unhandled syscall %u!\n", (unsigned)state.nr);
            break;
          }
        } else if (strcmp(name, "raw_syscalls:sys_enter") == 0) {
          auto syscall_enter_extract = [&]<typename UIntType>(void) -> bool {
            if (bytes.size() >= sizeof(syscall_enter_args<UIntType>)) {
              auto *p = (const syscall_enter_args<UIntType> *)bytes.data();
              for (unsigned i = 0; i < state.args.size(); ++i)
                state.args[i] = p->args[i];
              state.nr = p->syscall_nr;
              return true;
            }
            return false;
          };

          if (!syscall_enter_extract.template operator()<uint64_t>() &&
              !syscall_enter_extract.template operator()<uint32_t>())
            unexpected_rest();

          state.dir = 0;
        } else {
          unexpected_rest();
        }
      } else {
        unexpected_rest();
      }
      break;

    case 'M': {
      unsigned pid, tid;
      uint64_t addr, len, pgoff;

      std::string &hexname = this->__buff.s1;

      hexname.resize(8193);
      hexname[0] = '\0';

      bool two;
      if (likely(two = MATCHES_REST("MMAP2"))) {
        unsigned maj, min;
        uint64_t ino, ino_generation;
        unsigned prot, flags;

        sscanf_rest("%x/%x, %" PRIx64
                    ", %" PRIx64 ", %" PRIx64 ", %x, %x, %" PRIx64
                    ", %" PRIx64 ", %x, %x, %8192[0-9a-f]",
                    &pid, &tid, &addr,
                    &len, &pgoff, &maj, &min, &ino,
                    &ino_generation, &prot, &flags, &hexname[0]);

        assert(prot & PROT_EXEC);
      } else if (likely(MATCHES_REST("MMAP"))) {
        sscanf_rest("%x/%x, %" PRIx64 ", %" PRIx64 ", %" PRIx64
                    ", %8192[0-9a-f]",
                    &pid, &tid, &addr, &len, &pgoff, &hexname[0]);
      } else {
        unexpected_rest();
      }

      assert(pid == _.pid);

      if (!IsRightProcess(pid))
        continue;

      {
        unsigned hexname_len = strlen(hexname.c_str());
        assert(hexname_len > 0);
        hexname.resize(hexname_len);
      }

      std::string &name = this->__buff.s2;
      name.resize(hexname.size() / 2);
      for (unsigned i = 0; i < name.size(); ++i) {
        char hexchar[3];
        hexchar[0] = hexname[2*i];
        hexchar[1] = hexname[2*i+1];
        hexchar[2] = '\0';

        name[i] = strtol(hexchar, nullptr, 16);
      }

      const addr_intvl intvl(addr, len);

      if constexpr (IsVeryVerbose()) {
        std::string as(addr_intvl2str(intvl));

        fprintf(stderr, "[MMAP%s  @ %s in \"%s\"\n", two ? "2]" : "] ",
                as.c_str(), name.c_str());
      }

      intvl_map_clear(AddressSpace, intvl);

      const bool anon = name == "//anon";
      if (anon) {
        if (IsCOFF) {
          auto it = intvl_map_find(AddressSpaceInit, intvl);
          if (it != AddressSpaceInit.end())
            intvl_map_add(AddressSpace, intvl, std::make_pair((*it).second, ~0UL));
        }
        continue;
      }

      binary_index_t BIdx;
      bool IsNew;
      if (name[0] == '/') {
        if (!fs::exists(name)) {
          if constexpr (IsVeryVerbose())
            fprintf(stderr, "\"%s\" does not exist(%s)\n", name.c_str(), rest);
          continue;
        }

        std::tie(BIdx, IsNew) = jv.AddFromPath(explorer, name.c_str());
        if (!is_binary_index_valid(BIdx))
          continue;
      } else {
        auto MaybeBIdxSet = jv.Lookup(name.c_str());
        if (!MaybeBIdxSet)
          continue;
        const ip_binary_index_set &BIdxSet = *MaybeBIdxSet;
        if (BIdxSet.empty())
          continue;

        BIdx = *(BIdxSet).rbegin(); /* most recent (XXX?) */
        IsNew = false;
      }

      binary_t &b = jv.Binaries.at(BIdx);
      binary_state_t &x = state.for_binary(b);

      intvl_map_add(AddressSpace, intvl, std::make_pair(BIdx, pgoff));
      break;
    }

    default:
      fprintf(stderr, "examine_sb: \"%s\" (TODO)\n", line);
      break;
    }

#undef unexpected_rest
#undef sscanf_rest
  } while (likely(ptr != end));
}

template <unsigned Verbosity, bool Caching>
int IntelPT<Verbosity, Caching>::explore(void) {
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

template <unsigned Verbosity, bool Caching>
int IntelPT<Verbosity, Caching>::explore_packets() {
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

    int ret = process_packet(offset, &packet);
    if (unlikely(ret <= 0))
      return ret;
  }

  return 0;
}

template <unsigned Verbosity, bool Caching>
int IntelPT<Verbosity, Caching>::process_packet(uint64_t offset,
                                                struct pt_packet *packet) {
  switch (packet->type) {
  case ppt_unknown:
  case ppt_invalid:
    return 1;

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
    return 1;

  case ppt_psbend:
    tracking.in_header = 0;
    return 1;

  case ppt_pad:
    return 1;

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
    return 1;

  case ppt_stop:
    return 1;

  case ppt_fup:
  case ppt_tip:
  case ppt_tip_pge:
  case ppt_tip_pgd: {
    int errcode;
    uint64_t ip;

    errcode = pt_last_ip_update_ip(tracking.last_ip.get(), &packet->payload.ip,
                                   config.get());
    if (unlikely(errcode < 0))
      throw std::runtime_error(
          std::string("IntelPT: error tracking last-ip at offset ") +
          std::to_string(offset));

    errcode = pt_last_ip_query(&ip, tracking.last_ip.get());
    if (unlikely(errcode < 0)) {
      if (errcode == -pte_ip_suppressed) {
        if (Engaged) {
          if constexpr (IsVeryVerbose())
            fprintf(stderr, "<suppressed>\n");

          CurrPoint.Invalidate();
        }
      } else {
        throw std::runtime_error(
            std::string("IntelPT: error tracking last-ip at offset ") +
            std::to_string(offset));
      }
    } else {
      on_ip(ip, offset);
    }

    return 1;
  }

  case ppt_pip: /* we'll never see this in userspace */
  case ppt_vmcs:
    return 1;

  case ppt_tnt_8:
  case ppt_tnt_64:
    return tnt_payload(packet->payload.tnt, offset);

  case ppt_mode: {
    const struct pt_packet_mode *mode = &packet->payload.mode;
    switch (mode->leaf) {
    case pt_mol_exec: {
      switch (pt_get_exec_mode(&mode->bits.exec)) {
      case ptem_64bit:
        Curr.ExecBits = 64;
        break;

      case ptem_32bit:
        Curr.ExecBits = 32;
        break;

      case ptem_16bit:
        Curr.ExecBits = 16;
        break;

      case ptem_unknown:
        Curr.ExecBits = ~0u;
        break;
      }

      CheckEngaged();

      int errcode;

      //
      // look ahead and, if IP packet, deal with it but don't examine IP,
      // because IIRC (from reading libipt) whatever it is would have been
      // reachable anyway without examining the trace- plus it might be BOGUS.
      //
      errcode = pt_pkt_get_offset(decoder, &offset);
      if (unlikely(errcode < 0))
        throw std::runtime_error(
            std::string("IntelPT: error getting offset: ") +
            pt_errstr(pt_errcode(errcode)));

      errcode = pt_pkt_next(decoder, packet, sizeof(*packet));
      if (unlikely(errcode < 0)) {
        if (errcode == -pte_eos)
          return 0;
        return errcode;
      }

      switch (packet->type) {
        default:
          break;
        case ppt_fup:
        case ppt_tip:
        case ppt_tip_pge:
        case ppt_tip_pgd:
          errcode = pt_last_ip_update_ip(tracking.last_ip.get(),
                                         &packet->payload.ip, config.get());
          if (unlikely(errcode < 0))
            throw std::runtime_error(
                std::string("IntelPT: error tracking last-ip at offset ") +
                std::to_string(offset));

          return 1;
      }

      __attribute__((musttail)) return process_packet(offset, packet);
    }

    case pt_mol_tsx:
      // assuming this is followed by a mode.exec, there's nothing we need to do
      return 1;
    }

    throw std::runtime_error(
        std::string("IntelPT: unknown mode leaf at offset ") +
        std::to_string(offset));
  }

  case ppt_tsc:
    track_tsc(offset, &packet->payload.tsc);
    return 1;

  case ppt_cbr:
    track_cbr(offset, &packet->payload.cbr);
    return 1;

  case ppt_tma:
    track_tma(offset, &packet->payload.tma);
    return 1;

  case ppt_mtc:
    track_mtc(offset, &packet->payload.mtc);
    return 1;

  case ppt_cyc:
    track_cyc(offset, &packet->payload.cyc);
    return 1;

  case ppt_mnt:
  case ppt_exstop:
  case ppt_mwait:
  case ppt_pwre:
  case ppt_pwrx:
  case ppt_ptw:
  case ppt_cfe:
  case ppt_evd:
  case ppt_trig:
    return 1;
  }

  throw std::runtime_error(
      std::string("IntelPT: unknown packet at offset ") +
      std::to_string(offset));
}

struct tnt_error {};
struct infinite_loop_exception {};

template <unsigned Verbosity, bool Caching>
int IntelPT<Verbosity, Caching>::tnt_payload(const struct pt_packet_tnt &packet,
                                             const uint64_t offset) {
  if (unlikely(!Engaged))
    return 1;

  if (unlikely(!CurrPoint.Valid())) {
    if constexpr (IsVeryVerbose())
      fprintf(stderr, "%" PRIx64 "\tunhandled tnt\n", offset);
    return 1;
  }

  auto Saved = CurrPoint;
  try {
    TNTAdvance(packet.payload, packet.bit_size);

    assert(CurrPoint.Valid());
    return 1;
  } catch (const tnt_error &) {
    if constexpr (IsVerbose())
      fprintf(stderr, "tnt error from %s+%" PRIx64 "\n",
              Saved.Binary().Name.c_str(),
              static_cast<uint64_t>(Saved.Address()));
  } catch (const infinite_loop_exception &) {
    if constexpr (IsVerbose())
      fprintf(stderr, "tnt error (infinite loop) from %s+%" PRIx64 "\n",
              Saved.Binary().Name.c_str(),
              static_cast<uint64_t>(Saved.Address()));
  }

  CurrPoint.Invalidate();
  return 1;
}

template <unsigned Verbosity, bool Caching>
int IntelPT<Verbosity, Caching>::on_ip(const taddr_t IP, const uint64_t offset) {
  if (unlikely(!Engaged)) {
    if constexpr (IsVeryVerbose())
      if (RightProcess())
        fprintf(stderr, "%" PRIx64 "\t__IP %016" PRIx64 "\n", offset, (uint64_t)IP);
    return 0;
  }

  // TODO (from libipt): ip < priv->kernel_start ? ploc_in_user : ploc_in_kernel
#if 0
  if (sizeof(taddr_t) == 4)
    assert(IP < 0xffffffffull);
#endif

  auto it = intvl_map_find(AddressSpace, IP);
  if (unlikely(it == AddressSpace.end())) {
    if constexpr (IsVeryVerbose())
      fprintf(stderr, "%" PRIx64 "\tunknown IP %016" PRIx64 "\n", offset, (uint64_t)IP);

    CurrPoint.Invalidate();
    return 1;
  }

  const binary_index_t BIdx = (*it).second.first;
  if (unlikely(!is_binary_index_valid(BIdx))) {
    if constexpr (IsVerbose())
      fprintf(stderr, "%" PRIx64 "\tambiguous IP %016" PRIx64 "\n", offset, (uint64_t)IP);

    CurrPoint.Invalidate();
    return 1;
  }

  binary_t &b = jv.Binaries.at(BIdx);

  struct {
    taddr_t Base;
    uint64_t Offset;
  } mapping;

  mapping.Base = addr_intvl_lower((*it).first);
  mapping.Offset = (*it).second.second;

  const uint64_t Addr = ({
    binary_state_t &x = state.for_binary(b);
    B::_X(
        *x.Bin,
        [&](ELFO &O) -> uint64_t {
          assert(~mapping.Offset != 0);
          assert(IP >= mapping.Base);
          assert(static_cast<uint64_t>(mapping.Base) >= mapping.Offset);

          uint64_t off = IP - (mapping.Base - mapping.Offset);
          try {
            return elf::va_of_offset(O, off);
          } catch (...) {
            std::string as(addr_intvl2str((*it).first));
            fprintf(stderr,
                    "WTFF! %" PRIx64 " in %s: off=%" PRIx64
                    " in \"%s\" mapping.Base=%" PRIx64
                    " mapping.Offset=%" PRIx64 " \n",
                    (uint64_t)IP, as.c_str(), off, b.Name.c_str(),
                    (uint64_t)mapping.Base, mapping.Offset);
            abort();
          }
        },
        [&](COFFO &O) -> uint64_t {
          try {
            if (~x._coff.LoadAddr == 0) {
              assert(~mapping.Offset != 0);
              uint64_t off = IP - (mapping.Base - mapping.Offset);
              return coff::va_of_offset(O, off);
            } else {
              const taddr_t hmod = x._coff.LoadAddr;
              assert(IP >= hmod);
              taddr_t RVA = IP - hmod;
              return coff::va_of_rva(O, RVA);
            }
          } catch (...) {
            std::string as(addr_intvl2str((*it).first));
            fprintf(stderr,
                    "WTFF! %" PRIx64 " in %s in \"%s\" mapping.Base=%" PRIx64
                    " mapping.Offset=%" PRIx64 " \n",
                    (uint64_t)IP, as.c_str(), b.Name.c_str(),
                    (uint64_t)mapping.Base, mapping.Offset);
            abort();
          }
        });
  });

  if constexpr (IsVeryVerbose())
    fprintf(stderr, "%" PRIx64 "\t<IP> %016" PRIx64 " %s+%" PRIx64 "\n", offset,
            (uint64_t)IP, b.Name.c_str(), (uint64_t)Addr);

  if (CurrPoint.Valid()) {
    auto set_curr_term_addr =
        [&](basic_block_index_t BBIdx) -> basic_block_index_t {
      CurrPoint.SetTermAddr(address_of_basic_block_terminator(
          basic_block_of_index(BBIdx, CurrPoint.Binary()), CurrPoint.Binary()));
      return BBIdx;
    };
    if (CurrPoint.BinaryIndex() == BIdx) {
      bool WentNoFurther = false;
      basic_block_index_t NewBBIdx;

      std::tie(NewBBIdx, WentNoFurther) = StraightLineUntilSlow<false>(
          b, CurrPoint.BlockIndex(), Addr, set_curr_term_addr);
      CurrPoint.SetBlockIndex(NewBBIdx);

      assert(CurrPoint.Valid());
      if (WentNoFurther) {
        if constexpr (IsVeryVerbose())
            fprintf(stderr, "no further %s+%" PRIx64 "\n</IP>\n",
                    b.Name.c_str(), (uint64_t)Addr);
        return 0;
      }
    } else {
      if constexpr (Caching) {
        try {
          auto &x = state.for_basic_block(CurrPoint.Binary(), CurrPoint.Block());
          CurrPoint.SetBlockIndex(x.SL.BBIdx);
          CurrPoint.SetTermAddr(x.SL.TermAddr);
        } catch (const infinite_loop_exception &) {
          CurrPoint.Invalidate();
        }
      } else {
      CurrPoint.SetBlockIndex(StraightLineSlow<false>(
          CurrPoint.Binary(), CurrPoint.BlockIndex(), set_curr_term_addr));
      assert(CurrPoint.Valid());
      }
    }
  }

  binary_state_t &x = state.for_binary(b);
  if (!b.bbbmap.contains(Addr) && unlikely(x.__objdump.is_addr_bad(Addr))) {
    if constexpr (IsVerbose())
      fprintf(stderr,
              "OBJDUMP SAYS \"BADIP!\" %" PRIx64 "\t<IP> %" PRIx64 " %s+%" PRIx64 "\n",
              offset, (uint64_t)IP, b.Name.c_str(), (uint64_t)Addr);

    if constexpr (IsVeryVerbose())
      fprintf(stderr, "</IP>\n");

    CurrPoint.Invalidate();
    return 1;
  }

  const auto PrevPoint = CurrPoint;
  try {
    auto obp = [&]<bool Unlocked>(basic_block_t bb) -> void {
      const auto &bbprop = b.Analysis.ICFG[bb];

      // lock if necessary so we see the terminator address when it is published
      std::conditional_t<Unlocked, ip_sharable_lock<ip_sharable_mutex>,
                         __do_nothing_t> __may_s_lck(bbprop.mtx);

      CurrPoint.SetTermAddr(bbprop.Term.Addr);
    };

    CurrPoint.SetBinary(b);
    CurrPoint.SetBlockIndex(explorer.explore_basic_block(
        b, *x.Bin, Addr,
        [=](basic_block_t bb) -> void { obp.template operator()<false>(bb); },
        [=](basic_block_t bb) -> void { obp.template operator()<true>(bb); }));
    assert(CurrPoint.Valid());

    on_block(b, CurrPoint.BlockIndex());
  } catch (const invalid_control_flow_exception &) {
    if constexpr (IsVerbose())
      fprintf(stderr, "BADIP %" PRIx64 "\t<IP> %" PRIx64 " %s+%" PRIx64 "\n",
              offset, (uint64_t)IP, b.Name.c_str(), (uint64_t)Addr);

    if constexpr (IsVeryVerbose())
      fprintf(stderr, "</IP>\n");

    CurrPoint.Invalidate();
    return 1;
  }

  if (PrevPoint.Valid() && CurrPoint.Valid()) {
    assert(is_taddr_valid(PrevPoint.GetTermAddr()));
    block_transfer(PrevPoint.Binary(), PrevPoint.GetTermAddr(),
                   CurrPoint.Binary(), address_of_basic_block(CurrPoint.Block(), b));
  }

  if constexpr (IsVeryVerbose())
    fprintf(stderr, "</IP>\n");

  return 0;
}

template <unsigned Verbosity, bool Caching>
void IntelPT<Verbosity, Caching>::block_transfer(binary_t &fr_b,
                                                 taddr_t FrTermAddr,
                                                 binary_t &to_b,
                                                 taddr_t ToAddr) {
  const binary_index_t FrBIdx = index_of_binary(fr_b);
  const binary_index_t ToBIdx = index_of_binary(to_b);

  auto &fr_ICFG = fr_b.Analysis.ICFG;
  auto &to_ICFG = to_b.Analysis.ICFG;

  if constexpr (IsVeryVerbose())
    fprintf(stderr, "%s+%" PRIx64 " ==> "
           "%s+%" PRIx64 "\n",
           fr_b.Name.c_str(), (uint64_t)FrTermAddr, to_b.Name.c_str(),
           (uint64_t)ToAddr);

  TERMINATOR TermType;
  bool Term_indirect_jump_IsLj;

  ({
    ip_sharable_lock<ip_sharable_mutex> fr_s_lck_bbmap(fr_b.bbmap_mtx);

    const auto &Term = fr_ICFG[basic_block_at_address(FrTermAddr, fr_b)].Term;

    TermType = Term.Type;
    Term_indirect_jump_IsLj = Term._indirect_jump.IsLj;
  });

  basic_block_t to_bb = basic_block_starting_at_address(ToAddr, to_b);

  auto handle_indirect_call = [&](void) -> void {
    function_index_t FIdx =
        explorer.explore_function(to_b, *state.for_binary(to_b).Bin, ToAddr);

    if (!is_function_index_valid(FIdx))
      return;

    ip_sharable_lock<ip_sharable_mutex> fr_s_lck(fr_b.bbmap_mtx);

    basic_block_t fr_bb = basic_block_at_address(FrTermAddr, fr_b);
    basic_block_properties_t &fr_bbprop = fr_ICFG[fr_bb];

    fr_bbprop.insertDynTarget(FrBIdx, std::make_pair(ToBIdx, FIdx), jv);
  };

  switch (TermType) {
  case TERMINATOR::INDIRECT_JUMP: {
    if (Term_indirect_jump_IsLj)
      break;

    const bool TailCall = ({
      ip_sharable_lock<ip_sharable_mutex> fr_s_lck_bbmap(fr_b.bbmap_mtx);

      IsDefinitelyTailCall(fr_ICFG, basic_block_at_address(FrTermAddr, fr_b));
    });

    if (TailCall) {
      handle_indirect_call();
    } else if (FrBIdx != ToBIdx) {
      handle_indirect_call();
      fr_b.FixAmbiguousIndirectJump(FrTermAddr, explorer, *state.for_binary(fr_b).Bin, jv);
    } else {
      assert(FrBIdx == ToBIdx);

      ip_sharable_lock<ip_sharable_mutex> fr_s_lck_bbmap(fr_b.bbmap_mtx);

      fr_ICFG.add_edge(basic_block_at_address(FrTermAddr, fr_b), to_bb);
    }

    break;
  }

  case TERMINATOR::INDIRECT_CALL: {
    handle_indirect_call();
    break;
  }

  case TERMINATOR::RETURN: {
    {
      ip_sharable_lock<ip_sharable_mutex> fr_s_lck_bbmap(fr_b.bbmap_mtx);

      fr_ICFG[basic_block_at_address(FrTermAddr, fr_b)].Term._return.Returns = true;
    }

    //
    // what came before?
    //
    const taddr_t before_pc = ToAddr - 1;

    ip_sharable_lock<ip_sharable_mutex> to_s_lck_bbmap(to_b.bbmap_mtx);

    if (!exists_basic_block_at_address(before_pc, to_b))
      break;

    basic_block_t before_bb = basic_block_at_address(before_pc, to_b);
    basic_block_properties_t &before_bbprop = to_ICFG.at(before_bb);
    auto &before_Term = before_bbprop.Term;

    bool isCall = before_Term.Type == TERMINATOR::CALL;
    bool isIndirectCall = before_Term.Type == TERMINATOR::INDIRECT_CALL;
    if (isCall || isIndirectCall) {
      assert(to_ICFG.out_degree(before_bb) <= 1);

      if (isCall) {
        if (likely(is_function_index_valid(before_Term._call.Target)))
          to_b.Analysis.Functions.at(before_Term._call.Target).Returns = true;
      }

      to_ICFG.add_edge(before_bb, to_bb); /* connect */
    }
    break;
  }

  default:
    return;
  }
}

template <bool DoNotGoFurther, bool InfiniteLoopThrow, unsigned Verbosity = 0>
static std::pair<basic_block_index_t, bool>
StraightLineGo(const binary_t &b,
               basic_block_index_t Res,
               taddr_t GoNoFurther = 0,
               std::function<void(basic_block_t)> on_block = [](basic_block_t) -> void {},
               std::function<basic_block_index_t (basic_block_index_t)> on_final_block = [](basic_block_index_t Res) -> basic_block_index_t { return Res; }) {
  const auto &ICFG = b.Analysis.ICFG;

  std::reference_wrapper<const basic_block_properties_t> the_bbprop =
      ICFG[basic_block_of_index(Res, b)];

  basic_block_index_t ResSav = Res;
  for (
       (void)({
         ip_sharable_lock<ip_sharable_mutex>(the_bbprop.get().init_mtx);
         the_bbprop.get().mtx.lock_sharable();
         0;
       });
       ;
       (void)({
         the_bbprop.get().mtx.unlock_sharable();

         //
         // cycle detection: the code might infinitely loop. FIXME
         //
         // an example seen in the wild is at the end of start_thread() in
         // glibc/nptl/pthread_create.c...
         //
         // while (1)
         //   INTERNAL_SYSCALL_CALL (exit, 0);
         //
         if (unlikely(ResSav == Res)) {
           if constexpr (InfiniteLoopThrow)
             throw infinite_loop_exception();
           else
             return std::make_pair(invalid_basic_block_index, false);
         }

         ResSav = Res;

         basic_block_t newbb = basic_block_of_index(Res, b);
         const basic_block_properties_t &new_bbprop = ICFG[newbb];
         the_bbprop = new_bbprop;

         ip_sharable_lock<ip_sharable_mutex>(new_bbprop.init_mtx);
         new_bbprop.mtx.lock_sharable();

         on_block(newbb);
         0;
       })) {
    basic_block_t bb = basic_block_of_index(Res, b);
    const basic_block_properties_t &bbprop = the_bbprop.get();

    const auto Addr = bbprop.Addr;
    const auto Size = bbprop.Size;
    const auto TermType = bbprop.Term.Type;

    if constexpr (DoNotGoFurther) {
      if (Addr == GoNoFurther ||
          /* the following assumes that GoNoFurther sits cleanly in the block.
           * to verify this, we'd have to disassemble the instructions.
           *
           * NOTE: this happens to "resolve" a problem encountered with the
           * trace output, where an invalid IP follows a twirl. i.e., given the
           * code:
           *
           * 18d70:       f3 0f 1e fb             endbr32
           * 18d74:       e8 00 00 00 00          call   18d79
           * 18d79:       58                      pop    %eax
           * 18d7a:       05 23 b2 ff ff          add    $0xffffb223,%eax
           * 18d7f:       8b 80 38 00 00 00       mov    0x38(%eax),%eax
           *
           * we might have the following sequence:
           *
           *   on_ip(0x18d70);
           *   on_ip(0x18d76);  // <-- WTF, middle of twirl instruction
           *
           * this has been confirmed to confuse the hell out of ptxed.
           *
           **/
          unlikely(GoNoFurther >= Addr && GoNoFurther < Addr + Size)) {
        ip_sharable_lock<ip_sharable_mutex> s_lck_bb(
            bbprop.mtx, boost::interprocess::accept_ownership);
        return std::make_pair(on_final_block(basic_block_of_index(Res, b)), true);
      }
    }

    switch (TermType) {
    default:
      break;
    case TERMINATOR::UNCONDITIONAL_JUMP:
    case TERMINATOR::NONE: {
      if (unlikely(ICFG.out_degree<false>(bb) == 0)) {
        if constexpr (IsVerbose())
          fprintf(stderr, "cant proceed past NONE @ %s+%" PRIx64 " [size=%u] %s\n",
                  b.Name.c_str(),
                  static_cast<uint64_t>(Addr),
                  static_cast<unsigned>(Size),
                  description_of_terminator(TermType));
        break;
      }

      basic_block_index_t NewRes =
          index_of_basic_block(ICFG, ICFG.adjacent_front<false>(bb));

      Res = NewRes;
      continue;
    }
    case TERMINATOR::CALL: {
      function_index_t CalleeIdx = bbprop.Term._call.Target;
      if (unlikely(!is_function_index_valid(CalleeIdx)))
        break;

      basic_block_index_t EntryBBIdx = b.Analysis.Functions.at(CalleeIdx).Entry;
      if (!unlikely(is_basic_block_index_valid(EntryBBIdx))) {
        if constexpr (IsVerbose())
          fprintf(stderr, "cant proceed past CALL @ %s+%" PRIx64 "\n",
                  b.Name.c_str(), static_cast<uint64_t>(Addr));
        break;
      }
      Res = EntryBBIdx;
      assert(is_basic_block_index_valid(Res));
      continue;
    }
    case TERMINATOR::CONDITIONAL_JUMP:
      //
      // recognize this:
      //
      // ┌─────────────────────────────────────┐
      // │                                     │ ───┐
      // │ rep  stosq qword ptr es:[rdi], rax  │    │
      // │                                     │ ◀──┘
      // └─────────────────────────────────────┘
      //
      // there are no TNT packets for this "single-instruction" loop. we just
      // need to move past it.
      //
      if (unlikely(bbprop.IsSingleInstruction())) {
        if (likely(ICFG.out_degree<false>(bb) == 2)) {
          auto succ = ICFG.adjacent_n<2, false>(bb);
          if (succ[0] == bb) {
            Res = index_of_basic_block(ICFG, succ[1]);
            continue;
          } else if (succ[1] == bb) {
            Res = index_of_basic_block(ICFG, succ[0]);
            continue;
          }
        }
      }
      break;
    }

    ip_sharable_lock<ip_sharable_mutex> s_lck_bb(
        bbprop.mtx, boost::interprocess::accept_ownership);
    return std::make_pair(on_final_block(basic_block_of_index(Res, b)), false);
  }

  abort();
}

template <unsigned Verbosity, bool Caching>
template <bool InfiniteLoopThrow>
std::pair<basic_block_index_t, bool>
IntelPT<Verbosity, Caching>::StraightLineUntilSlow(
    const binary_t &b,
    basic_block_index_t From,
    taddr_t GoNoFurther,
    std::function<basic_block_index_t(basic_block_index_t)> on_final_block) {
  return StraightLineGo<true, InfiniteLoopThrow, Verbosity>(
      b, From, GoNoFurther,
      std::bind(&IntelPT<Verbosity, Caching>::on_block, this, std::ref(b),
                std::placeholders::_1), on_final_block);
}

template <unsigned Verbosity, bool Caching>
template <bool InfiniteLoopThrow>
basic_block_index_t IntelPT<Verbosity, Caching>::StraightLineSlow(
    const binary_t &b,
    basic_block_index_t From,
    std::function<basic_block_index_t(basic_block_index_t)> on_final_block) {
  return StraightLineGo<false, InfiniteLoopThrow, Verbosity>(
      b, From, 0 /* unused */,
      std::bind(&IntelPT<Verbosity, Caching>::on_block, this, std::ref(b),
                std::placeholders::_1), on_final_block).first;
}

template <unsigned Verbosity, bool Caching>
void IntelPT<Verbosity, Caching>::on_block(const binary_t &b,
                                           basic_block_index_t BBIdx) {
  if constexpr (IsVeryVerbose()) {
    binary_state_t &x = state.for_binary(b);

    const auto &ICFG = b.Analysis.ICFG;

    auto Addr = ICFG[basic_block_of_index(BBIdx, b)].Addr;

    fprintf(stderr, "%s+%016" PRIx64 "\n", b.Name.c_str(), (uint64_t)Addr);
    fprintf(stdout, "%s+%016" PRIx64 "\n", b.Name.c_str(), (uint64_t)Addr);
  }
}

template <unsigned Verbosity, bool Caching>
void IntelPT<Verbosity, Caching>::TNTAdvance(uint64_t tnt, uint8_t n) {
  assert(n > 0);

  if constexpr (IsVeryVerbose())
    fprintf(stderr, "<TNT>\n");

  binary_t &b = CurrPoint.Binary();
  basic_block_index_t Res = CurrPoint.BlockIndex();

  const auto &ICFG = b.Analysis.ICFG;
  do {
    const bool Taken = !!(tnt & (1ull << (n - 1)));

    if constexpr (Caching) {
      basic_block_t bb = basic_block_of_index(Res, b);
      auto &x = state.for_basic_block(b, bb);
      if (unlikely(x.SL.adj.empty())) {
        if constexpr (IsVerbose())
          fprintf(stderr,
                  "not/invalid conditional branch @ %s+%" PRIx64 " (%s)\n",
                  b.Name.c_str(), static_cast<uint64_t>(x.SL.Addr),
                  string_of_terminator(x.SL.TermType));
        throw tnt_error();
      }
      assert(x.SL.adj.size() == 2);
      Res = x.SL.adj[static_cast<unsigned>(Taken)];
    } else {
    Res = StraightLineSlow<true>(
        b, Res, [&](basic_block_index_t BBIdx) -> basic_block_index_t {
          basic_block_t bb = basic_block_of_index(BBIdx, b);
          const basic_block_properties_t &bbprop = ICFG[bb];

          unsigned out_deg = ICFG.out_degree<false>(bb);

          if (unlikely(bbprop.Term.Type != TERMINATOR::CONDITIONAL_JUMP) ||
              unlikely(out_deg == 0)) {
            if constexpr (IsVerbose())
              fprintf(stderr,
                      "not/invalid conditional branch @ %s+%" PRIx64 " (%s)\n",
                      b.Name.c_str(), static_cast<uint64_t>(bbprop.Addr),
                      string_of_terminator(bbprop.Term.Type));
            throw tnt_error();
          }

          if (unlikely(out_deg == 1))
            return index_of_basic_block(ICFG, ICFG.adjacent_front<false>(bb));

          assert(out_deg == 2);

          auto succ = ICFG.adjacent_n<2, false>(bb);
          const bool Is0NotTaking =
              ICFG[succ[0]].Addr == bbprop.Addr + bbprop.Size;

          return index_of_basic_block(
              ICFG, Taken ? (Is0NotTaking ? succ[1] : succ[0])
                          : (Is0NotTaking ? succ[0] : succ[1]));
        });
    }

#if 0
    const char *extra = n > 1 ? " " : "";
    fprintf(stderr, "%d%s", (int)Taken, extra);
#endif
  } while (--n);

  if constexpr (Caching) {
    basic_block_t bb = basic_block_of_index(Res, b);
    auto &x = state.for_basic_block(b, bb);
    CurrPoint.SetBlockIndex(x.SL.BBIdx);
    CurrPoint.SetTermAddr(x.SL.TermAddr);
  } else {
  CurrPoint.SetBlockIndex(StraightLineSlow<true>(
      b, Res, [&](basic_block_index_t BBIdx) -> basic_block_index_t {
        CurrPoint.SetTermAddr(address_of_basic_block_terminator(
            basic_block_of_index(BBIdx, b), b));
        return BBIdx;
      }));
  }

  if constexpr (IsVeryVerbose())
    fprintf(stderr, "</TNT>\n");
}

template <unsigned Verbosity, bool Caching>
void IntelPT<Verbosity, Caching>::ptdump_tracking_init(void)
{
  pt_last_ip_init(tracking.last_ip.get());
  pt_tcal_init(tracking.tcal.get());
  pt_time_init(tracking.time.get());

  tracking.session = NULL;
  tracking.tsc = 0ull;
  tracking.fcr = 0ull;
  tracking.in_header = 0;
}

template <unsigned Verbosity, bool Caching>
void IntelPT<Verbosity, Caching>::ptdump_tracking_reset(void) {
  pt_last_ip_init(tracking.last_ip.get());
  pt_tcal_init(tracking.tcal.get());
  pt_time_init(tracking.time.get());

  tracking.tsc = 0ull;
  tracking.fcr = 0ull;
  tracking.in_header = 0;
}

template <unsigned Verbosity, bool Caching>
int IntelPT<Verbosity, Caching>::sb_track_time(uint64_t offset)
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

        rewind(sideband.os);
        errcode = pt_sb_dump(tracking.session, sideband.os, sb_dump_flags, tsc);
        if (unlikely(errcode < 0))
#if 0
		return diag("sideband dump error", offset, errcode);
#else
		return errcode;
#endif
        examine_sb();
        return 0;
}

template <unsigned Verbosity, bool Caching>
int IntelPT<Verbosity, Caching>::track_time(uint64_t offset) {
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

template <unsigned Verbosity, bool Caching>
int IntelPT<Verbosity, Caching>::track_tsc(uint64_t offset,
                                           const struct pt_packet_tsc *packet) {
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

template <unsigned Verbosity, bool Caching>
int IntelPT<Verbosity, Caching>::track_cbr(uint64_t offset,
                                           const struct pt_packet_cbr *packet) {
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

template <unsigned Verbosity, bool Caching>
int IntelPT<Verbosity, Caching>::track_tma(uint64_t offset,
                                           const struct pt_packet_tma *packet) {
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

template <unsigned Verbosity, bool Caching>
int IntelPT<Verbosity, Caching>::track_mtc(uint64_t offset,
                                           const struct pt_packet_mtc *packet) {
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

template <unsigned Verbosity, bool Caching>
int IntelPT<Verbosity, Caching>::track_cyc(uint64_t offset,
                                           const struct pt_packet_cyc *packet) {
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

template <unsigned Verbosity, bool Caching>
int IntelPT<Verbosity, Caching>::ptdump_sb_pevent(char *filename,
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

	strncpy(sample_config->stypes[nstypes].name, name, sizeof(sample_config->stypes[nstypes].name));

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


template <unsigned Verbosity, bool Caching>
int IntelPT<Verbosity, Caching>::process_args(int argc, char **argv)
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

template <unsigned Verbosity, bool Caching>
IntelPT<Verbosity, Caching>::binary_state_t::binary_state_t(const binary_t &b) {
  Bin = B::Create(b.data());

  binary_t::Analysis_t::objdump_t &objdump =
      const_cast<binary_t &>(b).Analysis.objdump;

  if (objdump.empty()) {
    ip_scoped_lock<ip_sharable_mutex> e_lck(objdump.mtx);

    if (objdump.good.empty())
      run_objdump_and_parse_addresses(b.is_file() ? b.Name.c_str() : nullptr,
                                      *Bin, objdump);
  }

  // make a copy
  std::vector<unsigned long> blocks(objdump.good.num_blocks());
  boost::to_block_range(objdump.good, blocks.begin());

  __objdump.begin = objdump.begin;
  __objdump.good = boost::dynamic_bitset<unsigned long>(blocks.begin(), blocks.end());
  __objdump.good.resize(objdump.good.size());
}

template <unsigned Verbosity, bool Caching>
IntelPT<Verbosity, Caching>::basic_block_state_t::basic_block_state_t(
    const binary_t &b, basic_block_t bb) {
  if constexpr (!Caching)
    return;

  auto &ICFG = b.Analysis.ICFG;

  const basic_block_index_t Idx = index_of_basic_block(b, bb);
  assert(is_basic_block_index_valid(Idx));

  this->SL.BBIdx = StraightLineGo<false, true, Verbosity>(
      b, Idx, 0 /* unused */,
      [](basic_block_t) -> void {},
      [&](basic_block_index_t BBIdx) -> basic_block_index_t {
        basic_block_t bb = basic_block_of_index(BBIdx, b);
        const auto &bbprop = ICFG[bb];

        this->SL.Addr = bbprop.Addr;
//      this->SL.Size = bbprop.Size;
        this->SL.TermType = bbprop.Term.Type;
        this->SL.TermAddr = bbprop.Term.Addr;

        {
          icfg_t::adjacency_iterator it, it_end;
          std::tie(it, it_end) = ICFG.adjacent_vertices(bb);

          unsigned N = std::distance(it, it_end);
          if (N == 1) {
            SL.adj.push_back(*it);
            SL.adj.push_back(*it);
          } else if (N == 2 && SL.TermType == TERMINATOR::CONDITIONAL_JUMP) {
            basic_block_index_t succ0 = *it++;
            basic_block_index_t succ1 = *it++;

            bool Is0NotTaking = ICFG[succ0].Addr == bbprop.Addr + bbprop.Size;
            if (Is0NotTaking) {
              this->SL.adj.push_back(succ0);
              this->SL.adj.push_back(succ1);
            } else {
              this->SL.adj.push_back(succ1);
              this->SL.adj.push_back(succ0);
            }
          } else {
            ;
          }
        }

        return BBIdx;
      }).first;
  assert(is_basic_block_index_valid(SL.BBIdx));
}

#undef IsVerbose
#undef IsVeryVerbose

template class IntelPT<0, true>;
template class IntelPT<1, true>;
template class IntelPT<2, true>;

template class IntelPT<0, false>;
template class IntelPT<1, false>;
template class IntelPT<2, false>;

}

#endif /* x86 */
