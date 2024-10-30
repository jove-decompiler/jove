#if (defined(__x86_64__) || defined(__i386__)) &&                              \
    (defined(TARGET_X86_64) || defined(TARGET_I386))

#include "ipt.h"
#include "explore.h"
#include "objdump.h"
#include "concurrent.h"
#include "augmented_raw_syscalls.h"

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
#include "pevent.h"
#include "pt_last_ip.c"
#include "pt_time.c"
}

namespace fs = boost::filesystem;

namespace jove {

typedef boost::format fmt;

#define IsVerbose() (Verbosity >= 1)
#define IsVeryVerbose() (Verbosity >= 2)

template <IPT_PARAMETERS_DCL>
IntelPT<IPT_PARAMETERS_DEF>::IntelPT(int ptdump_argc, char **ptdump_argv,
                                     jv_t &jv, explorer_t &explorer,
                                     unsigned cpu,
                                     const address_space_t &AddressSpaceInit,
                                     void *begin, void *end,
                                     const char *sb_filename, unsigned verbose,
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

  if (process_args(ptdump_argc, ptdump_argv, sb_filename) != 0)
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

  for (const auto &pair : AddressSpaceInit) {
    binary_index_t BIdx = pair.second;
    if (is_binary_index_valid(BIdx))
      state.for_binary(jv.Binaries.at(BIdx))._coff.LoadAddr =
          addr_intvl_lower(pair.first);
  }
}

template <IPT_PARAMETERS_DCL>
IntelPT<IPT_PARAMETERS_DEF>::~IntelPT() {
  pt_pkt_free_decoder(decoder);

#if 0
  int errcode = pt_sb_dump(tracking.session, stderr, sb_dump_flags, UINT64_MAX);
#endif

#if 0
  if (unlikely(errcode < 0))
    return diag("sideband dump error", UINT64_MAX, errcode);
#endif

  pt_sb_free(tracking.session);
}

template <IPT_PARAMETERS_DCL>
int IntelPT<IPT_PARAMETERS_DEF>::ptdump_print_error(int errcode,
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

#if 1
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

template <IPT_PARAMETERS_DCL>
void IntelPT<IPT_PARAMETERS_DEF>::examine_sb_event(const struct pev_event &event, uint64_t offset) {
    auto do_comm_exec = [&](const struct pev_record_comm &comm) -> void {
      AddressSpace.clear();

      std::string name(comm.comm);

      const auto &pid = comm.pid;
      const auto &tid = comm.tid;

      if (boost::algorithm::ends_with(jv.Binaries.at(0).Name.c_str(), name) ||
          Our.pid == pid) {
        if constexpr (IsVerbose())
          fprintf(stderr, "comm.exec \"%s\"\n", comm.comm);

        if (IsCOFF) {
          if (Our.pid != pid)
            _wine.ExecCount = 1;
          else
            ++_wine.ExecCount;

          if constexpr (IsVerbose()) {
            if (RightWineExecCount())
              fprintf(stderr, "second exec for %u\n",
                      static_cast<unsigned>(pid));
            else
              fprintf(stderr, "wrong exec count (%u) for %u\n",
                      _wine.ExecCount,
                      static_cast<unsigned>(pid));
          }
        }

        if (IsVerbose() && Our.pid != pid)
          fprintf(stderr, "our pid is %u\n", static_cast<unsigned>(pid));

        Our.pid = pid;
      }
    };

#define unexpected_rest()                                                      \
  do {                                                                         \
    fprintf(stderr, "unexpected rest (%" PRIu32 ")\n", event.type);            \
    assert(false);                                                             \
    abort();\
  } while (0)

    uint32_t pid = ~0u;
    uint32_t tid = ~0u;
    if (event.sample.pid)
      pid = *event.sample.pid;
    if (event.sample.tid)
      tid = *event.sample.tid;

    unsigned cpu = ~0u;
    if (event.sample.cpu)
      cpu = *event.sample.cpu;

    struct {
      bool two = true;

      unsigned pid, tid;
      uint64_t addr, len, pgoff;
      const char *filename;
    } _mmap;

    switch (event.type) {
      case PERF_RECORD_AUX: {
        const struct pev_record_aux *aux = event.record.aux;
        assert(aux);
        if (aux->flags & PERF_AUX_FLAG_TRUNCATED) {
          if (cpu == Our.cpu) {
            if (!ignore_trunc_aux)
              throw truncated_aux_exception();
          }
        }
        break;
      }

    case PERF_RECORD_COMM: {
		const struct pev_record_comm *comm = event.record.comm;
                assert(comm);
      if (event.misc & PERF_RECORD_MISC_COMM_EXEC) {
        do_comm_exec(*comm);
      CheckEngaged();
      }
      break;
    }

    case PERF_RECORD_FORK: {
      const struct pev_record_fork *fork = event.record.fork;
      assert(fork);

      if constexpr (IsVeryVerbose())
        fprintf(stderr, "%016" PRIx64 "\tfork %u/%u, %u/%u\n", offset, fork->pid,
                fork->tid, fork->ppid, fork->ptid);
      break;
    }

    case PERF_RECORD_LOST_SAMPLES: {
      const struct pev_record_lost_samples *lost_samples = event.record.lost_samples;
      assert(lost_samples);

      if constexpr (IsVeryVerbose())
        fprintf(stderr, "%016" PRIx64 "\tlost_samples %" PRIx64 "\n",
                offset, lost_samples->lost);
      break;
    }

    case PERF_RECORD_ITRACE_START: {
      const struct pev_record_itrace_start *itrace_start =
          event.record.itrace_start;
      assert(itrace_start);

      Curr.pid = itrace_start->pid;

      const bool Eng = CheckEngaged();
      if constexpr (IsVeryVerbose())
        if (Eng)
          fprintf(stderr, "%016" PRIx64 "\titrace_start %u/%u\n", offset,
                  itrace_start->pid, itrace_start->tid);
      break;
    }

    case PERF_RECORD_EXIT: {
      const struct pev_record_exit *exit = event.record.exit;
      assert(exit);

      if constexpr (IsVeryVerbose())
        fprintf(stderr, "%016" PRIx64 "\texit %u/%u, %u/%u\n", offset, exit->pid,
                exit->tid, exit->ppid, exit->ptid);

      break;
    }

    case PERF_RECORD_SWITCH_CPU_WIDE: {
      const struct pev_record_switch_cpu_wide *switch_cpu_wide = event.record.switch_cpu_wide;
      assert(switch_cpu_wide);
      if (event.misc & PERF_RECORD_MISC_SWITCH_OUT) {
        if (cpu == Our.cpu) {
          Curr.pid = ~0u;
          Engaged = false;
        }
      } else {
        if (cpu == Our.cpu) {
          Curr.pid = pid;
          CheckEngaged();
        }
      }
      break;
    }

    case PERF_RECORD_SWITCH: {
      if (event.misc & PERF_RECORD_MISC_SWITCH_OUT) {
        if (cpu == Our.cpu) {
          Curr.pid = ~0u;
          Engaged = false;
        }
      } else {
        if (cpu == Our.cpu) {
          Curr.pid = pid;
          CheckEngaged();
        }
      }
      break;
    }

    case PERF_RECORD_SAMPLE: {
      assert(event.name);
      assert(event.record.raw);
      assert(event.sample.ip);
        const char *const name = event.name;
        const uint64_t ip = *event.sample.ip;

        if (strcmp(name, "__jove_augmented_syscalls__") == 0) {
          auto on_syscall = [&]<typename T>(const T *payload) -> void {
	  const auto &hdr = payload->hdr;

          auto nr = hdr.syscall_nr;
          auto ret = hdr.ret;

          assert(nr >= 0);

          switch (nr) {
          case syscalls::NR::execve:
          case syscalls::NR::execveat:
            break;
          default:
            if (!IsRightProcess(pid))
              return;
          }

          //
          // we can assume that the syscall successfully completed
          //
          switch (nr) {
          case syscalls::NR::munmap: {
            taddr_t addr = hdr.args[0];
            taddr_t len  = hdr.args[1];

            const addr_intvl intvl(addr, len);

            if constexpr (IsVeryVerbose()) {
              std::string as(addr_intvl2str(intvl));

              fprintf(stderr, "[munmap] @ %s\n", as.c_str());
            }

            intvl_map_clear(AddressSpace, intvl);
            break;
          }

          case syscalls::NR::mmap: {
            taddr_t addr   = hdr.args[0];
            taddr_t len    = hdr.args[1];
            unsigned prot  = hdr.args[2];
            unsigned flags = hdr.args[3];
            int fd         = hdr.args[4];
            taddr_t off    = hdr.args[5];

            if (prot & PROT_EXEC)
              return; /* we will see PERF_RECORD_MMAP2 */

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
            break;
          }

          case syscalls::NR::execve:
          case syscalls::NR::execveat: {
            std::vector<const char *> argvec;
            std::vector<const char *> envvec;

            const unsigned n = payload->hdr.str_len;

            const char *const beg = &payload->str[0];
            const char *const end = &payload->str[n];

            const char *eon;
            const char *const pathname = beg;

            eon = (char *)memchr(pathname, '\0', n - (pathname - beg));
            assert(eon);

            for (const char *arg = eon + 1; *arg; arg = eon + 1) {
              argvec.push_back(arg);

              unsigned left = n - (arg - beg);
              eon = (const char *)memchr(arg, '\0', left);
              assert(eon);
            }
            assert(eon != end);
            ++eon;
            assert(eon != end);
            assert(*eon == '\0');
args_done:
            for (const char *env = eon + 1; env != end; env = eon + 1) {
              envvec.push_back(env);

              unsigned left = n - (env - beg);
              eon = (const char *)memchr(env, '\0', left);
              assert(eon);
            }
envs_done:
            if constexpr (IsVerbose()) {
              fprintf(stderr, "nargs=%u nenvs=%u (%u / %u) exec:",
                      (unsigned)argvec.size(),
                      (unsigned)envvec.size(),
                      (unsigned)(sizeof(payload->hdr) + n),
                      TWOTIMESMAXLEN);
              for (const char *env : envvec)
                fprintf(stderr, " \"%s\"", env);
              fprintf(stderr, " \"%s\"", pathname);
              for (const char *arg : argvec)
                fprintf(stderr, " \"%s\"", arg);
              fprintf(stderr, "\n");
            }
            break;
          }

          default:
            fprintf(stderr, "unhandled syscall %u!\n", (unsigned)nr);
            break;
	  }
          };

	  unsigned bytes_size = event.record.raw->size;
	  const uint8_t *const bytes = (const uint8_t *)event.record.raw->data;

          const bool was32 = (bytes[4] & 1u) == 1u;

#if 1
          const unsigned size_of_struct =
              was32 ? sizeof(struct augmented_syscall_payload32)
                    : sizeof(struct augmented_syscall_payload64);

          bool bad = false;
          if (!(bytes[0] == 'J' &&
                bytes[1] == 'O' &&
                bytes[2] == 'V' &&
                bytes[3] == 'E')) {
            fprintf(stderr, "offset at %" PRIu64 " does not start with magic1! bytes_size=%u sizeof(struct)=%u\n", offset, bytes_size, size_of_struct);
            bad = true;
          }

          if (!(bytes[bytes_size - 1] == 'E' &&
                bytes[bytes_size - 2] == 'V' &&
                bytes[bytes_size - 3] == 'O' &&
                bytes[bytes_size - 4] == 'J')) {
            fprintf(stderr, "offset at %" PRIu64 " does not end with magic2! bytes_size=%u sizeof(struct)=%u\n", offset, bytes_size, size_of_struct);
            bad = true;
          }

          if (bad) {
            fprintf(stderr, "\n");
            hexdump(stderr, bytes, bytes_size);
            fprintf(stderr, "\n");
          }
#endif

	  if (was32) {
	    if (IsTarget32)
	      on_syscall.template operator()<struct augmented_syscall_payload32>(reinterpret_cast<const struct augmented_syscall_payload32 *>(bytes));
	  } else {
	    if (IsTarget64)
	      on_syscall.template operator()<struct augmented_syscall_payload64>(reinterpret_cast<const struct augmented_syscall_payload64 *>(bytes));
	  }
        } else {
          unexpected_rest();
        }
        break;
      }

    case PERF_RECORD_MMAP: {
      if ((event.misc & PERF_RECORD_MISC_CPUMODE_MASK) == PERF_RECORD_MISC_KERNEL)
        break;

      const struct pev_record_mmap *mmap = event.record.mmap;
      assert(mmap);

      _mmap.two = false;

      _mmap.pid = mmap->pid;
      _mmap.tid = mmap->tid;
      _mmap.addr = mmap->addr;
      _mmap.len = mmap->len;
      _mmap.pgoff = mmap->pgoff;
      _mmap.filename = mmap->filename;
    } /* fallthrough */
    case PERF_RECORD_MMAP2: {
      if ((event.misc & PERF_RECORD_MISC_CPUMODE_MASK) == PERF_RECORD_MISC_KERNEL)
        break;

      if (_mmap.two) {
        const struct pev_record_mmap2 *mmap2= event.record.mmap2;
        assert(mmap2);

        assert(mmap2->prot & PROT_EXEC);

      _mmap.pid = mmap2->pid;
      _mmap.tid = mmap2->tid;
      _mmap.addr = mmap2->addr;
      _mmap.len = mmap2->len;
      _mmap.pgoff = mmap2->pgoff;
      _mmap.filename = mmap2->filename;

      }

      if (pid <= 1) /* ignore kernel/init */
	break;

      if (_mmap.pid != pid) {
      fprintf(stderr, "_mmap.pid %u != pid %u %u %s\n", _mmap.pid, pid,
              (unsigned)_mmap.two, _mmap.filename);
      }
      assert(_mmap.pid == pid);

      if (!IsRightProcess(pid))
        break;

      std::string name(_mmap.filename);

      const addr_intvl intvl(_mmap.addr, _mmap.len);

      if constexpr (IsVeryVerbose()) {
        std::string as(addr_intvl2str(intvl));

        fprintf(stderr, "[MMAP%s  @ %s in \"%s\"\n", _mmap.two ? "2]" : "] ",
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
        break;
      }

      binary_index_t BIdx;
      bool IsNew;
      if (name[0] == '/') {
        if (!fs::exists(name)) {
          if constexpr (IsVeryVerbose())
            fprintf(stderr, "\"%s\" does not exist\n", name.c_str());
          break;
        }

        std::tie(BIdx, IsNew) = jv.AddFromPath(explorer, name.c_str());
        if (!is_binary_index_valid(BIdx))
          break;
      } else {
        binary_index_set BIdxSet;
        if (!jv.LookupByName(name.c_str(), BIdxSet))
          break;
        assert(!BIdxSet.empty());

        BIdx = *(BIdxSet).rbegin(); /* most recent (XXX?) */
        IsNew = false;
      }

      binary_t &b = jv.Binaries.at(BIdx);
      binary_state_t &x = state.for_binary(b);

      intvl_map_add(AddressSpace, intvl, std::make_pair(BIdx, _mmap.pgoff));
      break;
    }

    default:
      break;
    }
#undef unexpected_rest

}

template <IPT_PARAMETERS_DCL>
int IntelPT<IPT_PARAMETERS_DEF>::explore(void) {
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

template <IPT_PARAMETERS_DCL>
int IntelPT<IPT_PARAMETERS_DEF>::explore_packets() {
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

      if constexpr (IsVerbose())
        fprintf(stderr, "IntelPT: error decoding packet: %s\n",
                pt_errstr(pt_errcode(errcode)));
      return errcode;
    }

    int ret = process_packet(offset, &packet);
    if (unlikely(ret <= 0))
      return ret;
  }

  return 0;
}

template <IPT_PARAMETERS_DCL>
int IntelPT<IPT_PARAMETERS_DEF>::process_packet(uint64_t offset,
                                                struct pt_packet *packet) {
  switch (packet->type) {
  case ppt_unknown:
  case ppt_invalid:
    return 1;

  case ppt_psb:
    if (1 /* options->track_time */) {
      int errcode;

      errcode = pt_tcal_update_psb(tracking.tcal.get(), config.get());
      if (unlikely(errcode < 0)) {
        if constexpr (IsVerbose())
          fprintf(stderr, "%s: error calibrating time", __PRETTY_FUNCTION__);
      }
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
      if (unlikely(errcode < 0)) {
        if constexpr (IsVerbose())
          fprintf(stderr, "%s: error calibrating time", __PRETTY_FUNCTION__);
      }
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
    uint64_t IP;

    errcode = pt_last_ip_update_ip(tracking.last_ip.get(), &packet->payload.ip,
                                   config.get());
    if (unlikely(errcode < 0))
      throw std::runtime_error(
          std::string("IntelPT: error tracking last-ip at offset ") +
          std::to_string(offset));

    errcode = pt_last_ip_query(&IP, tracking.last_ip.get());
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
      on_ip(IP, offset);
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
      const auto SavedExecBits = Curr.ExecBits;
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

      if constexpr (IsVeryVerbose())
        if (Curr.ExecBits != SavedExecBits)
          fprintf(stderr, "%016" PRIx64 "\tbits %u -> %u\n", offset,
                  SavedExecBits, Curr.ExecBits);

      CheckEngaged();

#ifdef TARGET_I386
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

      if (packet->type == ppt_fup) {
          errcode = pt_last_ip_update_ip(tracking.last_ip.get(),
                                         &packet->payload.ip, config.get());
          if (unlikely(errcode < 0))
            throw std::runtime_error(
                std::string("IntelPT: error tracking last-ip at offset ") +
                std::to_string(offset));

          if constexpr (IsVeryVerbose()) {
            uint64_t IP;
            if (pt_last_ip_query(&IP, tracking.last_ip.get()) >= 0)
              fprintf(stderr, "%016" PRIx64 "\tskipping IP %016" PRIx64 "\n", offset, (uint64_t)IP);
          }

          CurrPoint.Invalidate();
          return 1;
      }

      __attribute__((musttail)) return process_packet(offset, packet);
#else
      return 1;
#endif
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
    return track_tsc(offset, &packet->payload.tsc);

  case ppt_cbr:
    return track_cbr(offset, &packet->payload.cbr);;

  case ppt_tma:
    return track_tma(offset, &packet->payload.tma);;

  case ppt_mtc:
    return track_mtc(offset, &packet->payload.mtc);;

  case ppt_cyc:
    return track_cyc(offset, &packet->payload.cyc);;

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

template <IPT_PARAMETERS_DCL>
int IntelPT<IPT_PARAMETERS_DEF>::tnt_payload(const struct pt_packet_tnt &packet,
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
              static_cast<uint64_t>(Saved.GetAddr()));
  } catch (const infinite_loop_exception &) {
    if constexpr (IsVerbose())
      fprintf(stderr, "tnt error (infinite loop) from %s+%" PRIx64 "\n",
              Saved.Binary().Name.c_str(),
              static_cast<uint64_t>(Saved.GetAddr()));
  }

  CurrPoint.Invalidate();
  return 1;
}

template <IPT_PARAMETERS_DCL>
int IntelPT<IPT_PARAMETERS_DEF>::on_ip(const taddr_t IP, const uint64_t offset) {
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
      fprintf(stderr, "%016" PRIx64 "\tunknown IP %016" PRIx64 "\n", offset, (uint64_t)IP);

    CurrPoint.Invalidate();
    return 1;
  }

  const binary_index_t BIdx = (*it).second.first;
  if (unlikely(!is_binary_index_valid(BIdx))) {
    if constexpr (IsVerbose())
      fprintf(stderr, "%016" PRIx64 "\tambiguous IP %016" PRIx64 "\n", offset, (uint64_t)IP);

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
    fprintf(stderr, "%016" PRIx64 "\t<IP> %016" PRIx64 " %s+%" PRIx64 "\n", offset,
            (uint64_t)IP, b.Name.c_str(), (uint64_t)Addr);

  if (CurrPoint.Valid()) {
    auto grab_addresses =
        [&](const basic_block_properties_t &bbprop,
            basic_block_index_t BBIdx) -> basic_block_index_t {
      CurrPoint.SetAddr(bbprop.Addr);
      CurrPoint.SetTermAddr(bbprop.Term.Addr);
      return BBIdx;
    };
    if (CurrPoint.BinaryIndex() == BIdx) {
      bool WentNoFurther = false;

      if constexpr (Caching) {
        try {
          const auto &SL = SLForBlock(b, CurrPoint.Block());
          CurrPoint.SetBlockIndex(SL.BBIdx);
          CurrPoint.SetAddr(SL.Addr);
          CurrPoint.SetTermAddr(SL.TermAddr);
          WentNoFurther = intvl_set_contains(SL.addrng, Addr);
        } catch (const infinite_loop_exception &) {
          CurrPoint.Invalidate();
        }
      } else {
        basic_block_index_t NewBBIdx;
        std::tie(NewBBIdx, WentNoFurther) = StraightLineUntilSlow<false>(
            b, CurrPoint.BlockIndex(), Addr, grab_addresses);
        CurrPoint.SetBlockIndex(NewBBIdx);
      }

      //assert(CurrPoint.Valid());
      if (WentNoFurther) {
        if constexpr (IsVeryVerbose())
            fprintf(stderr, "no further %s+%" PRIx64 "\n</IP>\n",
                    b.Name.c_str(), (uint64_t)Addr);
        return 0;
      }
    } else {
      if constexpr (Caching) {
        try {
          const auto &SL = SLForBlock(CurrPoint.Binary(), CurrPoint.Block());
          CurrPoint.SetBlockIndex(SL.BBIdx);
          CurrPoint.SetAddr(SL.Addr);
          CurrPoint.SetTermAddr(SL.TermAddr);
        } catch (const infinite_loop_exception &) {
          CurrPoint.Invalidate();
        }
      } else {
      CurrPoint.SetBlockIndex(StraightLineSlow<false>(
          CurrPoint.Binary(), CurrPoint.BlockIndex(), grab_addresses));
      assert(CurrPoint.Valid());
      }
    }
  }

  binary_state_t &x = state.for_binary(b);
  if constexpr(Objdump) {
    if (!b.bbbmap.contains(Addr)) {
      bool bad;

      if constexpr(Caching)
        bad = x.m_objdump.is_addr_bad(Addr);
      else
        bad = b.Analysis.objdump.is_addr_bad(Addr);

      if (unlikely(bad)) {
        if constexpr (IsVerbose())
          fprintf(stderr,
                  "OBJDUMP SAYS \"BADIP!\" %016" PRIx64 "\t<IP> %016" PRIx64 " %s+%" PRIx64 "\n",
                  offset, (uint64_t)IP, b.Name.c_str(), (uint64_t)Addr);

        if constexpr (IsVeryVerbose())
          fprintf(stderr, "</IP>\n");

        CurrPoint.Invalidate();
        return 1;
      }
    }
  }

  const auto PrevPoint = CurrPoint;
  try {
    auto obp = [&](basic_block_t bb, basic_block_properties_t &bbprop) -> void {
      CurrPoint.SetAddr(bbprop.Addr);
      CurrPoint.SetTermAddr(bbprop.Term.Addr);

      if constexpr (IsVeryVerbose())
        on_block(b, bbprop, bb);
    };
    auto obp_u = [&](basic_block_index_t BBIdx) -> void {
      basic_block_properties_t &bbprop =
          b.Analysis.ICFG[basic_block_of_index(BBIdx, b.Analysis.ICFG)];

      ip_sharable_lock<ip_sharable_mutex> s_lck(bbprop.mtx);
      obp(basic_block_of_index(BBIdx, b.Analysis.ICFG), bbprop);
    };

    CurrPoint.SetBinary(b);
    CurrPoint.SetBlockIndex(explorer.explore_basic_block(b, *x.Bin, Addr, obp, obp_u));
    assert(CurrPoint.Valid());
  } catch (const invalid_control_flow_exception &) {
    if constexpr (IsVerbose())
      fprintf(stderr, "BADIP %016" PRIx64 "\t<IP> %016" PRIx64 " %s+%" PRIx64 "\n",
              offset, (uint64_t)IP, b.Name.c_str(), (uint64_t)Addr);

    if constexpr (IsVeryVerbose())
      fprintf(stderr, "</IP>\n");

    CurrPoint.Invalidate();
    return 1;
  }

  if (PrevPoint.Valid() && CurrPoint.Valid()) {
    const taddr_t PrevTermAddr = PrevPoint.GetTermAddr();

    if (likely(is_taddr_valid(PrevTermAddr))) {
      block_transfer(PrevPoint.Binary(), PrevTermAddr,
                     CurrPoint.Binary(), CurrPoint.GetAddr());
    } else {
      if constexpr (IsVerbose()) {
        auto &prevb = PrevPoint.Binary();
        auto &prevprop = prevb.Analysis.ICFG[PrevPoint.Block()];

        fprintf(stderr,
                "PrevPoint has invalid terminator address %" PRIx64
                " @ %s+%" PRIx64 "\n",
                (uint64_t)PrevTermAddr, prevb.Name.c_str(),
                (uint64_t)prevprop.Addr);
      }
    }
  }

  if constexpr (IsVeryVerbose())
    fprintf(stderr, "</IP>\n");

  return 0;
}

template <IPT_PARAMETERS_DCL>
void IntelPT<IPT_PARAMETERS_DEF>::block_transfer(binary_t &fr_b,
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

      concurrent::set(fr_ICFG[basic_block_at_address(FrTermAddr, fr_b)].Term._return.Returns);
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
          concurrent::set(to_b.Analysis.Functions.at(before_Term._call.Target).Returns);
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
               std::function<basic_block_index_t (const basic_block_properties_t &, basic_block_index_t)> on_final_block = [](const basic_block_properties_t &, basic_block_index_t Res) -> basic_block_index_t { return Res; },
               std::function<void(const basic_block_properties_t &, basic_block_index_t)> on_block = [](const basic_block_properties_t &, basic_block_index_t) -> void {}) {
  const auto &ICFG = b.Analysis.ICFG;

  std::reference_wrapper<const basic_block_properties_t> the_bbprop =
      ICFG[basic_block_of_index(Res, b)];

  basic_block_index_t ResSav = Res;
  for (
       (void)({
         const basic_block_properties_t &bbprop = the_bbprop.get();

         if (!bbprop.pub.is.load(std::memory_order_acquire))
           ip_sharable_lock<ip_sharable_mutex>(bbprop.pub.mtx);
         bbprop.mtx.lock_sharable(); /* don't change on us */

         on_block(bbprop, Res);
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

         if (!new_bbprop.pub.is.load(std::memory_order_acquire))
           ip_sharable_lock<ip_sharable_mutex>(new_bbprop.pub.mtx);
         new_bbprop.mtx.lock_sharable(); /* don't change on us */

         on_block(new_bbprop, Res);
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
        return std::make_pair(on_final_block(bbprop, basic_block_of_index(Res, b)), true);
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
    return std::make_pair(on_final_block(bbprop, basic_block_of_index(Res, b)), false);
  }

  abort();
}

template <IPT_PARAMETERS_DCL>
template <bool InfiniteLoopThrow>
std::pair<basic_block_index_t, bool>
IntelPT<IPT_PARAMETERS_DEF>::StraightLineUntilSlow(
    const binary_t &b,
    basic_block_index_t From,
    taddr_t GoNoFurther,
    std::function<basic_block_index_t(const basic_block_properties_t &, basic_block_index_t)> on_final_block) {
  using namespace std::placeholders;

  return StraightLineGo<true, InfiniteLoopThrow, Verbosity>(
      b, From, GoNoFurther, on_final_block);
}

template <IPT_PARAMETERS_DCL>
template <bool InfiniteLoopThrow>
basic_block_index_t IntelPT<IPT_PARAMETERS_DEF>::StraightLineSlow(
    const binary_t &b,
    basic_block_index_t From,
    std::function<basic_block_index_t(const basic_block_properties_t &, basic_block_index_t)> on_final_block) {
  using namespace std::placeholders;

  return StraightLineGo<false, InfiniteLoopThrow, Verbosity>(
      b, From, 0 /* unused */, on_final_block).first;
}

template <IPT_PARAMETERS_DCL>
void IntelPT<IPT_PARAMETERS_DEF>::on_block(const binary_t &b,
                                           const basic_block_properties_t &bbprop,
                                           basic_block_t bb) {
  if constexpr (IsVeryVerbose()) {
    auto &ICFG = b.Analysis.ICFG;
    if (index_of_binary(b) == OnBlock.Last.BIdx &&
        index_of_basic_block(ICFG, bb) == OnBlock.Last.BBIdx) {
      fputs(".", stderr);
    } else {
      const auto Addr = bbprop.Addr;

      fprintf(stderr, "%s+%016" PRIx64 "\n", b.Name.c_str(), (uint64_t)Addr);
      //fprintf(stdout, "%s+%016" PRIx64 "\n", b.Name.c_str(), (uint64_t)Addr);
    }

    OnBlock.Last.BIdx = index_of_binary(b);
    OnBlock.Last.BBIdx = index_of_basic_block(ICFG, bb);
  }
}

template <IPT_PARAMETERS_DCL>
void IntelPT<IPT_PARAMETERS_DEF>::TNTAdvance(uint64_t tnt, uint8_t n) {
  if constexpr (IsVeryVerbose())
    fprintf(stderr, "<TNT>\n");

  assert(n > 0);
  assert(CurrPoint.Valid());

  binary_t &b = CurrPoint.Binary();
  basic_block_index_t Res = CurrPoint.BlockIndex();

  const auto &ICFG = b.Analysis.ICFG;
  do {
    const bool Taken = !!(tnt & (1ull << (n - 1)));

    if constexpr (Caching) {
      basic_block_t bb = basic_block_of_index(Res, b);
      const auto &SL = SLForBlock(b, bb);
      if (unlikely(SL.adj.empty())) {
        if constexpr (IsVerbose())
          fprintf(stderr,
                  "not/invalid conditional branch @ %s+%" PRIx64 " (%s)\n",
                  b.Name.c_str(), static_cast<uint64_t>(ICFG[basic_block_of_index(SL.BBIdx, b)].Addr),
                  string_of_terminator(SL.TermType));
        throw tnt_error();
      }
      assert(SL.adj.size() == 2);
      Res = SL.adj[static_cast<unsigned>(Taken)];
    } else {
    Res = StraightLineSlow<true>(
        b, Res, [&](const basic_block_properties_t &bbprop,
                    basic_block_index_t BBIdx) -> basic_block_index_t {
          basic_block_t bb = basic_block_of_index(BBIdx, b);

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

          basic_block_index_t TheRes = index_of_basic_block(
              ICFG, Taken ? (Is0NotTaking ? succ[1] : succ[0])
                          : (Is0NotTaking ? succ[0] : succ[1]));
          return TheRes;
        });
    }

    if constexpr (IsVeryVerbose()) {
      basic_block_t bb = basic_block_of_index(Res, b);
      const auto &bbprop = ICFG[bb];

      ip_sharable_lock<ip_sharable_mutex> s_lck(bbprop.mtx);

      on_block(b, bbprop, bb);
    }

#if 0
    const char *extra = n > 1 ? " " : "";
    fprintf(stderr, "%d%s", (int)Taken, extra);
#endif
  } while (--n);

  if constexpr (Caching) {
    basic_block_t bb = basic_block_of_index(Res, b);
    const auto &SL = SLForBlock(b, bb);
    CurrPoint.SetBlockIndex(SL.BBIdx);
    CurrPoint.SetAddr(SL.Addr);
    CurrPoint.SetTermAddr(SL.TermAddr);
  } else {
    CurrPoint.SetBlockIndex(StraightLineSlow<true>(
        b, Res,
        [&](const basic_block_properties_t &bbprop,
            basic_block_index_t BBIdx) -> basic_block_index_t {
          CurrPoint.SetAddr(bbprop.Addr);
          CurrPoint.SetTermAddr(bbprop.Term.Addr);
          return BBIdx;
        }));
  }

  if constexpr (IsVeryVerbose())
    fprintf(stderr, "</TNT>\n");
}

template <IPT_PARAMETERS_DCL>
void IntelPT<IPT_PARAMETERS_DEF>::ptdump_tracking_init(void)
{
  pt_last_ip_init(tracking.last_ip.get());
  pt_tcal_init(tracking.tcal.get());
  pt_time_init(tracking.time.get());

  tracking.session = NULL;
  tracking.tsc = 0ull;
  tracking.fcr = 0ull;
  tracking.in_header = 0;
}

template <IPT_PARAMETERS_DCL>
void IntelPT<IPT_PARAMETERS_DEF>::ptdump_tracking_reset(void) {
  pt_last_ip_init(tracking.last_ip.get());
  pt_tcal_init(tracking.tcal.get());
  pt_time_init(tracking.time.get());

  tracking.tsc = 0ull;
  tracking.fcr = 0ull;
  tracking.in_header = 0;
}

template <IPT_PARAMETERS_DCL>
int IntelPT<IPT_PARAMETERS_DEF>::sb_track_time(uint64_t offset)
{
	uint64_t tsc;
	int errcode;

	errcode = pt_time_query_tsc(&tsc, NULL, NULL, tracking.time.get());
	if (unlikely((errcode < 0) && (errcode != -pte_no_time))) {
		if constexpr (IsVerbose())
			fprintf(stderr, "%s: time tracking error\n", __PRETTY_FUNCTION__);
		return errcode;
	}

        while (struct pev_event *event = pt_sb_pop(tracking.session, tsc))
                examine_sb_event(*event, offset);

        return 1;
}

template <IPT_PARAMETERS_DCL>
int IntelPT<IPT_PARAMETERS_DEF>::track_time(uint64_t offset) {
	return sb_track_time(offset);
}

template <IPT_PARAMETERS_DCL>
int IntelPT<IPT_PARAMETERS_DEF>::track_tsc(uint64_t offset,
                                           const struct pt_packet_tsc *packet) {
        int errcode;

	if (1 /* !options->no_tcal */) {
		errcode = tracking.in_header ?
			pt_tcal_header_tsc(tracking.tcal.get(), packet, config.get()) :
			pt_tcal_update_tsc(tracking.tcal.get(), packet, config.get());
		if (unlikely(errcode < 0)) {
			if constexpr (IsVerbose())
				fprintf(stderr, "%s: error calibrating time\n", __PRETTY_FUNCTION__);
		}
	}

	errcode = pt_time_update_tsc(tracking.time.get(), packet, config.get());
	if (unlikely(errcode < 0)) {
		if constexpr (IsVerbose())
			fprintf(stderr, "%s: error updating time\n", __PRETTY_FUNCTION__);
	}

	return track_time(offset);
}

template <IPT_PARAMETERS_DCL>
int IntelPT<IPT_PARAMETERS_DEF>::track_cbr(uint64_t offset,
                                           const struct pt_packet_cbr *packet) {
        int errcode;

	if (1 /* !options->no_tcal */) {
		errcode = tracking.in_header ?
			pt_tcal_header_cbr(tracking.tcal.get(), packet, config.get()) :
			pt_tcal_update_cbr(tracking.tcal.get(), packet, config.get());
		if (unlikely(errcode < 0)) {
			if constexpr (IsVerbose())
				fprintf(stderr, "%s: error calibrating time\n", __PRETTY_FUNCTION__);
		}
        }

	errcode = pt_time_update_cbr(tracking.time.get(), packet, config.get());
	if (unlikely(errcode < 0)) {
		if constexpr (IsVerbose())
			fprintf(stderr, "%s: error updating time\n", __PRETTY_FUNCTION__);
	}

	return track_time(offset);
}

template <IPT_PARAMETERS_DCL>
int IntelPT<IPT_PARAMETERS_DEF>::track_tma(uint64_t offset,
                                           const struct pt_packet_tma *packet) {
        int errcode;

	if (1 /* !options->no_tcal */) {
		errcode = pt_tcal_update_tma(tracking.tcal.get(), packet, config.get());
		if (unlikely(errcode < 0)) {
			if constexpr (IsVerbose())
				fprintf(stderr, "%s: error calibrating time\n", __PRETTY_FUNCTION__);
		}
	}

	errcode = pt_time_update_tma(tracking.time.get(), packet, config.get());
	if (unlikely(errcode < 0)) {
		if constexpr (IsVerbose())
			fprintf(stderr, "%s: error updating time\n", __PRETTY_FUNCTION__);
	}

	return track_time(offset);
}

template <IPT_PARAMETERS_DCL>
int IntelPT<IPT_PARAMETERS_DEF>::track_mtc(uint64_t offset,
                                           const struct pt_packet_mtc *packet) {
        int errcode;

	if (1 /* !options->no_tcal */) {
		errcode = pt_tcal_update_mtc(tracking.tcal.get(), packet, config.get());
		if (unlikely(errcode < 0)) {
			if constexpr (IsVerbose())
                                fprintf(stderr,
                                        "%s: error calibrating time: %s\n",
                                        __PRETTY_FUNCTION__,
                                        pt_errstr(pt_errcode(errcode)));
                }
	}

	errcode = pt_time_update_mtc(tracking.time.get(), packet, config.get());
	if (unlikely(errcode < 0)) {
		if constexpr (IsVerbose())
                        fprintf(stderr, "%s: error updating time: %s\n",
                                __PRETTY_FUNCTION__,
                                pt_errstr(pt_errcode(errcode)));
        }

	return track_time(offset);
}

template <IPT_PARAMETERS_DCL>
int IntelPT<IPT_PARAMETERS_DEF>::track_cyc(uint64_t offset,
                                           const struct pt_packet_cyc *packet) {
	uint64_t fcr;
	int errcode;

	/* Initialize to zero in case of calibration errors. */
	fcr = 0ull;

	if (1 /* !options->no_tcal */) {
		errcode = pt_tcal_fcr(&fcr, tracking.tcal.get());

		if (unlikely(errcode < 0)) {
			if constexpr (IsVerbose())
                                fprintf(stderr, "%s: calibration error: %s\n",
                                        __PRETTY_FUNCTION__,
                                        pt_errstr(pt_errcode(errcode)));
                }

		errcode = pt_tcal_update_cyc(tracking.tcal.get(), packet, config.get());
		if (unlikely(errcode < 0)) {
			if constexpr (IsVerbose())
                                fprintf(stderr,
                                        "%s: error calibrating time: %s\n",
                                        __PRETTY_FUNCTION__,
                                        pt_errstr(pt_errcode(errcode)));
                }
	}

	errcode = pt_time_update_cyc(tracking.time.get(), packet, config.get(), fcr);

	if (unlikely(errcode < 0)) {
		if constexpr (IsVerbose())
                        fprintf(stderr, "%s: error updating time: %s\n",
                                __PRETTY_FUNCTION__,
                                pt_errstr(pt_errcode(errcode)));
        } else if (!fcr) {
		if constexpr (IsVerbose())
                        fprintf(stderr,
                                "%s: error updating time: no calibration\n",
                                __PRETTY_FUNCTION__);
        }

	return track_time(offset);
}

template <IPT_PARAMETERS_DCL>
int IntelPT<IPT_PARAMETERS_DEF>::ptdump_sb_pevent(const char *filename,
                                                  const struct pt_sb_pevent_config *conf) {
	struct pt_sb_pevent_config config;
	int errcode;

	config = *conf;
	config.filename = filename;
	config.begin = 0;
	config.end = 0;

	errcode = pt_sb_alloc_pevent_decoder(tracking.session, &config);
	if (unlikely(errcode < 0)) {
		if constexpr (IsVerbose())
			fprintf(stderr, "%s: error loading: %s\n",
				__PRETTY_FUNCTION__,
				pt_errstr(pt_errcode(errcode)));
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

template <IPT_PARAMETERS_DCL>
int IntelPT<IPT_PARAMETERS_DEF>::process_args(int argc, char **argv,
                                              const char *sb_filename) {
	struct pt_sb_pevent_config pevent;
	int idx, errcode;

	memset(&pevent, 0, sizeof(pevent));
	pevent.size = sizeof(pevent);
	pevent.time_mult = 1;

	for (idx = 1; idx < argc; ++idx) {
		if (strcmp(argv[idx], "--pevent:sample-type") == 0) {
			if (!get_arg_uint64(&pevent.sample_type,
					    "--pevent:sample-type",
					    argv[++idx], argv[0]))
				return -1;
		} else if (strcmp(argv[idx], "--pevent:sample-config") == 0) {
			errcode = pt_parse_sample_config(&pevent, argv[++idx]);
			if (errcode < 0) {
				fprintf(stderr,
					"%s: bad sample config %s: %s.\n",
					argv[0], argv[idx-1],
					pt_errstr(pt_errcode(errcode)));
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
				fprintf(stderr,
					"%s: --cpu: missing argument.\n",
					argv[0]);
				return -1;
			}

			if (strcmp(arg, "none") == 0) {
				memset(&config->cpu, 0, sizeof(config->cpu));
				continue;
			}

			errcode = pt_cpu_parse(&config->cpu, arg);
			if (errcode < 0) {
				fprintf(stderr,
					"%s: cpu must be specified as f/m[/s]\n",
					argv[0]);
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
		} else {
			throw std::runtime_error(
				std::string("unknown option \"") + argv[idx] +
				std::string("\""));
		}
	}

	errcode = ptdump_sb_pevent(sb_filename, &pevent);
	if (errcode < 0)
		throw std::runtime_error("ptdump_sb_pevent() failed");

	return 0;
}

template <IPT_PARAMETERS_DCL>
IntelPT<IPT_PARAMETERS_DEF>::binary_state_t::binary_state_t(const binary_t &b) {
  Bin = B::Create(b.data());

  if constexpr(Objdump) {
    binary_t::Analysis_t::objdump_output_type &objdump =
      const_cast<binary_t &>(b).Analysis.objdump;

    if (objdump.empty()) {
      ip_scoped_lock<ip_sharable_mutex> e_lck(objdump.mtx);

      if (objdump.good.empty())
        run_objdump_and_parse_addresses<binary_t::Analysis_t::objdump_output_type>(b.is_file() ? b.Name.c_str() : nullptr,
                                        *Bin, objdump);
    }

    if constexpr(Caching)
      m_objdump = objdump;
  }
}

#if 0

template <IPT_PARAMETERS_DCL>
const basic_block_properties_t::Analysis_t::straight_line_t &
IntelPT<IPT_PARAMETERS_DEF>::basic_block_state_t::SL(const binary_t &b,
                                                     basic_block_t the_bb) {
  const straight_line_t *p = prop.Analysis.pSL.Load(std::memory_order_acquire);
  if (likely(p))
    return *p;

  straight_line_t *ourSL =
      b.get_allocator().get_segment_manager()->construct<straight_line_t>(
          boost::interprocess::anonymous_instance)();
  assert(ourSL);

  {
    straight_line_t &SL = *ourSL;

    const basic_block_index_t TheIdx = index_of_basic_block(b, the_bb);
    assert(is_basic_block_index_valid(TheIdx));

    const auto &ICFG = b.Analysis.ICFG;

    SL.BBIdx = StraightLineGo<false, true, Verbosity>(
        b, TheIdx, 0 /* unused */,
        [&](basic_block_index_t BBIdx) -> basic_block_index_t {
          basic_block_t bb = basic_block_of_index(BBIdx, b);
          const auto &bbprop = ICFG[bb];

          SL.TermType = bbprop.Term.Type;
          SL.TermAddr = bbprop.Term.Addr;

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
                SL.adj.push_back(succ0);
                SL.adj.push_back(succ1);
              } else {
                SL.adj.push_back(succ1);
                SL.adj.push_back(succ0);
              }
            } else {
              ;
            }
          }

          return BBIdx;
        }).first;

    assert(is_basic_block_index_valid(SL.BBIdx));
  }

  const straight_line_t *expected = nullptr;
  if (prop.Analysis.pSL.CompareExchangeStrong(expected, ourSL,
                                              std::memory_order_release,
                                              std::memory_order_acquire))
    return *ourSL;

  assert(expected);

  b.get_allocator().get_segment_manager()->destroy_ptr(ourSL);
  return *expected;
}

#else

template <IPT_PARAMETERS_DCL>
IntelPT<IPT_PARAMETERS_DEF>::basic_block_state_t::basic_block_state_t(
    const binary_t &b, basic_block_t the_bb) {
  if constexpr (!Caching)
    return;

  auto &ICFG = b.Analysis.ICFG;

  const basic_block_index_t Idx = index_of_basic_block(b, the_bb);
  assert(is_basic_block_index_valid(Idx));

  auto &SL = this->theSL;

  auto on_block = [&](const basic_block_properties_t &bbprop,
                      basic_block_index_t BBIdx) -> void {
    intvl_set_add(SL.addrng, addr_intvl(bbprop.Addr, bbprop.Size));
  };

  SL.BBIdx = StraightLineGo<false, true, Verbosity>(
      b, Idx, 0 /* unused */,
      [&](const basic_block_properties_t &bbprop, basic_block_index_t BBIdx) -> basic_block_index_t {
        SL.Addr = bbprop.Addr;
        SL.TermType = bbprop.Term.Type;
        SL.TermAddr = bbprop.Term.Addr;

        {
          icfg_t::adjacency_iterator it, it_end;
          std::tie(it, it_end) = ICFG.adjacent_vertices(basic_block_of_index(BBIdx, b));

          unsigned N = std::distance(it, it_end);
          if (N == 1) {
            SL.adj.push_back(*it);
            SL.adj.push_back(*it);
          } else if (N == 2 && SL.TermType == TERMINATOR::CONDITIONAL_JUMP) {
            basic_block_index_t succ0 = *it++;
            basic_block_index_t succ1 = *it++;

            bool Is0NotTaking = ICFG[succ0].Addr == bbprop.Addr + bbprop.Size;
            if (Is0NotTaking) {
              SL.adj.push_back(succ0);
              SL.adj.push_back(succ1);
            } else {
              SL.adj.push_back(succ1);
              SL.adj.push_back(succ0);
            }
          } else {
            ;
          }
        }

        return BBIdx;
      }, on_block).first;

  assert(is_basic_block_index_valid(SL.BBIdx));
}

#endif

#undef IsVerbose
#undef IsVeryVerbose

#define IPT_EXTRACT_VALUES(s, data, elem)                                      \
  BOOST_PP_TUPLE_ELEM(3, 2, elem)

#define IPT_ALL_OPTIONS                                                        \
  BOOST_PP_SEQ_TRANSFORM(IPT_EXTRACT_VALUES, void, IPT_PARAMETERS)

#define IPT_GENERATE_TEMPLATE_ARG(r, product, i, elem)                         \
  BOOST_PP_COMMA_IF(i) BOOST_PP_SEQ_ELEM(i, product)

#define IPT_INSTANTIATE(r, product)                                            \
  template class IntelPT<                                                      \
      BOOST_PP_SEQ_FOR_EACH_I(IPT_GENERATE_TEMPLATE_ARG, product,              \
                              IPT_PARAMETERS)>;

BOOST_PP_SEQ_FOR_EACH_PRODUCT(IPT_INSTANTIATE, IPT_ALL_OPTIONS);

#undef IPT_INSTANTIATE

}

#endif /* x86 */
