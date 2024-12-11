#pragma once

namespace jove {

static void pkt_read_tma(struct pt_packet_tma *packet, const uint8_t *pos) {
  uint16_t ctc, fc;
  ctc = pos[pt_pl_tma_ctc_0];
  ctc |= pos[pt_pl_tma_ctc_1] << 8;

  fc = pos[pt_pl_tma_fc_0];
  fc |= pos[pt_pl_tma_fc_1] << 8;

  if (unlikely(fc & ~pt_pl_tma_fc_mask))
    throw error_decoding_exception();

  if (unlikely(pos[pt_pl_tma_ctc_1 + 1]))
    throw error_decoding_exception();

  packet->ctc = ctc;
  packet->fc = fc;
}

static int pkt_read_cyc(struct pt_packet_cyc *packet, const uint8_t *pos,
                        const struct pt_config *config) {
  uint64_t value;
  uint8_t cyc, ext, shl;

  const uint8_t *const begin = pos;
  const uint8_t *const end = config->end;

  /* The first byte contains the opcode and part of the payload.
   * We already checked that this first byte is within bounds.
   */
  cyc = *pos++;

  ext = cyc & pt_opm_cyc_ext;
  cyc >>= pt_opm_cyc_shr;

  value = cyc;
  shl = (8 - pt_opm_cyc_shr);

  while (ext) {
    uint64_t bits;

    if (unlikely(end <= pos))
      throw end_of_trace_exception();

    bits = *pos++;
    ext = bits & pt_opm_cycx_ext;

    bits >>= pt_opm_cycx_shr;
    bits <<= shl;

    shl += (8 - pt_opm_cycx_shr);
    if (unlikely(sizeof(value) * 8 < shl))
      throw error_decoding_exception();

    value |= bits;
  }

  packet->value = value;

  return (int)(pos - begin);
}

static uint64_t pt_pkt_read_value(const uint8_t *pos, int size) {
  uint64_t val;
  int idx;

  for (val = 0, idx = 0; idx < size; ++idx) {
    uint64_t byte = *pos++;

    byte <<= (idx * 8);
    val |= byte;
  }

  return val;
}

static int pkt_ip_size(enum pt_ip_compression ipc) {
  switch (ipc) {
  case pt_ipc_suppressed:
    return 0;

  case pt_ipc_update_16:
    return 2;

  case pt_ipc_update_32:
    return 4;

  case pt_ipc_update_48:
  case pt_ipc_sext_48:
    return 6;

  case pt_ipc_full:
    return 8;
  }

  throw error_decoding_exception();
}

static int pkt_read_ip(struct pt_packet_ip *packet, const uint8_t *pos,
                       const struct pt_config *config) {
  uint64_t ip;
  uint8_t ipc;
  int ipsize;

  ipc = (*pos++ >> pt_opm_ipc_shr) & pt_opm_ipc_shr_mask;

  ip = 0ull;
  ipsize = pkt_ip_size((enum pt_ip_compression)ipc);
  if (unlikely(ipsize < 0))
    throw error_decoding_exception();

  if (unlikely(config->end < pos + ipsize))
    throw end_of_trace_exception();

  if (likely(ipsize))
    ip = pt_pkt_read_value(pos, ipsize);

  packet->ipc = (enum pt_ip_compression)ipc;
  packet->ip = ip;

  return ipsize + 1;
}

static int pkt_read_mode_exec(struct pt_packet_mode_exec *packet,
                              uint8_t mode) {
  packet->csl = (mode & pt_mob_exec_csl) != 0;
  packet->csd = (mode & pt_mob_exec_csd) != 0;
  packet->iflag = (mode & pt_mob_exec_iflag) != 0;

  return ptps_mode;
}

static int pkt_read_mode_tsx(struct pt_packet_mode_tsx *packet, uint8_t mode) {
  packet->intx = (mode & pt_mob_tsx_intx) != 0;
  packet->abrt = (mode & pt_mob_tsx_abrt) != 0;

  return ptps_mode;
}

static int pkt_read_mode(struct pt_packet_mode *packet, const uint8_t *pos,
                         const struct pt_config *config) {
  uint8_t payload, mode, leaf;

  if (unlikely(config->end < pos + ptps_mode))
    throw end_of_trace_exception();

  payload = pos[pt_opcs_mode];
  leaf = payload & pt_mom_leaf;
  mode = payload & pt_mom_bits;

  packet->leaf = (enum pt_mode_leaf)leaf;
  switch (leaf) {
  case pt_mol_exec:
    return pkt_read_mode_exec(&packet->bits.exec, mode);
  case pt_mol_tsx:
    return pkt_read_mode_tsx(&packet->bits.tsx, mode);
  }
  throw error_decoding_exception();
}

} // namespace jove
