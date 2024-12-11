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
  const uint8_t *begin, *end;
  uint64_t value;
  uint8_t cyc, ext, shl;

  begin = pos;
  end = config->end;

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

} // namespace jove
