#if defined(__x86_64__) && (defined(TARGET_X86_64) || defined(TARGET_I386))
#pragma once
#include "ipt.h"

#include <cstdio>
#include <array>

extern "C" {
#include "pt_time.h"
#include "pt_opcodes.h"
}

#include "nonreference_ipt.h"

namespace jove {

struct afl_packet_type {
  unsigned char opcode = 0;
  unsigned char opcodesize = 0;
};

template <IPT_PARAMETERS_DCL> struct afl_ipt_t;

template <IPT_PARAMETERS_DCL>
struct ipt_traits<afl_ipt_t<IPT_PARAMETERS_DEF>> {
  using packet_type = afl_packet_type;
};

#define PPT_EXT 0xFF

#if 0
static constexpr
unsigned char orig_opc_lut[] = {
	0x02, 0x08, 0xff, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x06, 0x09, 0x12,
	0x09, 0x07, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x0f, 0x09, 0x12, 0x09, 0x05, 0x09, 0x12,
	0x09, 0x08, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x06, 0x09, 0x12,
	0x09, 0x07, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x05, 0x09, 0x12,
	0x09, 0x08, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x06, 0x09, 0x12,
	0x09, 0x07, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x11, 0x09, 0x12, 0x09, 0x05, 0x09, 0x12,
	0x09, 0x08, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x06, 0x09, 0x12,
	0x09, 0x07, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x05, 0x09, 0x12,
	0x09, 0x08, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x06, 0x09, 0x12,
	0x09, 0x07, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x0b, 0x09, 0x12, 0x09, 0x05, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x08, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x06, 0x09, 0x12,
	0x09, 0x07, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x05, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12
};

static constexpr
unsigned char orig_ext_lut[] = {
	0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x18, 0x04, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x03, 0x13, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x19, 0x0a, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x17, 0xff, 0x00, 0x00, 0x00, 0x00,
	0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static constexpr
unsigned char orig_opc_size_lut[] = {
	0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x08, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x03, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x03, 0x01, 0x01,
	0x01, 0x03, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x03, 0x01, 0x01,
	0x01, 0x05, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x05, 0x01, 0x01,
	0x01, 0x05, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x02, 0x01, 0x01, 0x01, 0x05, 0x01, 0x01,
	0x01, 0x07, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x07, 0x01, 0x01,
	0x01, 0x07, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x07, 0x01, 0x01,
	0x01, 0x07, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x07, 0x01, 0x01,
	0x01, 0x07, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x02, 0x01, 0x01, 0x01, 0x07, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x09, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x09, 0x01, 0x01,
	0x01, 0x09, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x09, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01
};

static constexpr
unsigned char orig_ext_size_lut[] = {
	0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x08, 0x08, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
#endif

static const
unsigned char psb[16] = {
	0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
	0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82
};

static const unsigned char psb_and_psbend[18] = {
	0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
	0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
	0x02, 0x23
};

static
void dump_lut(unsigned char *lut, char *lutname) {
	printf("unsigned char %s[] = {\n", lutname);
	for (int i = 0; i<32; i++) {
		printf("\t");
		for (int j = 0; j<8; j++) {
			printf("0x%02x", lut[i * 8 + j]);
			if (j != 7) printf(", ");
		}
		if (i != 31) printf(",\n");
		else printf("\n");
	}
	printf("};\n\n");
}

enum class lookup_table_kind {
	opc_lut,
	ext_lut,
	opc_size_lut,
	ext_size_lut
};

// function that was used to build the lookup tables for the packet decoder
template<lookup_table_kind WhichLut>
static constexpr
std::array<unsigned char, 256> build_luts(void) {
	std::array<unsigned char, 256> opc_lut;
	std::array<unsigned char, 256> ext_lut;
	std::array<unsigned char, 256> opc_size_lut;
	std::array<unsigned char, 256> ext_size_lut;

	for (int i = 0; i<256; i++) {
		opc_lut[i] = ppt_invalid;
	}

	for (int i = 0; i<256; i++) {
		ext_lut[i] = ppt_invalid;
	}

	for (int i = 0; i<256; i++) {
		opc_size_lut[i] = 0;
		ext_size_lut[i] = 0;
	}

	//ext packets
	opc_lut[pt_opc_ext] = PPT_EXT;
	opc_size_lut[pt_opc_ext] = 1; // not really important

								  //pad packet
	opc_lut[pt_opc_pad] = ppt_pad;
	opc_size_lut[pt_opc_pad] = 1;

	//tip packet
	for (int i = 0; i<8; i++) {
		unsigned char opcode = (unsigned char)((i << 5) + 0xd);

		if (i == 0) {
			opc_lut[opcode] = ppt_tip;
			opc_size_lut[opcode] = 1;
		}
		else if (i == 1) {
			opc_lut[opcode] = ppt_tip;
			opc_size_lut[opcode] = 1 + 2;
		}
		else if (i == 2) {
			opc_lut[opcode] = ppt_tip;
			opc_size_lut[opcode] = 1 + 4;
		}
		else if ((i == 3) || (i == 4)) {
			opc_lut[opcode] = ppt_tip;
			opc_size_lut[opcode] = 1 + 6;
		}
		else if (i == 6) {
			opc_lut[opcode] = ppt_tip;
			opc_size_lut[opcode] = 1 + 8;
		}
	}

	//tip.pge packet
	for (int i = 0; i<8; i++) {
		unsigned char opcode = (unsigned char)((i << 5) + 0x11);

		if (i == 0) {
			opc_lut[opcode] = ppt_tip_pge;
			opc_size_lut[opcode] = 1;
		}
		else if (i == 1) {
			opc_lut[opcode] = ppt_tip_pge;
			opc_size_lut[opcode] = 1 + 2;
		}
		else if (i == 2) {
			opc_lut[opcode] = ppt_tip_pge;
			opc_size_lut[opcode] = 1 + 4;
		}
		else if ((i == 3) || (i == 4)) {
			opc_lut[opcode] = ppt_tip_pge;
			opc_size_lut[opcode] = 1 + 6;
		}
		else if (i == 6) {
			opc_lut[opcode] = ppt_tip_pge;
			opc_size_lut[opcode] = 1 + 8;
		}
	}

	//tip.pgd packet
	for (int i = 0; i<8; i++) {
		unsigned char opcode = (unsigned char)((i << 5) + 0x1);

		if (i == 0) {
			opc_lut[opcode] = ppt_tip_pgd;
			opc_size_lut[opcode] = 1;
		}
		else if (i == 1) {
			opc_lut[opcode] = ppt_tip_pgd;
			opc_size_lut[opcode] = 1 + 2;
		}
		else if (i == 2) {
			opc_lut[opcode] = ppt_tip_pgd;
			opc_size_lut[opcode] = 1 + 4;
		}
		else if ((i == 3) || (i == 4)) {
			opc_lut[opcode] = ppt_tip_pgd;
			opc_size_lut[opcode] = 1 + 6;
		}
		else if (i == 6) {
			opc_lut[opcode] = ppt_tip_pgd;
			opc_size_lut[opcode] = 1 + 8;
		}
	}

	//fup packet
	for (int i = 0; i<8; i++) {
		unsigned char opcode = (unsigned char)((i << 5) + 0x1d);

		if (i == 0) {
			opc_lut[opcode] = ppt_fup;
			opc_size_lut[opcode] = 1;
		}
		else if (i == 1) {
			opc_lut[opcode] = ppt_fup;
			opc_size_lut[opcode] = 1 + 2;
		}
		else if (i == 2) {
			opc_lut[opcode] = ppt_fup;
			opc_size_lut[opcode] = 1 + 4;
		}
		else if ((i == 3) || (i == 4)) {
			opc_lut[opcode] = ppt_fup;
			opc_size_lut[opcode] = 1 + 6;
		}
		else if (i == 6) {
			opc_lut[opcode] = ppt_fup;
			opc_size_lut[opcode] = 1 + 8;
		}
	}

	//mode packet
	opc_lut[pt_opc_mode] = ppt_mode;
	opc_size_lut[pt_opc_mode] = 2;

	//tsc packet
	opc_lut[pt_opc_tsc] = ppt_tsc;
	opc_size_lut[pt_opc_tsc] = 8;

	//mtc packet
	opc_lut[pt_opc_mtc] = ppt_mtc;
	opc_size_lut[pt_opc_mtc] = 2;

	//cyc packet
	for (int i = 0; i<64; i++) {
		unsigned char opcode = (unsigned char)((i << 2) + 0x3);
		opc_lut[opcode] = ppt_cyc;
		opc_size_lut[opcode] = 1;
	}

	//tnt packets
	for (int i = 1; i <= 6; i++) {
		for (int bits = 0; bits<(1 << i); bits++) {
			unsigned char opcode = (unsigned char)((1 << (i + 1)) + (bits << 1));
			opc_lut[opcode] = ppt_tnt_8;
			opc_size_lut[opcode] = 1;
		}
	}

	//////extensions///////

	//psb packet
	ext_lut[pt_ext_psb] = ppt_psb;
	ext_size_lut[pt_ext_psb] = 16;

	//long tnt packet
	ext_lut[pt_ext_tnt_64] = ppt_tnt_64;
	ext_size_lut[pt_ext_tnt_64] = 8;

	//pip packet
	ext_lut[pt_ext_pip] = ppt_pip;
	ext_size_lut[pt_ext_pip] = 8;

	//ovf packet
	ext_lut[pt_ext_ovf] = ppt_ovf;
	ext_size_lut[pt_ext_ovf] = 2;

	//psbend packet
	ext_lut[pt_ext_psbend] = ppt_psbend;
	ext_size_lut[pt_ext_psbend] = 2;

	//cbr packet
	ext_lut[pt_ext_cbr] = ppt_cbr;
	ext_size_lut[pt_ext_cbr] = 4;

	//tma packet
	ext_lut[pt_ext_tma] = ppt_tma;
	ext_size_lut[pt_ext_tma] = 7;

	//stop packet
	ext_lut[pt_ext_stop] = ppt_stop;
	ext_size_lut[pt_ext_stop] = 2;

	//vmcs packet
	ext_lut[pt_ext_vmcs] = ppt_vmcs;
	ext_size_lut[pt_ext_vmcs] = 7;

	//exstop packet
	ext_lut[pt_ext_exstop] = ppt_exstop;
	ext_size_lut[pt_ext_exstop] = 2;

	//exstop-ip packet
	ext_lut[pt_ext_exstop_ip] = ppt_exstop;
	ext_size_lut[pt_ext_exstop_ip] = 2;

	//mwait packet
	ext_lut[pt_ext_mwait] = ppt_mwait;
	ext_size_lut[pt_ext_mwait] = 10;

	//pwre packet
	ext_lut[pt_ext_pwre] = ppt_pwre;
	ext_size_lut[pt_ext_pwre] = 4;

	//pwrx packet
	ext_lut[pt_ext_pwrx] = ppt_pwrx;
	ext_size_lut[pt_ext_pwrx] = 7;

	//ptw packet
	for (int i = 0; i<2; i++) {
		for (int j = 0; j<2; j++) {
			unsigned char opcode = (unsigned char)((i << 7) + (j << 5) + 0x12);
			ext_lut[opcode] = ppt_ptw;
			if (j == 0) {
				ext_size_lut[opcode] = 6;
			}
			else if (j == 1) {
				ext_size_lut[opcode] = 10;
			}
		}
	}

	//ext2
	ext_lut[pt_ext_ext2] = PPT_EXT;
	ext_size_lut[pt_ext_ext2] = 1; // not really important

	if constexpr (WhichLut == lookup_table_kind::opc_lut)
		return opc_lut;
	else if constexpr (WhichLut == lookup_table_kind::ext_lut)
		return ext_lut;
	else if constexpr (WhichLut == lookup_table_kind::opc_size_lut)
		return opc_size_lut;
	else if constexpr (WhichLut == lookup_table_kind::ext_size_lut)
		return ext_size_lut;

	__compiletime_unreachable();
}

static constexpr std::array<unsigned char, 256> opc_lut =
    build_luts<lookup_table_kind::opc_lut>();
static constexpr std::array<unsigned char, 256> ext_lut =
    build_luts<lookup_table_kind::ext_lut>();
static constexpr std::array<unsigned char, 256> opc_size_lut =
    build_luts<lookup_table_kind::opc_size_lut>();
static constexpr std::array<unsigned char, 256> ext_size_lut =
    build_luts<lookup_table_kind::ext_size_lut>();

#if 0
template <typename T, std::size_t N>
constexpr bool arrays_equal(const std::array<T, N>& std_arr, const T (&c_arr)[N]) {
    for (std::size_t i = 0; i < N; ++i) {
        if (std_arr[i] != c_arr[i]) {
            return false;
        }
    }
    return true;
}

static_assert(arrays_equal(opc_lut, orig_opc_lut));
static_assert(arrays_equal(ext_lut, orig_ext_lut));
static_assert(arrays_equal(opc_size_lut, orig_opc_size_lut));
static_assert(arrays_equal(ext_size_lut, orig_ext_size_lut));
#endif

// sign extend
inline static uint64_t sext(uint64_t val, uint8_t sign) {
	uint64_t signbit, mask;

	signbit = 1ull << (sign - 1);
	mask = ~0ull << sign;

	return val & signbit ? val | mask : val & ~mask;
}

// finds the next psb packet in the data buffer
inline static bool findpsb(const unsigned char **data, size_t *size) {
	if (*size < 16) return false;

	if (memcmp(*data, psb, sizeof(psb)) == 0) return true;

	for (size_t i = 0; i < (*size - sizeof(psb) - 1); i++) {
		if (((*data)[i] == psb[0]) && ((*data)[i+1] == psb[1])) {
			if (memcmp((*data) + i, psb, sizeof(psb)) == 0) {
				*data = *data + i;
				*size = *size - i;
				return true;
			}
		}
	}

	return false;
}

// gets the opcode and the size of the next packet in the trace buffer
static inline int get_next_opcode(const unsigned char *data, size_t size, 
	unsigned char *opcode_p, unsigned char *opcodesize_p)
{
	unsigned char opcode = opc_lut[*data];
	unsigned char opcodesize = opc_size_lut[*data];
    
    // handle extensions
    if(opcode == PPT_EXT) {
      if(size < 2) return 0;

      opcode = ext_lut[*(data+1)];
      opcodesize = ext_size_lut[*(data+1)];

      // second-level extension
      if(opcode == PPT_EXT) {
        if(size < 3) return 0;
        
        // currently there is only one possibility
        if((*(data+2)) == 0x88) {
          opcode = ppt_mnt;
          opcodesize = 11;
        } else {
          opcode = ppt_invalid;
          opcodesize = 0;
        }
      }
    } else if(opcode == ppt_cyc) {
      // special handling for cyc packets since
      // they don't have a predetermined size
      if(*data & 4) {
        opcodesize = 2;

        while(1) {
          if(size < opcodesize) return 0;
          if(!((*(data + (opcodesize - 1))) & 1)) break;
          opcodesize++;
        }
      }
    }

	if (size < opcodesize) return 0;

	*opcode_p = opcode;
	*opcodesize_p = opcodesize;

	return 1;
}

template <IPT_PARAMETERS_DCL>
struct afl_ipt_t
    : public ipt_t<IPT_PARAMETERS_DEF, afl_ipt_t<IPT_PARAMETERS_DEF>> {
#define IsVerbose() (Verbosity >= 1)
#define IsVeryVerbose() (Verbosity >= 2)

  typedef ipt_t<IPT_PARAMETERS_DEF, afl_ipt_t<IPT_PARAMETERS_DEF>> Base;

  using packet_type = Base::packet_type;

  uint32_t previous_offset = 0;
  uint64_t previous_ip = 0;
  const unsigned char *data = nullptr;
  size_t size = 0;

  template <typename... Args>
  afl_ipt_t(Args &&...args) : Base(std::forward<Args>(args)...) {
    data = reinterpret_cast<const unsigned char *>(this->aux_begin);
    size = this->aux_end - this->aux_begin;

#if 0
    if constexpr (!IsVerbose()) {
	dump_lut(opc_lut.data(), "opc_lut");
	dump_lut(ext_lut.data(), "ext_lut");
	dump_lut(opc_size_lut.data(), "opc_size_lut");
	dump_lut(ext_size_lut.data(), "ext_size_lut");
    }
#endif
  }

  void process_packets_engaged(uint64_t offset, packet_type &packet) {
    __attribute__((musttail)) return process_packets<true>(offset, packet);
  }

  void process_packets_unengaged(uint64_t offset, packet_type &packet) {
    __attribute__((musttail)) return process_packets<false>(offset, packet);
  }

uint64_t decode_ip(const unsigned char *data) {
	uint64_t next_ip;

	switch ((*data) >> 5) {
	case 0:
		next_ip = previous_ip;
		break;
	case 1:
		next_ip = (previous_ip & 0xFFFFFFFFFFFF0000ULL) | *((uint16_t *)(data + 1));
		break;
	case 2:
		next_ip = (previous_ip & 0xFFFFFFFF00000000ULL) | *((uint32_t *)(data + 1));
		break;
	case 3:
		next_ip = sext(*((uint32_t *)(data + 1)) | ((uint64_t)(*((uint16_t *)(data + 5))) << 32), 48);
		break;
	case 4:
		next_ip = (previous_ip & 0xFFFF000000000000ULL) | *((uint32_t *)(data + 1)) | ((uint64_t)(*((uint16_t *)(data + 5))) << 32);
		break;
	case 6:
		next_ip = *((uint64_t *)(data + 1));
		break;
	}
	previous_ip = next_ip;

	if constexpr (IsVeryVerbose())
		fprintf(stderr, "ip: %p\n", (void *)next_ip);

	return next_ip;
}

  void packet_sync(packet_type &packet) {
    if (size < sizeof(psb) || !findpsb(&data, &size)) {
            throw end_of_trace_exception();
    }

    previous_offset = 0;
    previous_ip = 0;

    packet.opcodesize = 0;

    this->ptdump_tracking_reset();
  }

  uint64_t next_packet(packet_type &out) {
    {
      auto opcodesize = out.opcodesize;

      data += opcodesize;
      size -= opcodesize;
    }

    if (unlikely(data >= this->aux_end) ||
        unlikely(!get_next_opcode(data, size, &out.opcode, &out.opcodesize)))
            throw end_of_trace_exception();

    if (unlikely(!out.opcodesize))
      throw error_decoding_exception();

    return data - this->aux_begin;
  }


// fast decoder that decodes only tip (and related packets)
// and skips over the reset
template <bool IsEngaged>
void process_packets(uint64_t offset, packet_type &the_packet) {
  uint64_t next_ip;
  auto type = the_packet.opcode;

  if constexpr (!IsVerbose())
    fprintf(stdout, "%016" PRIx64 "\t%u\n", offset, (unsigned)type);

  switch (type) {
  case ppt_psb:
    if (IsVeryVerbose())
      fprintf(stderr, "psb\n");
    this->tracking.in_header = 1;
    break;

  case ppt_psbend:
    if (IsVeryVerbose())
      fprintf(stderr, "psbend\n");
    this->tracking.in_header = 0;
    break;

  case ppt_tsc: {
    if (IsVeryVerbose())
      fprintf(stderr, "tsc\n");
    struct pt_packet_tsc packet;
    packet.tsc = pt_pkt_read_value(data + pt_opcs_tsc, pt_pl_tsc_size);

    this->track_tsc(offset, &packet);
    IPT_PROCESS_GTFO_IF_ENGAGED_CHANGED(IsEngaged);
    break;
  }
  case ppt_cbr: {
    if (IsVeryVerbose())
      fprintf(stderr, "cbr\n");
    struct pt_packet_cbr packet;
    packet.ratio = data[2];

    this->track_cbr(offset, &packet);
    IPT_PROCESS_GTFO_IF_ENGAGED_CHANGED(IsEngaged);
    break;
  }
  case ppt_tma: {
    if (IsVeryVerbose())
      fprintf(stderr, "tma\n");
    struct pt_packet_tma packet;
    pkt_read_tma(&packet, (const uint8_t *)data);

    this->track_tma(offset, &packet);
    IPT_PROCESS_GTFO_IF_ENGAGED_CHANGED(IsEngaged);
    break;
  }
  case ppt_mtc: {
    if (IsVeryVerbose())
      fprintf(stderr, "mtc\n");
    struct pt_packet_mtc packet;
    packet.ctc = data[pt_opcs_mtc];

    this->track_mtc(offset, &packet);
    IPT_PROCESS_GTFO_IF_ENGAGED_CHANGED(IsEngaged);
    break;
  }
  case ppt_cyc: {
    if (IsVeryVerbose())
      fprintf(stderr, "cyc\n");
    struct pt_packet_cyc packet;
    auto sz = pkt_read_cyc(&packet, (const uint8_t *)data, &this->config);
    assert(the_packet.opcodesize == sz);

    this->track_cyc(offset, &packet);
    IPT_PROCESS_GTFO_IF_ENGAGED_CHANGED(IsEngaged);
    break;
  }

  case ppt_mode: {
    struct pt_packet_mode packet;
    auto sz = pkt_read_mode(&packet, (const uint8_t *)data, &this->config);
    assert(the_packet.opcodesize == sz);

    this->handle_mode(packet, offset);
    IPT_PROCESS_GTFO_IF_ENGAGED_CHANGED(IsEngaged);
    break;
  }

  case ppt_fup:
  case ppt_tip:
  case ppt_tip_pge:
  case ppt_tip_pgd: {
#if 0
    uint64_t next_ip = decode_ip(data);
#else
    struct pt_packet_ip packet;
    pkt_read_ip(&packet, (const uint8_t *)data, &this->config);
    uint64_t next_ip = this->track_ip(offset, packet);
#endif
    if constexpr (IsEngaged) {
      if (likely(next_ip))
        this->on_ip(next_ip, offset);
      else
        this->CurrPoint.Invalidate();
    } else {
      if constexpr (IsVeryVerbose())
        if (this->RightProcess())
          fprintf(stderr, "%016" PRIx64 "\t__IP %016" PRIx64 "\n", offset,
                  (uint64_t)next_ip);
    }
    break;
  }
  default:
    break;
  }

  __attribute__((musttail)) return process_packets<IsEngaged>(
      next_packet(the_packet), the_packet);
}

#undef IsVerbose
#undef IsVeryVerbose
};

}

#endif /* x86 */
