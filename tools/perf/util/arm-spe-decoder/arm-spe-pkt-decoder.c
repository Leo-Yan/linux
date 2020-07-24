// SPDX-License-Identifier: GPL-2.0
/*
 * Arm Statistical Profiling Extensions (SPE) support
 * Copyright (c) 2017-2018, Arm Ltd.
 */

#include <stdio.h>
#include <string.h>
#include <endian.h>
#include <byteswap.h>
#include <linux/bitops.h>

#include "arm-spe-pkt-decoder.h"

#if __BYTE_ORDER == __BIG_ENDIAN
#define le16_to_cpu bswap_16
#define le32_to_cpu bswap_32
#define le64_to_cpu bswap_64
#define memcpy_le64(d, s, n) do { \
	memcpy((d), (s), (n));    \
	*(d) = le64_to_cpu(*(d)); \
} while (0)
#else
#define le16_to_cpu
#define le32_to_cpu
#define le64_to_cpu
#define memcpy_le64 memcpy
#endif

static const char * const arm_spe_packet_name[] = {
	[ARM_SPE_PAD]		= "PAD",
	[ARM_SPE_END]		= "END",
	[ARM_SPE_TIMESTAMP]	= "TS",
	[ARM_SPE_ADDRESS]	= "ADDR",
	[ARM_SPE_COUNTER]	= "LAT",
	[ARM_SPE_CONTEXT]	= "CONTEXT",
	[ARM_SPE_OP_TYPE]	= "OP-TYPE",
	[ARM_SPE_EVENTS]	= "EVENTS",
	[ARM_SPE_DATA_SOURCE]	= "DATA-SOURCE",
};

const char *arm_spe_pkt_name(enum arm_spe_pkt_type type)
{
	return arm_spe_packet_name[type];
}

/*
 * Return ARM SPE payload size from header bits 5:4
 *   00 : byte
 *   01 : halfword (2)
 *   10 : word (4)
 *   11 : doubleword (8)
 */
#define PAYLOAD_LEN(val)	\
	(1 << (((val) & SPE_HEADER_SZ_MASK) >> SPE_HEADER_SZ_SHIFT))

static int arm_spe_get_payload(const unsigned char *buf, size_t len,
			       unsigned char ext_hdr,
			       struct arm_spe_pkt *packet)
{
	size_t payload_len = PAYLOAD_LEN(buf[ext_hdr]);

	if (len < 1 + ext_hdr + payload_len)
		return ARM_SPE_NEED_MORE_BYTES;

	buf += 1 + ext_hdr;

	switch (payload_len) {
	case 1: packet->payload = *(uint8_t *)buf; break;
	case 2: packet->payload = le16_to_cpu(*(uint16_t *)buf); break;
	case 4: packet->payload = le32_to_cpu(*(uint32_t *)buf); break;
	case 8: packet->payload = le64_to_cpu(*(uint64_t *)buf); break;
	default: return ARM_SPE_BAD_PACKET;
	}

	return 1 + ext_hdr + payload_len;
}

static int arm_spe_get_pad(struct arm_spe_pkt *packet)
{
	packet->type = ARM_SPE_PAD;
	return 1;
}

static int arm_spe_get_alignment(const unsigned char *buf, size_t len,
				 struct arm_spe_pkt *packet)
{
	unsigned int alignment = 1 << ((buf[0] & 0xf) + 1);

	if (len < alignment)
		return ARM_SPE_NEED_MORE_BYTES;

	packet->type = ARM_SPE_PAD;
	return alignment - (((uintptr_t)buf) & (alignment - 1));
}

static int arm_spe_get_end(struct arm_spe_pkt *packet)
{
	packet->type = ARM_SPE_END;
	return 1;
}

static int arm_spe_get_timestamp(const unsigned char *buf, size_t len,
				 struct arm_spe_pkt *packet)
{
	packet->type = ARM_SPE_TIMESTAMP;
	return arm_spe_get_payload(buf, len, 0, packet);
}

static int arm_spe_get_events(const unsigned char *buf, size_t len,
			      struct arm_spe_pkt *packet)
{
	packet->type = ARM_SPE_EVENTS;

	/* we use index to identify Events with a less number of
	 * comparisons in arm_spe_pkt_desc(): E.g., the LLC-ACCESS,
	 * LLC-REFILL, and REMOTE-ACCESS events are identified if
	 * index > 1.
	 */
	packet->index = PAYLOAD_LEN(buf[0]);

	return arm_spe_get_payload(buf, len, 0, packet);
}

static int arm_spe_get_data_source(const unsigned char *buf, size_t len,
				   struct arm_spe_pkt *packet)
{
	packet->type = ARM_SPE_DATA_SOURCE;
	return arm_spe_get_payload(buf, len, 0, packet);
}

static int arm_spe_get_context(const unsigned char *buf, size_t len,
			       struct arm_spe_pkt *packet)
{
	packet->type = ARM_SPE_CONTEXT;
	packet->index = buf[0] & SPE_CTX_PKT_HDR_INDEX_MASK;
	return arm_spe_get_payload(buf, len, 0, packet);
}

static int arm_spe_get_op_type(const unsigned char *buf, size_t len,
			       struct arm_spe_pkt *packet)
{
	packet->type = ARM_SPE_OP_TYPE;
	packet->index = buf[0] & SPE_OP_PKT_HDR_CLASS_MASK;
	return arm_spe_get_payload(buf, len, 0, packet);
}

static int arm_spe_get_counter(const unsigned char *buf, size_t len,
			       const unsigned char ext_hdr, struct arm_spe_pkt *packet)
{
	packet->type = ARM_SPE_COUNTER;
	if (ext_hdr)
		packet->index = (((buf[0] & SPE_CNT_PKT_HDR_EXT_INDEX_MASK) << 3) |
				  (buf[1] & SPE_CNT_PKT_HDR_INDEX_MASK));
	else
		packet->index = buf[0] & SPE_CNT_PKT_HDR_INDEX_MASK;

	return arm_spe_get_payload(buf, len, ext_hdr, packet);
}

static int arm_spe_get_addr(const unsigned char *buf, size_t len,
			    const unsigned char ext_hdr, struct arm_spe_pkt *packet)
{
	packet->type = ARM_SPE_ADDRESS;
	if (ext_hdr)
		packet->index = (((buf[0] & SPE_ADDR_PKT_HDR_EXT_INDEX_MASK) << 3) |
				  (buf[1] & SPE_ADDR_PKT_HDR_INDEX_MASK));
	else
		packet->index = buf[0] & SPE_ADDR_PKT_HDR_INDEX_MASK;

	return arm_spe_get_payload(buf, len, ext_hdr, packet);
}

static int arm_spe_do_get_packet(const unsigned char *buf, size_t len,
				 struct arm_spe_pkt *packet)
{
	unsigned int hdr;
	unsigned char ext_hdr = 0;

	memset(packet, 0, sizeof(struct arm_spe_pkt));

	if (!len)
		return ARM_SPE_NEED_MORE_BYTES;

	hdr = buf[0];

	if (hdr == SPE_HEADER0_PAD)
		return arm_spe_get_pad(packet);

	if (hdr == SPE_HEADER0_END) /* no timestamp at end of record */
		return arm_spe_get_end(packet);

	if (hdr == SPE_HEADER0_TIMESTAMP)
		return arm_spe_get_timestamp(buf, len, packet);

	if ((hdr & SPE_HEADER0_MASK1) == SPE_HEADER0_EVENTS)
		return arm_spe_get_events(buf, len, packet);

	if ((hdr & SPE_HEADER0_MASK1) == SPE_HEADER0_SOURCE)
		return arm_spe_get_data_source(buf, len, packet);

	if ((hdr & SPE_HEADER0_MASK2) == SPE_HEADER0_CONTEXT)
		return arm_spe_get_context(buf, len, packet);

	if ((hdr & SPE_HEADER0_MASK2) == SPE_HEADER0_OPERATION)
		return arm_spe_get_op_type(buf, len, packet);

	if ((hdr & SPE_HEADER0_MASK3) == SPE_HEADER0_EXTENDED) {
		/* 16-bit extended format header */
		ext_hdr = 1;

		hdr = buf[1];
		if (hdr == SPE_HEADER1_ALIGNMENT)
			return arm_spe_get_alignment(buf, len, packet);
	}

	/*
	 * The short format header's byte 0 or the extended format header's
	 * byte 1 has been assigned to 'hdr', which uses the same encoding for
	 * address packet and counter packet, so don't need to distinguish if
	 * it's short format or extended format and handle in once.
	 */
	if ((hdr & SPE_HEADER0_MASK4) == SPE_HEADER0_ADDRESS)
		return arm_spe_get_addr(buf, len, ext_hdr, packet);

	if ((hdr & SPE_HEADER0_MASK4) == SPE_HEADER0_COUNTER)
		return arm_spe_get_counter(buf, len, ext_hdr, packet);

	return ARM_SPE_BAD_PACKET;
}

int arm_spe_get_packet(const unsigned char *buf, size_t len,
		       struct arm_spe_pkt *packet)
{
	int ret;

	ret = arm_spe_do_get_packet(buf, len, packet);
	/* put multiple consecutive PADs on the same line, up to
	 * the fixed-width output format of 16 bytes per line.
	 */
	if (ret > 0 && packet->type == ARM_SPE_PAD) {
		while (ret < 16 && len > (size_t)ret && !buf[ret])
			ret += 1;
	}
	return ret;
}

int arm_spe_pkt_desc(const struct arm_spe_pkt *packet, char *buf,
		     size_t buf_len)
{
	int ret, ns, el, idx = packet->index;
	unsigned long long payload = packet->payload;
	const char *name = arm_spe_pkt_name(packet->type);
	size_t blen;

	switch (packet->type) {
	case ARM_SPE_BAD:
	case ARM_SPE_PAD:
	case ARM_SPE_END:
		return snprintf(buf, buf_len, "%s", name);
	case ARM_SPE_EVENTS: {
		blen = buf_len;

		ret = 0;
		ret = snprintf(buf, buf_len, "EV");
		if (ret < 0)
			return ret;
		buf += ret;
		blen -= ret;
		if (payload & SPE_EVT_PKT_GEN_EXCEPTION) {
			ret = snprintf(buf, buf_len, " EXCEPTION-GEN");
			if (ret < 0)
				return ret;
			buf += ret;
			blen -= ret;
		}
		if (payload & SPE_EVT_PKT_ARCH_RETIRED) {
			ret = snprintf(buf, buf_len, " RETIRED");
			if (ret < 0)
				return ret;
			buf += ret;
			blen -= ret;
		}
		if (payload & SPE_EVT_PKT_L1D_ACCESS) {
			ret = snprintf(buf, buf_len, " L1D-ACCESS");
			if (ret < 0)
				return ret;
			buf += ret;
			blen -= ret;
		}
		if (payload & SPE_EVT_PKT_L1D_REFILL) {
			ret = snprintf(buf, buf_len, " L1D-REFILL");
			if (ret < 0)
				return ret;
			buf += ret;
			blen -= ret;
		}
		if (payload & SPE_EVT_PKT_TLB_ACCESS) {
			ret = snprintf(buf, buf_len, " TLB-ACCESS");
			if (ret < 0)
				return ret;
			buf += ret;
			blen -= ret;
		}
		if (payload & SPE_EVT_PKT_TLB_WALK) {
			ret = snprintf(buf, buf_len, " TLB-REFILL");
			if (ret < 0)
				return ret;
			buf += ret;
			blen -= ret;
		}
		if (payload & SPE_EVT_PKT_NOT_TAKEN) {
			ret = snprintf(buf, buf_len, " NOT-TAKEN");
			if (ret < 0)
				return ret;
			buf += ret;
			blen -= ret;
		}
		if (payload & SPE_EVT_PKT_MISPREDICTED) {
			ret = snprintf(buf, buf_len, " MISPRED");
			if (ret < 0)
				return ret;
			buf += ret;
			blen -= ret;
		}
		if (idx > 1) {
			if (payload & SPE_EVT_PKT_LLC_ACCESS) {
				ret = snprintf(buf, buf_len, " LLC-ACCESS");
				if (ret < 0)
					return ret;
				buf += ret;
				blen -= ret;
			}
			if (payload & SPE_EVT_PKT_LLC_MISS) {
				ret = snprintf(buf, buf_len, " LLC-REFILL");
				if (ret < 0)
					return ret;
				buf += ret;
				blen -= ret;
			}
			if (payload & SPE_EVT_PKT_REMOTE_ACCESS) {
				ret = snprintf(buf, buf_len, " REMOTE-ACCESS");
				if (ret < 0)
					return ret;
				buf += ret;
				blen -= ret;
			}
		}

		if (idx > 2) {
			if (payload & SPE_EVT_PKT_ALIGNMENT) {
				ret = snprintf(buf, buf_len, " ALIGNMENT");
				if (ret < 0)
					return ret;
				buf += ret;
				blen -= ret;
			}
			if (payload & SPE_EVT_PKT_SVE_PARTIAL_PREDICATE) {
				ret = snprintf(buf, buf_len, " SVE-PARTIAL-PRED");
				if (ret < 0)
					return ret;
				buf += ret;
				blen -= ret;
			}
			if (payload & SPE_EVT_PKT_SVE_EMPTY_PREDICATE) {
				ret = snprintf(buf, buf_len, " SVE-EMPTY-PRED");
				if (ret < 0)
					return ret;
				buf += ret;
				blen -= ret;
			}
		}

		return buf_len - blen;
	}
	case ARM_SPE_OP_TYPE:
		switch (idx) {
		case SPE_OP_PKT_HDR_CLASS_OTHER:
			blen = buf_len;

			if ((payload & SPE_OP_PKT_OTHER_SVE_SUBCLASS_MASK) ==
					SPE_OP_PKT_OTHER_SUBCLASS_SVG_OP) {
				ret = snprintf(buf, buf_len, "SVE-OTHER");
				buf += ret;
				blen -= ret;

				/* Effective Venctor Length */
				ret = snprintf(buf, buf_len, " EVL %d",
					32 << ((payload & SPE_OP_PKT_SVE_EVL_MASK) >>
						SPE_OP_PKT_SVE_EVL_SHIFT));
				buf += ret;
				blen -= ret;

				if (payload & SPE_OP_PKT_SVE_FP) {
					ret = snprintf(buf, buf_len, " FP");
					buf += ret;
					blen -= ret;
				}
				if (payload & SPE_OP_PKT_SVE_PRED) {
					ret = snprintf(buf, buf_len, " PRED");
					buf += ret;
					blen -= ret;
				}
			} else {
				ret = snprintf(buf, buf_len, "OTHER");
				buf += ret;
				blen -= ret;

				ret = snprintf(buf, buf_len, " %s",
					       payload & SPE_OP_PKT_OTHER_SUBCLASS_COND ?
					       "COND-SELECT" : "UNCOND");
				buf += ret;
				blen -= ret;
			}

			if (ret < 0)
				return ret;
			return buf_len - blen;

		case SPE_OP_PKT_HDR_CLASS_LD_ST_ATOMIC:
			blen = buf_len;

			if (payload & SPE_OP_PKT_LDST)
				ret = snprintf(buf, buf_len, "ST");
			else
				ret = snprintf(buf, buf_len, "LD");
			if (ret < 0)
				return ret;
			buf += ret;
			blen -= ret;
			if ((payload & SPE_OP_PKT_LDST_SUBCLASS_ATOMIC_MASK) ==
					SPE_OP_PKT_LDST_SUBCLASS_ATOMIC) {
				if (payload & SPE_OP_PKT_AT) {
					ret = snprintf(buf, buf_len, " AT");
					if (ret < 0)
						return ret;
					buf += ret;
					blen -= ret;
				}
				if (payload & SPE_OP_PKT_EXCL) {
					ret = snprintf(buf, buf_len, " EXCL");
					if (ret < 0)
						return ret;
					buf += ret;
					blen -= ret;
				}
				if (payload & SPE_OP_PKT_AR) {
					ret = snprintf(buf, buf_len, " AR");
					if (ret < 0)
						return ret;
					buf += ret;
					blen -= ret;
				}
			} else if ((payload & SPE_OP_PKT_LDST_SUBCLASS_MASK) ==
					SPE_OP_PKT_LDST_SUBCLASS_SIMD_FP) {
				ret = snprintf(buf, buf_len, " SIMD-FP");
				if (ret < 0)
					return ret;
				buf += ret;
				blen -= ret;
			} else if ((payload & SPE_OP_PKT_LDST_SUBCLASS_MASK) ==
					SPE_OP_PKT_LDST_SUBCLASS_GP_REG) {
				ret = snprintf(buf, buf_len, " GP-REG");
				if (ret < 0)
					return ret;
				buf += ret;
				blen -= ret;
			} else if ((payload & SPE_OP_PKT_LDST_SUBCLASS_MASK) ==
					SPE_OP_PKT_LDST_SUBCLASS_UNSPEC_REG) {
				ret = snprintf(buf, buf_len, " UNSPEC-REG");
				if (ret < 0)
					return ret;
				buf += ret;
				blen -= ret;
			} else if ((payload & SPE_OP_PKT_LDST_SUBCLASS_MASK) ==
					SPE_OP_PKT_LDST_SUBCLASS_MRS_MSR) {
				ret = snprintf(buf, buf_len, " MRS-MSR");
				if (ret < 0)
					return ret;
				buf += ret;
				blen -= ret;
			} else if ((payload & SPE_OP_PKT_LDST_SUBCLASS_SVE_MASK) ==
					SPE_OP_PKT_LDST_SUBCLASS_SVE) {
				/* Effective Venctor Length */
				ret = snprintf(buf, buf_len, " EVL %d",
					32 << ((payload & SPE_OP_PKT_SVE_EVL_MASK) >>
						SPE_OP_PKT_SVE_EVL_SHIFT));
				if (ret < 0)
					return ret;

				buf += ret;
				blen -= ret;

				if (payload & SPE_OP_PKT_SVE_PRED) {
					ret = snprintf(buf, buf_len, " PRED");
					if (ret < 0)
						return ret;
					buf += ret;
					blen -= ret;
				}
				if (payload & SPE_OP_PKT_SVE_SG) {
					ret = snprintf(buf, buf_len, " SG");
					if (ret < 0)
						return ret;
					buf += ret;
					blen -= ret;
				}
			}
			return buf_len - blen;
		case SPE_OP_PKT_HDR_CLASS_BR_ERET:
			blen = buf_len;

			ret = snprintf(buf, buf_len, "B");
			if (ret < 0)
				return ret;
			buf += ret;
			blen -= ret;
			if (payload & SPE_OP_PKT_BRANCH_SUBCLASS_COND) {
				ret = snprintf(buf, buf_len, " COND");
				if (ret < 0)
					return ret;
				buf += ret;
				blen -= ret;
			}
			if ((payload & SPE_OP_PKT_BRANCH_SUBCLASS_MASK) ==
					SPE_OP_PKT_BRANCH_SUBCLASS_INDIRECT) {
				ret = snprintf(buf, buf_len, " IND");
				if (ret < 0)
					return ret;
				buf += ret;
				blen -= ret;
			}
			return buf_len - blen;
		default:
			return 0;
		}
	case ARM_SPE_DATA_SOURCE:
	case ARM_SPE_TIMESTAMP:
		return snprintf(buf, buf_len, "%s %lld", name, payload);
	case ARM_SPE_ADDRESS:
		switch (idx) {
		case SPE_ADDR_PKT_HDR_INDEX_INS:
		case SPE_ADDR_PKT_HDR_INDEX_BRANCH:
			ns = !!(packet->payload & SPE_ADDR_PKT_INST_VA_NS);
			el = packet->payload >> SPE_ADDR_PKT_INST_VA_EL_SHIFT;
			el &= SPE_ADDR_PKT_INST_VA_EL_MASK;
			payload &= GENMASK(SPE_ADDR_PKT_ADDR_MSB, 0);
			return snprintf(buf, buf_len, "%s 0x%llx el%d ns=%d",
					(idx == 1) ? "TGT" : "PC", payload, el, ns);
		case SPE_ADDR_PKT_HDR_INDEX_DATA_VIRT:
			return snprintf(buf, buf_len, "VA 0x%llx", payload);
		case SPE_ADDR_PKT_HDR_INDEX_DATA_PHYS:
			ns = !!(packet->payload & SPE_ADDR_PKT_INST_VA_NS);
			payload &= GENMASK(SPE_ADDR_PKT_ADDR_MSB, 0);
			return snprintf(buf, buf_len, "PA 0x%llx ns=%d",
					payload, ns);
		default:
			return 0;
		}
	case ARM_SPE_CONTEXT:
		return snprintf(buf, buf_len, "%s 0x%lx el%d", name,
				(unsigned long)payload, idx + 1);
	case ARM_SPE_COUNTER: {
		blen = buf_len;

		ret = snprintf(buf, buf_len, "%s %d ", name,
			       (unsigned short)payload);
		buf += ret;
		blen -= ret;
		switch (idx) {
		case SPE_CNT_PKT_HDR_INDEX_TOTAL_LAT:
			ret = snprintf(buf, buf_len, "TOT");
			break;
		case SPE_CNT_PKT_HDR_INDEX_ISSUE_LAT:
			ret = snprintf(buf, buf_len, "ISSUE");
			break;
		case SPE_CNT_PKT_HDR_INDEX_TRANS_LAT:
			ret = snprintf(buf, buf_len, "XLAT");
			break;
		default:
			ret = 0;
			break;
		}
		if (ret < 0)
			return ret;
		blen -= ret;
		return buf_len - blen;
	}
	default:
		break;
	}

	return snprintf(buf, buf_len, "%s 0x%llx (%d)",
			name, payload, packet->index);
}
