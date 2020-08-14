/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Arm Statistical Profiling Extensions (SPE) support
 * Copyright (c) 2017-2018, Arm Ltd.
 */

#ifndef INCLUDE__ARM_SPE_PKT_DECODER_H__
#define INCLUDE__ARM_SPE_PKT_DECODER_H__

#include <stddef.h>
#include <stdint.h>

#define ARM_SPE_PKT_DESC_MAX		256

#define ARM_SPE_NEED_MORE_BYTES		-1
#define ARM_SPE_BAD_PACKET		-2

#define ARM_SPE_PKT_MAX_SZ		16

enum arm_spe_pkt_type {
	ARM_SPE_BAD,
	ARM_SPE_PAD,
	ARM_SPE_END,
	ARM_SPE_TIMESTAMP,
	ARM_SPE_ADDRESS,
	ARM_SPE_COUNTER,
	ARM_SPE_CONTEXT,
	ARM_SPE_OP_TYPE,
	ARM_SPE_EVENTS,
	ARM_SPE_DATA_SOURCE,
};

struct arm_spe_pkt {
	enum arm_spe_pkt_type	type;
	unsigned char		index;
	uint64_t		payload;
};

/* Short header (HEADER0) and extended header (HEADER1) */
#define SPE_HEADER0_PAD			0x0
#define SPE_HEADER0_END			0x1
#define SPE_HEADER0_TIMESTAMP		0x71
#define SPE_HEADER0_MASK1		0xcf	/* Mask for event & data source */
#define SPE_HEADER0_EVENTS		0x42
#define SPE_HEADER0_SOURCE		0x43
#define SPE_HEADER0_MASK2		0xfc	/* Mask for context & operation */
#define SPE_HEADER0_CONTEXT		0x64
#define SPE_HEADER0_OPERATION		0x48
#define SPE_HEADER0_MASK3		0xe0	/* Mask for extended format */
#define SPE_HEADER0_EXTENDED		0x20
#define SPE_HEADER0_MASK4		0xf8	/* Mask for address & counter */
#define SPE_HEADER0_ADDRESS		0xb0
#define SPE_HEADER0_COUNTER		0x98
#define SPE_HEADER1_ALIGNMENT		0x0

#define SPE_HEADER_SZ_SHIFT		(4)
#define SPE_HEADER_SZ_MASK		(0x30)

/* Address packet header */
#define SPE_ADDR_PKT_HDR_INDEX_MASK		(0x7)
#define SPE_ADDR_PKT_HDR_INDEX_INS		(0x0)
#define SPE_ADDR_PKT_HDR_INDEX_BRANCH		(0x1)
#define SPE_ADDR_PKT_HDR_INDEX_DATA_VIRT	(0x2)
#define SPE_ADDR_PKT_HDR_INDEX_DATA_PHYS	(0x3)

#define SPE_ADDR_PKT_HDR_EXT_INDEX_MASK		(0x3)

#define SPE_ADDR_PKT_ADDR_MSB			(55)

/* Address packet payload for data access physical address */
#define SPE_ADDR_PKT_DATA_PA_NS			BIT(63)
#define SPE_ADDR_PKT_DATA_PA_CH			BIT(62)
#define SPE_ADDR_PKT_DATA_PA_PAT_SHIFT		(56)
#define SPE_ADDR_PKT_DATA_PA_PAT_MASK		(0xf)

/* Address packet payload for instrcution virtual address */
#define SPE_ADDR_PKT_INST_VA_NS			BIT(63)
#define SPE_ADDR_PKT_INST_VA_EL_SHIFT		(61)
#define SPE_ADDR_PKT_INST_VA_EL_MASK		(0x3)
#define SPE_ADDR_PKT_INST_VA_EL0		(0)
#define SPE_ADDR_PKT_INST_VA_EL1		(1)
#define SPE_ADDR_PKT_INST_VA_EL2		(2)
#define SPE_ADDR_PKT_INST_VA_EL3		(3)

/* Context packet header */
#define SPE_CTX_PKT_HDR_INDEX_MASK		(0x3)

/* Counter packet header */
#define SPE_CNT_PKT_HDR_INDEX_MASK		(0x7)
#define SPE_CNT_PKT_HDR_INDEX_TOTAL_LAT		(0x0)
#define SPE_CNT_PKT_HDR_INDEX_ISSUE_LAT		(0x1)
#define SPE_CNT_PKT_HDR_INDEX_TRANS_LAT		(0x2)

#define SPE_CNT_PKT_HDR_EXT_INDEX_MASK		(0x3)

/* Event packet payload */
#define SPE_EVT_PKT_SVE_EMPTY_PREDICATE		BIT(18)
#define SPE_EVT_PKT_SVE_PARTIAL_PREDICATE	BIT(17)
#define SPE_EVT_PKT_ALIGNMENT			BIT(11)
#define SPE_EVT_PKT_REMOTE_ACCESS		BIT(10)
#define SPE_EVT_PKT_LLC_MISS			BIT(9)
#define SPE_EVT_PKT_LLC_ACCESS			BIT(8)
#define SPE_EVT_PKT_MISPREDICTED		BIT(7)
#define SPE_EVT_PKT_NOT_TAKEN			BIT(6)
#define SPE_EVT_PKT_TLB_WALK			BIT(5)
#define SPE_EVT_PKT_TLB_ACCESS			BIT(4)
#define SPE_EVT_PKT_L1D_REFILL			BIT(3)
#define SPE_EVT_PKT_L1D_ACCESS			BIT(2)
#define SPE_EVT_PKT_ARCH_RETIRED		BIT(1)
#define SPE_EVT_PKT_GEN_EXCEPTION		BIT(0)

/* Operation packet header */
#define SPE_OP_PKT_HDR_CLASS_MASK		(0x7)
#define SPE_OP_PKT_HDR_CLASS_OTHER		(0x0)
#define SPE_OP_PKT_HDR_CLASS_LD_ST_ATOMIC	(0x1)
#define SPE_OP_PKT_HDR_CLASS_BR_ERET		(0x2)

#define SPE_OP_PKT_OTHER_SUBCLASS_MASK		(0xfe)
#define SPE_OP_PKT_OTHER_SUBCLASS_OTHER_OP	(0x0)
#define SPE_OP_PKT_OTHER_SVE_SUBCLASS_MASK	(0x89)
#define SPE_OP_PKT_OTHER_SUBCLASS_SVG_OP	(0x8)

#define SPE_OP_PKT_OTHER_SUBCLASS_COND		BIT(0)

#define SPE_OP_PKT_BRANCH_SUBCLASS_MASK		(0xfe)
#define SPE_OP_PKT_BRANCH_SUBCLASS_DIRECT	(0x0)
#define SPE_OP_PKT_BRANCH_SUBCLASS_INDIRECT	(0x2)

#define SPE_OP_PKT_BRANCH_SUBCLASS_COND		BIT(0)

#define SPE_OP_PKT_LDST_SUBCLASS_MASK		(0xfe)
#define SPE_OP_PKT_LDST_SUBCLASS_GP_REG		(0x0)
#define SPE_OP_PKT_LDST_SUBCLASS_SIMD_FP	(0x4)
#define SPE_OP_PKT_LDST_SUBCLASS_UNSPEC_REG	(0x10)
#define SPE_OP_PKT_LDST_SUBCLASS_MRS_MSR	(0x30)

#define SPE_OP_PKT_LDST_SUBCLASS_ATOMIC_MASK	(0xe2)
#define SPE_OP_PKT_LDST_SUBCLASS_ATOMIC		(0x2)

#define SPE_OP_PKT_LDST_SUBCLASS_SVE_MASK	(0xa)
#define SPE_OP_PKT_LDST_SUBCLASS_SVE		(0x8)

#define SPE_OP_PKT_AR				BIT(4)
#define SPE_OP_PKT_EXCL				BIT(3)
#define SPE_OP_PKT_AT				BIT(2)
#define SPE_OP_PKT_LDST				BIT(0)

const char *arm_spe_pkt_name(enum arm_spe_pkt_type);

int arm_spe_get_packet(const unsigned char *buf, size_t len,
		       struct arm_spe_pkt *packet);

int arm_spe_pkt_desc(const struct arm_spe_pkt *packet, char *buf, size_t len);
#endif
