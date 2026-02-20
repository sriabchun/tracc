// SPDX-License-Identifier: GPL-2.0
#ifndef IPFIX_H
#define IPFIX_H

#include <stdint.h>
#include <arpa/inet.h>

/*
 * IPFIX exporter for traffic accounting.
 *
 * Template IDs:
 *   256 - IPv4 per-region record (egress/ingress)
 *   257 - IPv6 per-region record (egress/ingress)
 *   258 - Per-VNI total record
 *
 * Uses standard IANA Information Elements where possible,
 * enterprise IEs (PEN 99999) for dst_region_id.
 */

/* IPFIX Message Header (RFC 7011 §3.1) */
struct __attribute__((packed)) ipfix_msg_hdr {
	uint16_t version;       /* 0x000a */
	uint16_t length;        /* total length */
	uint32_t export_time;   /* seconds since epoch */
	uint32_t seq_number;    /* incremental sequence */
	uint32_t obs_domain_id; /* observation domain */
};

/* Set Header (RFC 7011 §3.3.2) */
struct __attribute__((packed)) ipfix_set_hdr {
	uint16_t set_id;   /* 2 = template, 3 = options template, >=256 = data */
	uint16_t length;
};

/* Template IDs */
#define TMPL_ID_V4_REGION  256
#define TMPL_ID_V6_REGION  257
#define TMPL_ID_VNI_TOTAL 258

/* IANA Information Element IDs */
#define IE_SRC_IPV4         8   /* sourceIPv4Address, 4 bytes */
#define IE_SRC_IPV6        27   /* sourceIPv6Address, 16 bytes */
#define IE_PACKET_DELTA_COUNT  2  /* packetDeltaCount, 8 bytes */
#define IE_OCTET_DELTA_COUNT   1  /* octetDeltaCount, 8 bytes */
#define IE_FLOW_DIRECTION    61  /* flowDirection, 1 byte (0=ingress,1=egress) */
#define IE_VXLAN_VNI        351  /* VxLAN VNI (layer2SegmentId), 8 bytes */

/* Private Enterprise Number for custom fields */
#define IE_ENTERPRISE_BIT  0x8000
#define IE_DST_REGION_ID       1     /* custom: dst_region_id (inner), 4 bytes, enterprise=own PEN */
#define IE_MY_REGION_ID    2     /* custom: my_region_id (src), 4 bytes, enterprise=own PEN */
#define IE_DST_REGION_ID_VNI 3  /* custom: dst_region_id (outer/VNI), 4 bytes, enterprise=own PEN */
#define ENTERPRISE_PEN     99999 /* private PEN placeholder */

/* IPFIX exporter context */
struct ipfix_exporter {
	int sockfd;
	struct sockaddr_storage collector;
	socklen_t collector_len;
	uint32_t seq_number;
	uint32_t obs_domain_id;
	uint32_t my_region_id;
};

int ipfix_init(struct ipfix_exporter *exp, const char *host, uint16_t port,
	       uint32_t obs_domain_id, uint32_t my_region_id);
void ipfix_close(struct ipfix_exporter *exp);
void ipfix_send_templates(struct ipfix_exporter *exp);

/*
 * Export counter records via IPFIX.
 * dir: 0 = ingress, 1 = egress (IPFIX IE 61 flowDirection)
 */
void ipfix_export_v4(struct ipfix_exporter *exp, uint32_t ip, uint32_t dst_region_id,
		     uint64_t packets, uint64_t bytes, uint8_t dir);
void ipfix_export_v6(struct ipfix_exporter *exp, const uint8_t ip6[16],
		     uint32_t dst_region_id, uint64_t packets, uint64_t bytes,
		     uint8_t dir);
void ipfix_export_vni(struct ipfix_exporter *exp, uint32_t vni,
		      uint32_t dst_region_id,
		      uint64_t packets, uint64_t bytes, uint8_t dir);

/* Flush buffered records in a single IPFIX message */
void ipfix_flush(struct ipfix_exporter *exp);

/*
 * Buffer for building IPFIX message.
 * Max UDP payload ~65507, we use a conservative 8K.
 */
#define IPFIX_BUF_SIZE 8192

#endif /* IPFIX_H */
