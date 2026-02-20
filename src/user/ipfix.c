// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <time.h>
#include "ipfix.h"

/* Internal send buffer */
static uint8_t sendbuf[IPFIX_BUF_SIZE];
static size_t sendpos;
static uint16_t cur_set_tmpl;   /* template ID of currently open data set, 0 = none */
static size_t   cur_set_start;  /* offset of current data set header */
static uint32_t msg_seq_number; /* seq_number snapshot for current message header */

static void buf_reset(void)
{
	sendpos = sizeof(struct ipfix_msg_hdr); /* reserve space for header */
	cur_set_tmpl = 0;
}

static int buf_append(const void *data, size_t len)
{
	if (sendpos + len > IPFIX_BUF_SIZE)
		return -1;
	memcpy(sendbuf + sendpos, data, len);
	sendpos += len;
	return 0;
}

static inline void put16(uint8_t *p, uint16_t v) { v = htons(v); memcpy(p, &v, 2); }
static inline void put32(uint8_t *p, uint32_t v) { v = htonl(v); memcpy(p, &v, 4); }
static inline void put64(uint8_t *p, uint64_t v)
{
	uint32_t hi = htonl((uint32_t)(v >> 32));
	uint32_t lo = htonl((uint32_t)v);
	memcpy(p, &hi, 4);
	memcpy(p + 4, &lo, 4);
}

/* --- Init / Close --- */

int ipfix_init(struct ipfix_exporter *exp, const char *host, uint16_t port,
	       uint32_t obs_domain_id, uint32_t my_region_id)
{
	memset(exp, 0, sizeof(*exp));
	exp->obs_domain_id = obs_domain_id;
	exp->my_region_id = my_region_id;

	struct addrinfo hints = { .ai_socktype = SOCK_DGRAM };
	struct addrinfo *res;
	char portstr[16];
	snprintf(portstr, sizeof(portstr), "%u", port);

	int err = getaddrinfo(host, portstr, &hints, &res);
	if (err) {
		fprintf(stderr, "IPFIX: getaddrinfo(%s:%s): %s\n",
			host, portstr, gai_strerror(err));
		return -1;
	}

	exp->sockfd = socket(res->ai_family, SOCK_DGRAM, 0);
	if (exp->sockfd < 0) {
		fprintf(stderr, "IPFIX: socket: %s\n", strerror(errno));
		freeaddrinfo(res);
		return -1;
	}

	memcpy(&exp->collector, res->ai_addr, res->ai_addrlen);
	exp->collector_len = res->ai_addrlen;
	freeaddrinfo(res);

	msg_seq_number = 0;
	buf_reset();
	return 0;
}

void ipfix_close(struct ipfix_exporter *exp)
{
	if (exp->sockfd >= 0)
		close(exp->sockfd);
	exp->sockfd = -1;
}

/* --- Send raw buffer as IPFIX message --- */

static void ipfix_send_msg(struct ipfix_exporter *exp)
{
	if (sendpos <= sizeof(struct ipfix_msg_hdr))
		return; /* nothing to send */

	/* Fill message header */
	struct ipfix_msg_hdr *hdr = (struct ipfix_msg_hdr *)sendbuf;
	put16((uint8_t *)&hdr->version, 0x000a);
	put16((uint8_t *)&hdr->length, (uint16_t)sendpos);
	put32((uint8_t *)&hdr->export_time, (uint32_t)time(NULL));
	put32((uint8_t *)&hdr->seq_number, msg_seq_number);
	put32((uint8_t *)&hdr->obs_domain_id, exp->obs_domain_id);

	ssize_t ret = sendto(exp->sockfd, sendbuf, sendpos, 0,
			     (struct sockaddr *)&exp->collector,
			     exp->collector_len);
	if (ret < 0)
		fprintf(stderr, "IPFIX: sendto: %s\n", strerror(errno));

	msg_seq_number = exp->seq_number;
	buf_reset();
}

/* --- Template definitions --- */

static void add_field_spec(uint16_t ie_id, uint16_t length)
{
	uint8_t fs[4];
	put16(fs, ie_id);
	put16(fs + 2, length);
	buf_append(fs, 4);
}

static void add_enterprise_field_spec(uint16_t ie_id, uint16_t length, uint32_t pen)
{
	uint8_t fs[8];
	put16(fs, ie_id | IE_ENTERPRISE_BIT);
	put16(fs + 2, length);
	put32(fs + 4, pen);
	buf_append(fs, 8);
}

void ipfix_send_templates(struct ipfix_exporter *exp)
{
	buf_reset();

	/*
	 * Template Set (set_id=2) containing 3 templates.
	 * Calculate total length after building.
	 */
	size_t set_start = sendpos;
	struct ipfix_set_hdr set_hdr = {};
	buf_append(&set_hdr, sizeof(set_hdr)); /* placeholder */

	/* Template 256: IPv4 per-region
	 * Fields: sourceIPv4Address(4), dst_region_id(4,enterprise),
	 *         packetDeltaCount(8), octetDeltaCount(8), flowDirection(1),
	 *         my_region_id(4,enterprise)
	 */
	{
		uint8_t th[4];
		put16(th, TMPL_ID_V4_REGION);
		put16(th + 2, 6); /* 6 fields */
		buf_append(th, 4);
		add_field_spec(IE_SRC_IPV4, 4);
		add_enterprise_field_spec(IE_DST_REGION_ID, 4, ENTERPRISE_PEN);
		add_field_spec(IE_PACKET_DELTA_COUNT, 8);
		add_field_spec(IE_OCTET_DELTA_COUNT, 8);
		add_field_spec(IE_FLOW_DIRECTION, 1);
		add_enterprise_field_spec(IE_MY_REGION_ID, 4, ENTERPRISE_PEN);
	}

	/* Template 257: IPv6 per-region
	 * Fields: sourceIPv6Address(16), dst_region_id(4,enterprise),
	 *         packetDeltaCount(8), octetDeltaCount(8), flowDirection(1),
	 *         my_region_id(4,enterprise)
	 */
	{
		uint8_t th[4];
		put16(th, TMPL_ID_V6_REGION);
		put16(th + 2, 6);
		buf_append(th, 4);
		add_field_spec(IE_SRC_IPV6, 16);
		add_enterprise_field_spec(IE_DST_REGION_ID, 4, ENTERPRISE_PEN);
		add_field_spec(IE_PACKET_DELTA_COUNT, 8);
		add_field_spec(IE_OCTET_DELTA_COUNT, 8);
		add_field_spec(IE_FLOW_DIRECTION, 1);
		add_enterprise_field_spec(IE_MY_REGION_ID, 4, ENTERPRISE_PEN);
	}

	/* Template 258: Per-VNI total
	 * Fields: VxLAN VNI(8), packetDeltaCount(8), octetDeltaCount(8),
	 *         flowDirection(1), my_region_id(4,enterprise), dst_region_id(4,enterprise)
	 */
	{
		uint8_t th[4];
		put16(th, TMPL_ID_VNI_TOTAL);
		put16(th + 2, 6);
		buf_append(th, 4);
		add_field_spec(IE_VXLAN_VNI, 8);
		add_field_spec(IE_PACKET_DELTA_COUNT, 8);
		add_field_spec(IE_OCTET_DELTA_COUNT, 8);
		add_field_spec(IE_FLOW_DIRECTION, 1);
		add_enterprise_field_spec(IE_MY_REGION_ID, 4, ENTERPRISE_PEN);
		add_enterprise_field_spec(IE_DST_REGION_ID_VNI, 4, ENTERPRISE_PEN);
	}

	/* Patch set header length */
	size_t set_len = sendpos - set_start;
	put16(sendbuf + set_start, 2); /* set_id = 2 (template) */
	put16(sendbuf + set_start + 2, (uint16_t)set_len);

	ipfix_send_msg(exp);
}

/* --- Data record export --- */

/* Start a data set for the given template, returns set start offset */
static size_t data_set_begin(uint16_t template_id)
{
	size_t start = sendpos;
	struct ipfix_set_hdr sh = {};
	buf_append(&sh, sizeof(sh)); /* placeholder */
	put16(sendbuf + start, template_id);
	return start;
}

/* Finish a data set, patching its length */
static void data_set_end(size_t set_start)
{
	uint16_t len = (uint16_t)(sendpos - set_start);
	put16(sendbuf + set_start + 2, len);
}

static void close_current_set(void)
{
	if (cur_set_tmpl) {
		data_set_end(cur_set_start);
		cur_set_tmpl = 0;
	}
}

static void ensure_data_set(struct ipfix_exporter *exp, uint16_t tmpl_id, size_t rec_size)
{
	if (cur_set_tmpl == tmpl_id &&
	    sendpos + rec_size <= IPFIX_BUF_SIZE)
		return;

	close_current_set();

	if (sendpos + sizeof(struct ipfix_set_hdr) + rec_size > IPFIX_BUF_SIZE)
		ipfix_send_msg(exp);

	cur_set_start = data_set_begin(tmpl_id);
	cur_set_tmpl = tmpl_id;
}

void ipfix_export_v4(struct ipfix_exporter *exp, uint32_t ip, uint32_t dst_region_id,
		     uint64_t packets, uint64_t bytes, uint8_t dir)
{
	ensure_data_set(exp, TMPL_ID_V4_REGION, 29);

	uint8_t rec[29];
	memcpy(rec, &ip, 4);              /* sourceIPv4Address (network order) */
	put32(rec + 4, dst_region_id);
	put64(rec + 8, packets);
	put64(rec + 16, bytes);
	rec[24] = dir;
	put32(rec + 25, exp->my_region_id & 0xFFFF);
	buf_append(rec, 29);

	exp->seq_number++;
}

void ipfix_export_v6(struct ipfix_exporter *exp, const uint8_t ip6[16],
		     uint32_t dst_region_id, uint64_t packets, uint64_t bytes,
		     uint8_t dir)
{
	ensure_data_set(exp, TMPL_ID_V6_REGION, 41);

	uint8_t rec[41];
	memcpy(rec, ip6, 16);             /* sourceIPv6Address */
	put32(rec + 16, dst_region_id);
	put64(rec + 20, packets);
	put64(rec + 28, bytes);
	rec[36] = dir;
	put32(rec + 37, exp->my_region_id & 0xFFFF);
	buf_append(rec, 41);

	exp->seq_number++;
}

void ipfix_export_vni(struct ipfix_exporter *exp, uint32_t vni,
		      uint32_t dst_region_id,
		      uint64_t packets, uint64_t bytes, uint8_t dir)
{
	ensure_data_set(exp, TMPL_ID_VNI_TOTAL, 33);

	uint8_t rec[33];
	put64(rec, (uint64_t)vni);        /* layer2SegmentId (VNI) */
	put64(rec + 8, packets);
	put64(rec + 16, bytes);
	rec[24] = dir;
	put32(rec + 25, exp->my_region_id);
	put32(rec + 29, dst_region_id);
	buf_append(rec, 33);

	exp->seq_number++;
}

void ipfix_flush(struct ipfix_exporter *exp)
{
	close_current_set();
	if (sendpos > sizeof(struct ipfix_msg_hdr))
		ipfix_send_msg(exp);
}
