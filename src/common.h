#ifndef TRAFFIC_ACCOUNT_COMMON_H
#define TRAFFIC_ACCOUNT_COMMON_H

#include <linux/types.h>

/* Sentinel dst_region_id for destinations outside any defined region */
#define DST_REGION_ID_NONE  0xFFFFFFFF

/* Default VXLAN UDP port */
#define DEFAULT_VXLAN_PORT 4789

/* Max entries for maps */
#define MAX_COUNTERS   262144  /* 256K src_ip × region pairs */
#define MAX_SUBNETS    16384
#define MAX_INFRA_SUBNETS  4096    /* max infrastructure CIDRs */
#define MAX_VNIS       16384   /* max distinct VNIs for per-VNI accounting */

/* --- IPv4 structures --- */

struct counter_key {
	__u32 src_ip;
	__u32 dst_region_id;
};

struct lpm_key {
	__u32 prefixlen;
	__u32 addr;
};

/* --- IPv6 structures --- */

struct counter_key6 {
	__u8  src_ip6[16];
	__u32 dst_region_id;
};

struct lpm_key6 {
	__u32 prefixlen;
	__u8  addr[16];
};

/* --- Shared counter value --- */

struct counter_val {
	__u64 packets;
	__u64 bytes;
};

/* --- Per-VNI total counter key --- */

struct vni_counter_key {
	__u32 vni;
	__u32 dst_region_id;   /* from outer dst IP LPM lookup, DST_REGION_ID_NONE if unmatched */
	__u8  dir;            /* 0 = egress, 1 = ingress */
	__u8  _pad[3];
};

#endif /* TRAFFIC_ACCOUNT_COMMON_H */
