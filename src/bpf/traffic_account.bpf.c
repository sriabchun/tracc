// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../common.h"

/* VXLAN header: 8 bytes (RFC 7348) */
struct vxlanhdr {
	__be32 vx_flags;  /* Flags(8b) + Reserved(24b) */
	__be32 vx_vni;    /* VNI(24b) + Reserved(8b) */
};

/* --- Maps --- */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CONFIG);
	__type(key, __u32);
	__type(value, __u32);
} config SEC(".maps");

/* IPv4 LPM */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, MAX_SUBNETS);
	__type(key, struct lpm_key);
	__type(value, __u32);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} dst_region_map SEC(".maps");

/* IPv6 LPM */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, MAX_SUBNETS);
	__type(key, struct lpm_key6);
	__type(value, __u32);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} dst_region_map6 SEC(".maps");

/* Infrastructure LPM maps (outer dst IP → dst_region_id) */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, MAX_INFRA_SUBNETS);
	__type(key, struct lpm_key);
	__type(value, __u32);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} dst_infra_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, MAX_INFRA_SUBNETS);
	__type(key, struct lpm_key6);
	__type(value, __u32);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} dst_infra_map6 SEC(".maps");

/*
 * Counter maps use ARRAY_OF_MAPS indirection for atomic swap.
 * Userspace rotates inner maps at each poll cycle: creates a fresh empty
 * inner map, swaps it into the outer slot, then reads and closes the old one
 * with zero contention.
 *
 * Outer slots: [0] = egress, [1] = ingress  (v4/v6)
 *              [0] = single map              (vni)
 */

/* --- IPv4 counter inner maps + outer --- */

struct inner_v4_map {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, MAX_COUNTERS);
	__type(key, struct counter_key);
	__type(value, struct counter_val);
	__uint(map_flags, BPF_F_NO_PREALLOC);
};

struct inner_v4_map egress_v4 SEC(".maps");
struct inner_v4_map ingress_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 2);
	__type(key, __u32);
	__array(values, struct inner_v4_map);
} counters_v4 SEC(".maps") = {
	.values = { [0] = &egress_v4, [1] = &ingress_v4 },
};

/* --- IPv6 counter inner maps + outer --- */

struct inner_v6_map {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, MAX_COUNTERS);
	__type(key, struct counter_key6);
	__type(value, struct counter_val);
	__uint(map_flags, BPF_F_NO_PREALLOC);
};

struct inner_v6_map egress_v6 SEC(".maps");
struct inner_v6_map ingress_v6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 2);
	__type(key, __u32);
	__array(values, struct inner_v6_map);
} counters_v6 SEC(".maps") = {
	.values = { [0] = &egress_v6, [1] = &ingress_v6 },
};

/* --- Per-VNI counter inner map + outer --- */

struct inner_vni_map {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, MAX_VNIS);
	__type(key, struct vni_counter_key);
	__type(value, struct counter_val);
	__uint(map_flags, BPF_F_NO_PREALLOC);
};

struct inner_vni_map vni_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__type(key, __u32);
	__array(values, struct inner_vni_map);
} counters_vni SEC(".maps") = {
	.values = { [0] = &vni_map },
};

/* --- Get configured VXLAN port --- */

static __always_inline __u16 get_vxlan_port(void)
{
	__u32 cfg_idx = CFG_VXLAN_PORT;
	__u32 *val = bpf_map_lookup_elem(&config, &cfg_idx);
	return val ? (__u16)*val : DEFAULT_VXLAN_PORT;
}

/* --- Account an inner IPv4 packet --- */
/* dir: 0 = egress (LPM dst, key src), 1 = ingress (LPM src, key dst) */

static __always_inline int account_inner_v4(struct iphdr *inner_ip, void *data_end, int dir)
{
	if ((void *)(inner_ip + 1) > data_end)
		return -1;

	__u32 src_ip = inner_ip->saddr;
	__u32 dst_ip = inner_ip->daddr;
	__u16 inner_len = bpf_ntohs(inner_ip->tot_len);

	__u32 lpm_ip  = dir ? src_ip : dst_ip;
	__u32 key_ip  = dir ? dst_ip : src_ip;

	struct lpm_key lpm = { .prefixlen = 32, .addr = lpm_ip };
	__u32 *region = bpf_map_lookup_elem(&dst_region_map, &lpm);
	__u32 dst_region_id = region ? *region : DST_REGION_ID_NONE;

	struct counter_key ckey = { .src_ip = key_ip, .dst_region_id = dst_region_id };

	__u32 slot = (__u32)dir;
	void *inner = bpf_map_lookup_elem(&counters_v4, &slot);
	if (!inner)
		return -1;

	struct counter_val *val = bpf_map_lookup_elem(inner, &ckey);
	if (val) {
		val->packets += 1;
		val->bytes += inner_len;
	} else {
		struct counter_val init = { .packets = 1, .bytes = inner_len };
		bpf_map_update_elem(inner, &ckey, &init, BPF_NOEXIST);
	}
	return 0;
}

/* --- Account an inner IPv6 packet --- */

static __always_inline int account_inner_v6(struct ipv6hdr *inner_ip6, void *data_end, int dir)
{
	if ((void *)(inner_ip6 + 1) > data_end)
		return -1;

	__u16 inner_len = bpf_ntohs(inner_ip6->payload_len) + 40;

	/* LPM lookup: ingress looks up src, egress looks up dst */
	struct lpm_key6 lpm = { .prefixlen = 128 };
	__builtin_memcpy(lpm.addr, dir ? &inner_ip6->saddr : &inner_ip6->daddr, 16);
	__u32 *region = bpf_map_lookup_elem(&dst_region_map6, &lpm);
	__u32 dst_region_id = region ? *region : DST_REGION_ID_NONE;

	/* Counter key: ingress keys on dst, egress keys on src.
	 * Mask to /80 — all addresses in the same /80 belong to one host. */
	struct counter_key6 ckey = { .dst_region_id = dst_region_id };
	__builtin_memcpy(ckey.src_ip6, dir ? &inner_ip6->daddr : &inner_ip6->saddr, 10);
	/* bytes 10..15 stay zero from struct initializer */

	__u32 slot = (__u32)dir;
	void *inner = bpf_map_lookup_elem(&counters_v6, &slot);
	if (!inner)
		return -1;

	struct counter_val *val = bpf_map_lookup_elem(inner, &ckey);
	if (val) {
		val->packets += 1;
		val->bytes += inner_len;
	} else {
		struct counter_val init = { .packets = 1, .bytes = inner_len };
		bpf_map_update_elem(inner, &ckey, &init, BPF_NOEXIST);
	}
	return 0;
}

/* --- Account inner packet by ethertype --- */

static __always_inline int account_inner(struct ethhdr *inner_eth, void *data_end, int dir)
{
	if ((void *)(inner_eth + 1) > data_end)
		return -1;

	if (inner_eth->h_proto == bpf_htons(ETH_P_IP)) {
		return account_inner_v4((struct iphdr *)(inner_eth + 1), data_end, dir);
	} else if (inner_eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		return account_inner_v6((struct ipv6hdr *)(inner_eth + 1), data_end, dir);
	}
	return -1;
}

/* Get inner IP payload length from inner ethernet header */
static __always_inline __u16 get_inner_len(struct ethhdr *inner_eth, void *data_end)
{
	if ((void *)(inner_eth + 1) > data_end)
		return 0;
	if (inner_eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = (void *)(inner_eth + 1);
		if ((void *)(ip + 1) > data_end)
			return 0;
		return bpf_ntohs(ip->tot_len);
	} else if (inner_eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = (void *)(inner_eth + 1);
		if ((void *)(ip6 + 1) > data_end)
			return 0;
		return bpf_ntohs(ip6->payload_len) + 40;
	}
	return 0;
}

/*
 * Account per-VNI totals (for non-primary VNIs).
 * Only packets + bytes + direction + dst_region_id, no IP-level breakdown.
 */
static __always_inline void account_vni_total(__u32 vni, __u16 inner_len,
					      int dir, __u32 dst_region_id)
{
	__u32 slot = 0;
	void *inner = bpf_map_lookup_elem(&counters_vni, &slot);
	if (!inner)
		return;

	struct vni_counter_key vkey = {
		.vni = vni, .dst_region_id = dst_region_id, .dir = dir
	};
	struct counter_val *val = bpf_map_lookup_elem(inner, &vkey);
	if (val) {
		val->packets += 1;
		val->bytes += inner_len;
	} else {
		struct counter_val init = { .packets = 1, .bytes = inner_len };
		bpf_map_update_elem(inner, &vkey, &init, BPF_NOEXIST);
	}
}

/*
 * Parse through outer headers to reach VXLAN payload.
 * Supports both IPv4 and IPv6 outer tunnels.
 */
static __always_inline int account_packet(void *data, void *data_end, int dir)
{
	struct ethhdr *outer_eth = data;
	if ((void *)(outer_eth + 1) > data_end)
		return -1;

	struct udphdr *udp;
	__u32 outer_dst4 = 0;
	struct in6_addr *outer_dst6 = NULL;
	int outer_af = 0;

	if (outer_eth->h_proto == bpf_htons(ETH_P_IP)) {
		/* --- Outer IPv4 --- */
		struct iphdr *outer_ip = (void *)(outer_eth + 1);
		if ((void *)(outer_ip + 1) > data_end)
			return -1;
		if (outer_ip->protocol != IPPROTO_UDP)
			return -1;
		__u32 ihl = outer_ip->ihl * 4;
		if (ihl < 20 || (void *)outer_ip + ihl > data_end)
			return -1;
		udp = (void *)outer_ip + ihl;
		outer_dst4 = outer_ip->daddr;
		outer_af = 4;
	} else if (outer_eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		/* --- Outer IPv6 --- */
		struct ipv6hdr *outer_ip6 = (void *)(outer_eth + 1);
		if ((void *)(outer_ip6 + 1) > data_end)
			return -1;
		/* Only handle UDP as next header directly (no extension headers) */
		if (outer_ip6->nexthdr != IPPROTO_UDP)
			return -1;
		udp = (void *)(outer_ip6 + 1);
		outer_dst6 = &outer_ip6->daddr;
		outer_af = 6;
	} else {
		return -1;
	}

	if ((void *)(udp + 1) > data_end)
		return -1;

	__u16 port = get_vxlan_port();
	if (udp->dest != bpf_htons(port))
		return -1;

	/* --- VXLAN Header (8 bytes) --- */
	struct vxlanhdr *vxlan = (void *)(udp + 1);
	if ((void *)(vxlan + 1) > data_end)
		return -1;

	/* Check VNI (upper 24 bits of vx_vni in network byte order) */
	__u32 cfg_idx = CFG_VXLAN_VNI;
	__u32 *cfg_vni = bpf_map_lookup_elem(&config, &cfg_idx);
	if (!cfg_vni)
		return -1;
	__u32 pkt_vni = bpf_ntohl(vxlan->vx_vni) >> 8;

	/* --- Inner Ethernet + IP --- */
	struct ethhdr *inner_eth = (void *)(vxlan + 1);

	if (pkt_vni == *cfg_vni) {
		/* Primary VNI: full per-IP/region accounting */
		return account_inner(inner_eth, data_end, dir);
	}

	/* Non-primary VNI: per-VNI total accounting */
	{
		__u16 inner_len = get_inner_len(inner_eth, data_end);
		if (inner_len) {
			/* Lookup outer dst IP → dst_region_id */
			__u32 dst_region_id = DST_REGION_ID_NONE;
			if (outer_af == 4) {
				struct lpm_key lk = { .prefixlen = 32, .addr = outer_dst4 };
				__u32 *loc = bpf_map_lookup_elem(&dst_infra_map, &lk);
				if (loc)
					dst_region_id = *loc;
			} else if (outer_af == 6 && outer_dst6) {
				struct lpm_key6 lk6 = { .prefixlen = 128 };
				__builtin_memcpy(lk6.addr, outer_dst6, 16);
				__u32 *loc = bpf_map_lookup_elem(&dst_infra_map6, &lk6);
				if (loc)
					dst_region_id = *loc;
			}
			account_vni_total(pkt_vni, inner_len, dir, dst_region_id);
		}
	}

	return 0;
}

SEC("xdp")
int xdp_traffic_account(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	account_packet(data, data_end, 1); /* ingress */
	return XDP_PASS;
}

SEC("tc")
int tc_traffic_account(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	account_packet(data, data_end, 0); /* egress */
	return 0; /* TC_ACT_OK */
}

char _license[] SEC("license") = "GPL";
