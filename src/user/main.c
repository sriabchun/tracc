// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../common.h"
#include "ipfix.h"

#define DIR_BOTH    0
#define DIR_INGRESS 1
#define DIR_EGRESS  2

static volatile sig_atomic_t running = 1;
static volatile sig_atomic_t reload_flag = 0;

static void sig_handler(int sig)
{
	(void)sig;
	running = 0;
}

static void sighup_handler(int sig)
{
	(void)sig;
	reload_flag = 1;
}

/* --- Configuration --- */

struct subnet_region {
	int af;          /* AF_INET or AF_INET6 */
	__u32 addr;      /* IPv4 only */
	__u8  addr6[16]; /* IPv6 only */
	__u32 prefixlen;
	__u32 dst_region_id;
};

struct infra_entry {
	int af;          /* AF_INET or AF_INET6 */
	__u32 addr;      /* IPv4 only */
	__u8  addr6[16]; /* IPv6 only */
	__u32 prefixlen;
	__u32 dst_region_id;
};

struct app_config {
	char ifname[IF_NAMESIZE];
	__u16 vxlan_port;
	__u32 vxlan_vni;
	int poll_interval;
	int direction;        /* 0 = both, 1 = ingress only, 2 = egress only */
	char collector[256];   /* IP[:port], empty = no IPFIX export */
	__u16 collector_port;
	__u32 my_region_id;   /* mandatory, included in every IPFIX record */

	struct subnet_region *regions;
	int n_regions;

	struct infra_entry *infra;
	int n_infra;
};

static void config_free(struct app_config *cfg)
{
	free(cfg->regions);
	free(cfg->infra);
}

static int parse_config(const char *path, struct app_config *cfg)
{
	FILE *f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "Cannot open config %s: %s\n", path, strerror(errno));
		return -1;
	}

	/* defaults */
	cfg->vxlan_port = DEFAULT_VXLAN_PORT;
	cfg->vxlan_vni = 0;
	cfg->poll_interval = 30;
	cfg->direction = DIR_BOTH;
	cfg->collector[0] = '\0';
	cfg->collector_port = 4739;  /* IANA default for IPFIX */
	cfg->my_region_id = 0;
	cfg->ifname[0] = '\0';
	cfg->regions = NULL;
	cfg->n_regions = 0;
	cfg->infra = NULL;
	cfg->n_infra = 0;

	int regions_cap = 0;
	int infra_cap = 0;
	int cur_region_id = -1;
	int cur_dst_region_id = -1;

	char line[256];
	char section[64] = "";

	while (fgets(line, sizeof(line), f)) {
		/* strip newline and comments */
		char *nl = strchr(line, '\n');
		if (nl) *nl = '\0';
		char *comment = strchr(line, '#');
		if (comment) *comment = '\0';

		/* skip empty */
		char *p = line;
		while (*p == ' ' || *p == '\t') p++;
		if (*p == '\0') continue;

		/* section header */
		if (*p == '[') {
			char *end = strchr(p, ']');
			if (end) {
				*end = '\0';
				snprintf(section, sizeof(section), "%s", p + 1);
			}
			if (strncmp(section, "region ", 7) == 0) {
				/* [region Continent/Name] or [region Continent/Name/N] */
				const char *sect_path = section + 7;
				/* Count slashes: 1 = region, 2+ = AZ */
				int slashes = 0;
				const char *last_slash = NULL;
				for (const char *s = sect_path; *s; s++)
					if (*s == '/') { slashes++; last_slash = s; }
				if (slashes >= 2 && last_slash) {
					/* AZ: dst_region_id = dst_region_id | (az << 16) */
					int az = atoi(last_slash + 1);
					if (cur_region_id >= 0)
						cur_dst_region_id = cur_region_id | (az << 16);
					else
						cur_dst_region_id = -1;
				} else {
					cur_region_id = -1;
				}
			}
			continue;
		}

		if (strcmp(section, "general") == 0) {
			char key[64], val[64];
			if (sscanf(p, "%63s %63s", key, val) == 2) {
				if (strcmp(key, "interface") == 0)
					snprintf(cfg->ifname, sizeof(cfg->ifname), "%.15s", val);
				else if (strcmp(key, "vxlan_port") == 0) {
					unsigned long v = strtoul(val, NULL, 0);
					if (v == 0 || v > 65535) {
						fprintf(stderr, "Config error: invalid vxlan_port '%s'\n", val);
						fclose(f); return -1;
					}
					cfg->vxlan_port = (__u16)v;
				}
				else if (strcmp(key, "vxlan_vni") == 0) {
					unsigned long v = strtoul(val, NULL, 0);
					if (v == 0 || v > 0xFFFFFF) {
						fprintf(stderr, "Config error: invalid vxlan_vni '%s' (must be 1..16777215)\n", val);
						fclose(f); return -1;
					}
					cfg->vxlan_vni = (__u32)v;
				}
				else if (strcmp(key, "poll_interval") == 0) {
					long v = strtol(val, NULL, 10);
					if (v < 1) {
						fprintf(stderr, "Config error: invalid poll_interval '%s'\n", val);
						fclose(f); return -1;
					}
					cfg->poll_interval = (int)v;
				}
				else if (strcmp(key, "direction") == 0) {
					if (strcmp(val, "ingress") == 0)
						cfg->direction = DIR_INGRESS;
					else if (strcmp(val, "egress") == 0)
						cfg->direction = DIR_EGRESS;
					else
						cfg->direction = DIR_BOTH;
				}
				else if (strcmp(key, "collector") == 0) {
					if (val[0] == '[') {
						/* Bracketed IPv6: [addr]:port */
						char *bracket = strchr(val, ']');
						if (bracket) {
							size_t hlen = bracket - val - 1;
							if (hlen >= sizeof(cfg->collector))
								hlen = sizeof(cfg->collector) - 1;
							memcpy(cfg->collector, val + 1, hlen);
							cfg->collector[hlen] = '\0';
							if (*(bracket + 1) == ':')
								cfg->collector_port = (__u16)strtoul(bracket + 2, NULL, 10);
						}
					} else {
						char *colon = strrchr(val, ':');
						/* Only treat as host:port if there's exactly one colon (IPv4) */
						if (colon && strchr(val, ':') == colon) {
							size_t hlen = colon - val;
							if (hlen >= sizeof(cfg->collector))
								hlen = sizeof(cfg->collector) - 1;
							memcpy(cfg->collector, val, hlen);
							cfg->collector[hlen] = '\0';
							cfg->collector_port = (__u16)strtoul(colon + 1, NULL, 10);
						} else {
							/* Bare address (IPv4 or IPv6 without port) */
							snprintf(cfg->collector,
								 sizeof(cfg->collector),
								 "%.255s", val);
						}
					}
				}
				else if (strcmp(key, "my_region_id") == 0)
					cfg->my_region_id = (__u32)strtoul(val, NULL, 0);
			}
		} else if (strncmp(section, "region ", 7) == 0) {
			/* Determine if region or AZ by counting slashes */
			const char *sect_path = section + 7;
			int slashes = 0;
			for (const char *s = sect_path; *s; s++)
				if (*s == '/') slashes++;
			int is_az = (slashes >= 2);

			if (!is_az) {
				/* "id 0xXXYY" line sets the current region id */
				char key[64], val[64];
				if (sscanf(p, "%63s %63s", key, val) == 2 &&
				    strcmp(key, "id") == 0) {
					cur_region_id = (int)strtoul(val, NULL, 0);
					continue;
				}
			}

			int cur_id = is_az ? cur_dst_region_id : cur_region_id;
			if (cur_id < 0) continue;

			/* CIDR line */
			char cidr[64];
			if (sscanf(p, "%63s", cidr) != 1) continue;
			char *slash = strchr(cidr, '/');
			if (!slash) continue;
			*slash = '\0';
			int prefixlen = atoi(slash + 1);

			struct in_addr addr4;
			struct in6_addr addr6;

			if (is_az) {
				if (cfg->n_infra >= infra_cap) {
					infra_cap = infra_cap ? infra_cap * 2 : 64;
					void *tmp = realloc(cfg->infra,
						infra_cap * sizeof(struct infra_entry));
					if (!tmp) { fclose(f); return -1; }
					cfg->infra = tmp;
				}

				if (inet_pton(AF_INET, cidr, &addr4) == 1) {
					cfg->infra[cfg->n_infra].af = AF_INET;
					cfg->infra[cfg->n_infra].addr = addr4.s_addr;
					cfg->infra[cfg->n_infra].prefixlen = prefixlen;
					cfg->infra[cfg->n_infra].dst_region_id = (__u32)cur_id;
					cfg->n_infra++;
				} else if (inet_pton(AF_INET6, cidr, &addr6) == 1) {
					cfg->infra[cfg->n_infra].af = AF_INET6;
					memcpy(cfg->infra[cfg->n_infra].addr6, &addr6, 16);
					cfg->infra[cfg->n_infra].prefixlen = prefixlen;
					cfg->infra[cfg->n_infra].dst_region_id = (__u32)cur_id;
					cfg->n_infra++;
				}
			} else {
				if (cfg->n_regions >= regions_cap) {
					regions_cap = regions_cap ? regions_cap * 2 : 64;
					void *tmp = realloc(cfg->regions,
						regions_cap * sizeof(struct subnet_region));
					if (!tmp) { fclose(f); return -1; }
					cfg->regions = tmp;
				}

				if (inet_pton(AF_INET, cidr, &addr4) == 1) {
					cfg->regions[cfg->n_regions].af = AF_INET;
					cfg->regions[cfg->n_regions].addr = addr4.s_addr;
					cfg->regions[cfg->n_regions].prefixlen = prefixlen;
					cfg->regions[cfg->n_regions].dst_region_id = (__u32)cur_id;
					cfg->n_regions++;
				} else if (inet_pton(AF_INET6, cidr, &addr6) == 1) {
					cfg->regions[cfg->n_regions].af = AF_INET6;
					memcpy(cfg->regions[cfg->n_regions].addr6, &addr6, 16);
					cfg->regions[cfg->n_regions].prefixlen = prefixlen;
					cfg->regions[cfg->n_regions].dst_region_id = (__u32)cur_id;
					cfg->n_regions++;
				}
			}
		}
	}

	fclose(f);

	if (cfg->ifname[0] == '\0') {
		fprintf(stderr, "Config error: 'interface' not set in [general]\n");
		return -1;
	}

	if (cfg->vxlan_vni == 0) {
		fprintf(stderr, "Config error: 'vxlan_vni' not set in [general]\n");
		return -1;
	}

	if (cfg->my_region_id == 0) {
		fprintf(stderr, "Config error: 'my_region_id' not set in [general]\n");
		return -1;
	}

	return 0;
}

/* --- Map population --- */

static int populate_config_map(int map_fd, struct app_config *cfg)
{
	__u32 key, val;

	key = CFG_VXLAN_PORT;
	val = cfg->vxlan_port;
	if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) < 0)
		return -1;

	key = CFG_VXLAN_VNI;
	val = cfg->vxlan_vni;
	return bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
}

static int populate_regions(int map_fd, int map6_fd,
			    struct subnet_region *regions, int count)
{
	for (int i = 0; i < count; i++) {
		if (regions[i].af == AF_INET6) {
			struct lpm_key6 key = { .prefixlen = regions[i].prefixlen };
			memcpy(key.addr, regions[i].addr6, 16);
			if (bpf_map_update_elem(map6_fd, &key,
						&regions[i].dst_region_id, BPF_ANY) < 0) {
				fprintf(stderr, "Failed to add region6 %u: %s\n",
					regions[i].dst_region_id, strerror(errno));
				return -1;
			}
		} else {
			struct lpm_key key = {
				.prefixlen = regions[i].prefixlen,
				.addr = regions[i].addr,
			};
			if (bpf_map_update_elem(map_fd, &key,
						&regions[i].dst_region_id, BPF_ANY) < 0) {
				fprintf(stderr, "Failed to add region %u: %s\n",
					regions[i].dst_region_id, strerror(errno));
				return -1;
			}
		}
	}
	return 0;
}

static int populate_infra(int map_fd, int map6_fd,
			      struct infra_entry *locs, int count)
{
	for (int i = 0; i < count; i++) {
		if (locs[i].af == AF_INET6) {
			struct lpm_key6 key = { .prefixlen = locs[i].prefixlen };
			memcpy(key.addr, locs[i].addr6, 16);
			if (bpf_map_update_elem(map6_fd, &key,
						&locs[i].dst_region_id, BPF_ANY) < 0) {
				fprintf(stderr, "Failed to add infra subnet6 %u: %s\n",
					locs[i].dst_region_id, strerror(errno));
				return -1;
			}
		} else {
			struct lpm_key key = {
				.prefixlen = locs[i].prefixlen,
				.addr = locs[i].addr,
			};
			if (bpf_map_update_elem(map_fd, &key,
						&locs[i].dst_region_id, BPF_ANY) < 0) {
				fprintf(stderr, "Failed to add infra subnet %u: %s\n",
					locs[i].dst_region_id, strerror(errno));
				return -1;
			}
		}
	}
	return 0;
}

/* --- Config reload (SIGHUP) --- */

static void clear_lpm_map4(int fd)
{
	struct lpm_key key;
	while (bpf_map_get_next_key(fd, NULL, &key) == 0)
		bpf_map_delete_elem(fd, &key);
}

static void clear_lpm_map6(int fd)
{
	struct lpm_key6 key;
	while (bpf_map_get_next_key(fd, NULL, &key) == 0)
		bpf_map_delete_elem(fd, &key);
}

static int reload_config(const char *config_path, struct app_config *cfg,
			 int config_fd, int regions_fd, int regions6_fd,
			 int dst_infra_fd, int dst_infra6_fd)
{
	struct app_config new_cfg = {};
	if (parse_config(config_path, &new_cfg) < 0) {
		fprintf(stderr, "SIGHUP: failed to parse config, keeping old\n");
		config_free(&new_cfg);
		return -1;
	}

	/* Warn about immutable fields */
	if (strcmp(new_cfg.ifname, cfg->ifname) != 0)
		fprintf(stderr, "SIGHUP: 'interface' change ignored (requires restart)\n");
	if (new_cfg.direction != cfg->direction)
		fprintf(stderr, "SIGHUP: 'direction' change ignored (requires restart)\n");
	if (strcmp(new_cfg.collector, cfg->collector) != 0 ||
	    new_cfg.collector_port != cfg->collector_port)
		fprintf(stderr, "SIGHUP: 'collector' change ignored (requires restart)\n");
	if (new_cfg.my_region_id != cfg->my_region_id)
		fprintf(stderr, "SIGHUP: 'my_region_id' change ignored (requires restart)\n");

	/* Update config map (vxlan_port, vxlan_vni) */
	populate_config_map(config_fd, &new_cfg);

	/* Clear and repopulate LPM maps */
	clear_lpm_map4(regions_fd);
	clear_lpm_map6(regions6_fd);
	clear_lpm_map4(dst_infra_fd);
	clear_lpm_map6(dst_infra6_fd);

	populate_regions(regions_fd, regions6_fd,
			 new_cfg.regions, new_cfg.n_regions);
	populate_infra(dst_infra_fd, dst_infra6_fd,
		       new_cfg.infra, new_cfg.n_infra);

	/* Update mutable fields */
	cfg->vxlan_port = new_cfg.vxlan_port;
	cfg->vxlan_vni = new_cfg.vxlan_vni;
	cfg->poll_interval = new_cfg.poll_interval;

	/* Swap region/infra arrays */
	free(cfg->regions);
	free(cfg->infra);
	cfg->regions = new_cfg.regions;
	cfg->n_regions = new_cfg.n_regions;
	cfg->infra = new_cfg.infra;
	cfg->n_infra = new_cfg.n_infra;

	printf("SIGHUP: config reloaded (%d regions, %d infra CIDRs)\n",
	       cfg->n_regions, cfg->n_infra);
	return 0;
}

/* --- Map-swap infrastructure --- */

struct inner_map_fds {
	int v4[2];   /* [0]=egress, [1]=ingress */
	int v6[2];
	int vni;
};

static int create_inner_map(const char *name, __u32 key_size,
			    __u32 value_size, __u32 max_entries)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts,
		.map_flags = BPF_F_NO_PREALLOC,
	);
	int fd = bpf_map_create(BPF_MAP_TYPE_PERCPU_HASH, name,
				key_size, value_size, max_entries, &opts);
	if (fd < 0)
		fprintf(stderr, "Failed to create inner map '%s': %s\n",
			name, strerror(errno));
	return fd;
}

static int create_inner_maps(struct inner_map_fds *fds)
{
	fds->v4[0] = create_inner_map("egress_v4",
		sizeof(struct counter_key), sizeof(struct counter_val),
		MAX_COUNTERS);
	fds->v4[1] = create_inner_map("ingress_v4",
		sizeof(struct counter_key), sizeof(struct counter_val),
		MAX_COUNTERS);
	fds->v6[0] = create_inner_map("egress_v6",
		sizeof(struct counter_key6), sizeof(struct counter_val),
		MAX_COUNTERS);
	fds->v6[1] = create_inner_map("ingress_v6",
		sizeof(struct counter_key6), sizeof(struct counter_val),
		MAX_COUNTERS);
	fds->vni = create_inner_map("vni_map",
		sizeof(struct vni_counter_key), sizeof(struct counter_val),
		MAX_VNIS);

	if (fds->v4[0] < 0 || fds->v4[1] < 0 ||
	    fds->v6[0] < 0 || fds->v6[1] < 0 || fds->vni < 0) {
		if (fds->v4[0] >= 0) close(fds->v4[0]);
		if (fds->v4[1] >= 0) close(fds->v4[1]);
		if (fds->v6[0] >= 0) close(fds->v6[0]);
		if (fds->v6[1] >= 0) close(fds->v6[1]);
		if (fds->vni >= 0) close(fds->vni);
		return -1;
	}
	return 0;
}

static int swap_inner_maps(int outer_v4, int outer_v6, int outer_vni,
			   struct inner_map_fds *new_fds)
{
	__u32 slot;

	slot = 0;
	if (bpf_map_update_elem(outer_v4, &slot, &new_fds->v4[0], BPF_ANY) < 0)
		return -1;
	slot = 1;
	if (bpf_map_update_elem(outer_v4, &slot, &new_fds->v4[1], BPF_ANY) < 0)
		return -1;

	slot = 0;
	if (bpf_map_update_elem(outer_v6, &slot, &new_fds->v6[0], BPF_ANY) < 0)
		return -1;
	slot = 1;
	if (bpf_map_update_elem(outer_v6, &slot, &new_fds->v6[1], BPF_ANY) < 0)
		return -1;

	slot = 0;
	if (bpf_map_update_elem(outer_vni, &slot, &new_fds->vni, BPF_ANY) < 0)
		return -1;

	return 0;
}

static void close_inner_maps(struct inner_map_fds *fds)
{
	if (fds->v4[0] >= 0) { close(fds->v4[0]); fds->v4[0] = -1; }
	if (fds->v4[1] >= 0) { close(fds->v4[1]); fds->v4[1] = -1; }
	if (fds->v6[0] >= 0) { close(fds->v6[0]); fds->v6[0] = -1; }
	if (fds->v6[1] >= 0) { close(fds->v6[1]); fds->v6[1] = -1; }
	if (fds->vni >= 0) { close(fds->vni); fds->vni = -1; }
}

/* --- Counter polling --- */

static void poll_counters_v4(int map_fd, const char *timebuf, const char *dir,
			    struct ipfix_exporter *exp, int verbose,
			    struct counter_val *vals, int ncpus)
{
	struct counter_key key = {}, next_key;
	uint8_t ipfix_dir = (strcmp(dir, "ingress") == 0) ? 0 : 1;

	while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &next_key, vals) == 0) {
			__u64 total_pkts = 0, total_bytes = 0;
			for (int i = 0; i < ncpus; i++) {
				total_pkts += vals[i].packets;
				total_bytes += vals[i].bytes;
			}

			if (total_pkts > 0) {
				if (exp)
					ipfix_export_v4(exp, next_key.src_ip,
							next_key.dst_region_id,
							total_pkts, total_bytes,
							ipfix_dir);
				if (verbose) {
					char ip_str[INET_ADDRSTRLEN];
					struct in_addr sa = { .s_addr = next_key.src_ip };
					inet_ntop(AF_INET, &sa, ip_str, sizeof(ip_str));
					printf("%s dir=%s ip=%s region=%u packets=%llu bytes=%llu\n",
					       timebuf, dir, ip_str, next_key.dst_region_id,
					       (unsigned long long)total_pkts,
					       (unsigned long long)total_bytes);
				}
			}
		}

		key = next_key;
	}
}

static void poll_counters_v6(int map_fd, const char *timebuf, const char *dir,
			    struct ipfix_exporter *exp, int verbose,
			    struct counter_val *vals, int ncpus)
{
	struct counter_key6 key = {}, next_key;
	uint8_t ipfix_dir = (strcmp(dir, "ingress") == 0) ? 0 : 1;

	while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &next_key, vals) == 0) {
			__u64 total_pkts = 0, total_bytes = 0;
			for (int i = 0; i < ncpus; i++) {
				total_pkts += vals[i].packets;
				total_bytes += vals[i].bytes;
			}

			if (total_pkts > 0) {
				if (exp)
					ipfix_export_v6(exp, next_key.src_ip6,
							next_key.dst_region_id,
							total_pkts, total_bytes,
							ipfix_dir);
				if (verbose) {
					char ip_str[INET6_ADDRSTRLEN];
					inet_ntop(AF_INET6, next_key.src_ip6,
						  ip_str, sizeof(ip_str));
					printf("%s dir=%s ip=%s region=%u packets=%llu bytes=%llu\n",
					       timebuf, dir, ip_str, next_key.dst_region_id,
					       (unsigned long long)total_pkts,
					       (unsigned long long)total_bytes);
				}
			}
		}

		key = next_key;
	}
}

static void poll_vni_counters(int map_fd, const char *timebuf,
			      struct ipfix_exporter *exp, int verbose,
			      struct counter_val *vals, int ncpus)
{
	struct vni_counter_key key = {}, next_key;

	while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &next_key, vals) == 0) {
			__u64 total_pkts = 0, total_bytes = 0;
			for (int i = 0; i < ncpus; i++) {
				total_pkts += vals[i].packets;
				total_bytes += vals[i].bytes;
			}

			if (total_pkts > 0) {
				if (exp)
					ipfix_export_vni(exp, next_key.vni,
							 next_key.dst_region_id,
							 total_pkts, total_bytes,
							 next_key.dir ? 0 : 1);
				if (verbose) {
					printf("%s dir=%s vni=%u dst_region_id=%u packets=%llu bytes=%llu\n",
					       timebuf,
					       next_key.dir ? "ingress" : "egress",
					       next_key.vni,
					       next_key.dst_region_id,
					       (unsigned long long)total_pkts,
					       (unsigned long long)total_bytes);
				}
			}
		}

		key = next_key;
	}
}

/*
 * Atomic map-swap poll cycle:
 * 1. Create fresh empty inner maps
 * 2. Swap them into the outer ARRAY_OF_MAPS
 * 3. Wait for in-flight BPF programs to drain (RCU grace period)
 * 4. Iterate the old maps (read-only, no deletes needed)
 * 5. Export via IPFIX
 * 6. Close old maps (kernel frees them)
 */
static void poll_counters(int outer_v4, int outer_v6, int outer_vni,
			  struct inner_map_fds *cur,
			  struct ipfix_exporter *exp, int verbose,
			  int direction)
{
	struct inner_map_fds new_fds;
	if (create_inner_maps(&new_fds) < 0) {
		fprintf(stderr, "Map creation failed, skipping poll cycle\n");
		return;
	}

	struct inner_map_fds old = *cur;

	if (swap_inner_maps(outer_v4, outer_v6, outer_vni, &new_fds) < 0) {
		fprintf(stderr, "Map swap failed, skipping poll cycle\n");
		close_inner_maps(&new_fds);
		return;
	}

	*cur = new_fds;

	/* RCU grace period: all in-flight XDP/TC programs complete in <1us,
	 * 10ms is extremely conservative. */
	usleep(10000);

	/* Iterate old maps — no BPF program can write to them anymore */
	time_t now = time(NULL);
	struct tm *tm = localtime(&now);
	char timebuf[64];
	strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%S%z", tm);

	int ncpus = libbpf_num_possible_cpus();
	struct counter_val *vals = calloc(ncpus, sizeof(struct counter_val));
	if (!vals) {
		fprintf(stderr, "Failed to allocate per-CPU buffer\n");
		close_inner_maps(&old);
		return;
	}

	if (exp)
		ipfix_send_templates(exp);

	if (direction != DIR_INGRESS) {
		poll_counters_v4(old.v4[0], timebuf, "egress", exp, verbose,
				 vals, ncpus);
		poll_counters_v6(old.v6[0], timebuf, "egress", exp, verbose,
				 vals, ncpus);
	}
	if (direction != DIR_EGRESS) {
		poll_counters_v4(old.v4[1], timebuf, "ingress", exp, verbose,
				 vals, ncpus);
		poll_counters_v6(old.v6[1], timebuf, "ingress", exp, verbose,
				 vals, ncpus);
	}
	poll_vni_counters(old.vni, timebuf, exp, verbose, vals, ncpus);

	if (exp)
		ipfix_flush(exp);

	if (verbose)
		fflush(stdout);

	free(vals);

	/* Close old maps — kernel frees them */
	close_inner_maps(&old);
}

/* --- Attach helpers --- */

static struct bpf_link *attach_xdp(struct bpf_program *prog, int ifindex)
{
	struct bpf_link *link = bpf_program__attach_xdp(prog, ifindex);
	if (!link) {
		fprintf(stderr, "Failed to attach XDP: %s\n", strerror(errno));
		return NULL;
	}
	return link;
}

static int attach_tc(struct bpf_program *prog, int ifindex)
{
	LIBBPF_OPTS(bpf_tc_hook, hook,
		.ifindex = ifindex,
		.attach_point = BPF_TC_EGRESS,
	);
	LIBBPF_OPTS(bpf_tc_opts, opts,
		.prog_fd = bpf_program__fd(prog),
	);

	/* Create clsact qdisc (ignore if exists) */
	bpf_tc_hook_create(&hook);

	if (bpf_tc_attach(&hook, &opts) < 0) {
		fprintf(stderr, "Failed to attach TC egress: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static void detach_tc(int ifindex)
{
	LIBBPF_OPTS(bpf_tc_hook, hook,
		.ifindex = ifindex,
		.attach_point = BPF_TC_EGRESS,
	);
	bpf_tc_hook_destroy(&hook);
}

/* Get IPv4 address of interface as a 32-bit host-order integer for obs_domain_id.
 * Prefers IPv4; falls back to lower 32 bits of first IPv6 address. Returns 0 on failure. */
static __u32 get_iface_ip_as_id(const char *ifname)
{
	struct ifaddrs *ifa_list, *ifa;
	__u32 result = 0;

	if (getifaddrs(&ifa_list) < 0)
		return 0;

	for (ifa = ifa_list; ifa; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr || strcmp(ifa->ifa_name, ifname) != 0)
			continue;
		if (ifa->ifa_addr->sa_family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
			result = ntohl(sin->sin_addr.s_addr);
			break; /* IPv4 found, use it */
		}
		if (ifa->ifa_addr->sa_family == AF_INET6 && result == 0) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
			memcpy(&result, &sin6->sin6_addr.s6_addr[12], 4);
			result = ntohl(result);
			/* keep looking for IPv4 */
		}
	}
	freeifaddrs(ifa_list);
	return result;
}

/* --- Usage --- */

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s -c <config_file> [-v]\n", prog);
	fprintf(stderr, "  -c  config file path\n");
	fprintf(stderr, "  -v  verbose: also print counters to stdout\n");
}

/* --- Main --- */

int main(int argc, char **argv)
{
	const char *config_path = NULL;
	int verbose = 0;
	int opt;

	while ((opt = getopt(argc, argv, "c:vh")) != -1) {
		switch (opt) {
		case 'c':
			config_path = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (!config_path) {
		usage(argv[0]);
		return 1;
	}

	/* Parse config */
	struct app_config cfg = {};
	if (parse_config(config_path, &cfg) < 0)
		return 1;

	int ifindex = if_nametoindex(cfg.ifname);
	if (!ifindex) {
		fprintf(stderr, "Interface '%s' not found\n", cfg.ifname);
		config_free(&cfg);
		return 1;
	}

	/* Open and load BPF object */
	struct bpf_object *obj = bpf_object__open("traffic_account.bpf.o");
	if (!obj) {
		fprintf(stderr, "Failed to open BPF object: %s\n", strerror(errno));
		config_free(&cfg);
		return 1;
	}

	if (bpf_object__load(obj) < 0) {
		fprintf(stderr, "Failed to load BPF object: %s\n", strerror(errno));
		bpf_object__close(obj);
		config_free(&cfg);
		return 1;
	}

	/* Find programs */
	struct bpf_program *xdp_prog = bpf_object__find_program_by_name(obj, "xdp_traffic_account");
	struct bpf_program *tc_prog = bpf_object__find_program_by_name(obj, "tc_traffic_account");
	if (!xdp_prog || !tc_prog) {
		fprintf(stderr, "Failed to find BPF programs\n");
		bpf_object__close(obj);
		config_free(&cfg);
		return 1;
	}

	/* Find static maps (config, LPM, infra) */
	int config_fd = bpf_object__find_map_fd_by_name(obj, "config");
	int regions_fd = bpf_object__find_map_fd_by_name(obj, "dst_region_map");
	int regions6_fd = bpf_object__find_map_fd_by_name(obj, "dst_region_map6");
	int dst_infra_fd = bpf_object__find_map_fd_by_name(obj, "dst_infra_map");
	int dst_infra6_fd = bpf_object__find_map_fd_by_name(obj, "dst_infra_map6");

	if (config_fd < 0 || regions_fd < 0 || regions6_fd < 0 ||
	    dst_infra_fd < 0 || dst_infra6_fd < 0) {
		fprintf(stderr, "Failed to find static BPF maps\n");
		bpf_object__close(obj);
		config_free(&cfg);
		return 1;
	}

	/* Find outer counter maps (ARRAY_OF_MAPS) */
	int outer_v4 = bpf_object__find_map_fd_by_name(obj, "counters_v4");
	int outer_v6 = bpf_object__find_map_fd_by_name(obj, "counters_v6");
	int outer_vni = bpf_object__find_map_fd_by_name(obj, "counters_vni");

	if (outer_v4 < 0 || outer_v6 < 0 || outer_vni < 0) {
		fprintf(stderr, "Failed to find outer counter maps\n");
		bpf_object__close(obj);
		config_free(&cfg);
		return 1;
	}

	/* Get initial inner map fds.
	 * dup() so we can close them independently of libbpf's internal fds. */
	struct inner_map_fds cur = {
		.v4  = { dup(bpf_object__find_map_fd_by_name(obj, "egress_v4")),
			 dup(bpf_object__find_map_fd_by_name(obj, "ingress_v4")) },
		.v6  = { dup(bpf_object__find_map_fd_by_name(obj, "egress_v6")),
			 dup(bpf_object__find_map_fd_by_name(obj, "ingress_v6")) },
		.vni = dup(bpf_object__find_map_fd_by_name(obj, "vni_map")),
	};

	if (cur.v4[0] < 0 || cur.v4[1] < 0 ||
	    cur.v6[0] < 0 || cur.v6[1] < 0 || cur.vni < 0) {
		fprintf(stderr, "Failed to find inner counter maps\n");
		close_inner_maps(&cur);
		bpf_object__close(obj);
		config_free(&cfg);
		return 1;
	}

	/* Populate maps */
	if (populate_config_map(config_fd, &cfg) < 0 ||
	    populate_regions(regions_fd, regions6_fd,
			    cfg.regions, cfg.n_regions) < 0 ||
	    populate_infra(dst_infra_fd, dst_infra6_fd,
			       cfg.infra, cfg.n_infra) < 0) {
		close_inner_maps(&cur);
		bpf_object__close(obj);
		config_free(&cfg);
		return 1;
	}

	/* Attach XDP (ingress) if needed */
	struct bpf_link *xdp_link = NULL;
	if (cfg.direction != DIR_EGRESS) {
		xdp_link = attach_xdp(xdp_prog, ifindex);
		if (!xdp_link) {
			close_inner_maps(&cur);
			bpf_object__close(obj);
			config_free(&cfg);
			return 1;
		}
	}

	/* Attach TC (egress) if needed */
	int tc_attached = 0;
	if (cfg.direction != DIR_INGRESS) {
		if (attach_tc(tc_prog, ifindex) < 0) {
			if (xdp_link)
				bpf_link__destroy(xdp_link);
			close_inner_maps(&cur);
			bpf_object__close(obj);
			config_free(&cfg);
			return 1;
		}
		tc_attached = 1;
	}

	const char *dir_str = cfg.direction == DIR_INGRESS ? "ingress" :
			      cfg.direction == DIR_EGRESS  ? "egress"  : "both";
	printf("Traffic accounting started on %s (VXLAN port %u, VNI %u, poll %ds, "
	       "direction %s)\n",
	       cfg.ifname, cfg.vxlan_port, cfg.vxlan_vni, cfg.poll_interval, dir_str);
	printf("Subnet regions: %d, Infra CIDRs: %d\n",
	       cfg.n_regions, cfg.n_infra);

	/* IPFIX exporter setup */
	struct ipfix_exporter ipfix_exp;
	struct ipfix_exporter *exp_ptr = NULL;

	if (cfg.collector[0] != '\0') {
		__u32 obs_domain_id = get_iface_ip_as_id(cfg.ifname);
		if (!obs_domain_id) {
			fprintf(stderr, "Cannot determine IP of %s for obs_domain_id\n",
				cfg.ifname);
			if (tc_attached) detach_tc(ifindex);
			if (xdp_link) bpf_link__destroy(xdp_link);
			close_inner_maps(&cur);
			bpf_object__close(obj);
			config_free(&cfg);
			return 1;
		}
		if (ipfix_init(&ipfix_exp, cfg.collector, cfg.collector_port,
			       obs_domain_id, cfg.my_region_id) < 0) {
			fprintf(stderr, "Failed to init IPFIX exporter\n");
			if (tc_attached) detach_tc(ifindex);
			if (xdp_link) bpf_link__destroy(xdp_link);
			close_inner_maps(&cur);
			bpf_object__close(obj);
			config_free(&cfg);
			return 1;
		}
		exp_ptr = &ipfix_exp;
		struct in_addr disp = { .s_addr = htonl(obs_domain_id) };
		printf("IPFIX export to %s:%u (obs_domain_id %s = 0x%08x, my_region_id %u)\n",
		       cfg.collector, cfg.collector_port,
		       inet_ntoa(disp), obs_domain_id, cfg.my_region_id);
	} else {
		/* No collector configured, force verbose */
		verbose = 1;
	}

	/* Signal handlers */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGHUP, sighup_handler);

	/* Main polling loop */
	while (running) {
		sleep(cfg.poll_interval);
		if (!running)
			break;
		if (reload_flag) {
			reload_flag = 0;
			/* Flush counters before reload — region IDs may change */
			poll_counters(outer_v4, outer_v6, outer_vni, &cur,
				      exp_ptr, verbose, cfg.direction);
			reload_config(config_path, &cfg, config_fd,
				      regions_fd, regions6_fd,
				      dst_infra_fd, dst_infra6_fd);
		}
		poll_counters(outer_v4, outer_v6, outer_vni, &cur,
			      exp_ptr, verbose, cfg.direction);
	}

	/* Final export of any accumulated counters */
	poll_counters(outer_v4, outer_v6, outer_vni, &cur,
		      exp_ptr, verbose, cfg.direction);

	/* Cleanup */
	printf("\nDetaching and cleaning up...\n");
	if (exp_ptr)
		ipfix_close(exp_ptr);
	if (tc_attached)
		detach_tc(ifindex);
	if (xdp_link)
		bpf_link__destroy(xdp_link);
	close_inner_maps(&cur);
	bpf_object__close(obj);
	config_free(&cfg);

	return 0;
}
