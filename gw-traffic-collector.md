## High-Performance VXLAN Traffic Accounting — Requirements & Implementation Plan

### Problem Statement

We need a system that sits on a Linux host, intercepts all VXLAN-encapsulated traffic (ingress + egress), and accounts inner-packet bytes/packets per `[source_IP, destination_region]` pair. Results are exported via IPFIX (RFC 7011) to a remote collector every N seconds. Must handle up to **200 Gbps** with minimal CPU overhead.

### Requirements

**Functional:**
1. **Primary VNI accounting** — For a configured VNI, decapsulate VXLAN, parse inner Ethernet/IP, look up inner dst IP (egress) or src IP (ingress) in an LPM trie to get a `dst_region_id`, and increment per-CPU counters keyed on `{src_ip, dst_region_id}`. Account inner IP payload size only (no encap overhead).
2. **Non-primary VNI accounting** — For all other VNIs, account per-VNI totals: `{vni, dst_region_id, direction}` → `{packets, bytes}`. The `dst_region_id` comes from an infrastructure LPM lookup on the **outer** dst IP.
3. **IPv4 + IPv6** — Both inner and outer tunnels. Separate maps for v4/v6 counters.
4. **IPv6 /80 masking** — All IPv6 addresses in the same /80 prefix belong to one host. Copy only 10 bytes into the counter key.
5. **Bidirectional** — XDP for ingress, TC for egress. Configurable to run one or both.
6. **IPFIX export** — Three templates: IPv4 per-region (tmpl 256), IPv6 per-region (257), per-VNI total (258). Enterprise IEs with a private PEN for `dst_region_id` and `my_region_id`. Batch records of the same template into a single data set to minimize overhead. Send templates before data on every poll cycle. `obs_domain_id` auto-derived from interface IP.
7. **Region ID scheme** — `0xXXYY` (continent + region). Infrastructure locations add AZ: `region_id | (AZ << 16)`. In per-region IPFIX records, `my_region_id` is masked to `& 0xFFFF` (strip AZ). Sentinel `0xFFFFFFFF` for unknown regions.
8. **Config format** — INI-style. `[general]` for globals, `[region Continent/Name]` for public subnets with `id 0xXXYY`, `[region Continent/Name/N]` for infra subnets (AZ auto-calculated from N, no id line).

**Non-functional:**
- Target kernel 6.17+, clang 20, libbpf
- `-Wall -Werror` for both BPF and userspace
- Single-threaded userspace daemon (no locking needed for IPFIX buffer)
- Per-CPU hash maps for counters (lock-free in BPF)
- LPM trie with `NO_PREALLOC` for subnets
- Non-VXLAN traffic passes through untouched (`XDP_PASS` / `TC_ACT_OK`)

### Architecture

```
Kernel (per-packet, XDP/TC):
  Outer Eth → Outer IP → UDP port check → VXLAN hdr → VNI check
    Primary VNI → Inner Eth → Inner IP → LPM(dst) → PERCPU_HASH[{src, region}]++
    Other VNI   → get_inner_len → LPM(outer_dst) → PERCPU_HASH[{vni, region, dir}]++
  → XDP_PASS / TC_ACT_OK

Userspace (every N seconds):
  Send IPFIX templates
  Iterate PERCPU_HASH → sum per-CPU → export via IPFIX → delete entry
  Flush IPFIX buffer
```

### Implementation Plan

**Phase 1: Shared headers** (`src/common.h`)
- [ ] Define config map indices (`CFG_VXLAN_PORT`, `CFG_VXLAN_VNI`)
- [ ] Define `DST_REGION_ID_NONE` sentinel (0xFFFFFFFF)
- [ ] Define map size constants
- [ ] Define shared structs: `counter_key`, `counter_key6`, `lpm_key`, `lpm_key6`, `counter_val`, `vni_counter_key`

**Phase 2: BPF program** (`src/bpf/traffic_account.bpf.c`)
- [ ] Declare all BPF maps: config (ARRAY), dst_region_map/6 (LPM_TRIE), traffic_counters/6 + ingress_counters/6 (PERCPU_HASH), vni_counters (PERCPU_HASH), dst_infra_map/6 (LPM_TRIE)
- [ ] Implement `account_inner_v4` — parse inner IPv4, LPM lookup, update egress or ingress counter map
- [ ] Implement `account_inner_v6` — same for IPv6, /80 masking on counter key
- [ ] Implement `account_inner` — dispatch by inner ethertype
- [ ] Implement `get_inner_len` — extract inner IP payload length without full accounting
- [ ] Implement `account_vni_total` — per-VNI counter update
- [ ] Implement `account_packet` — parse outer headers (ETH→IP/IPv6→UDP→VXLAN), check port, extract VNI, dispatch to primary or VNI-total path. For VNI-total, do infra LPM on outer dst IP
- [ ] XDP program (`SEC("xdp")`) calling `account_packet(data, data_end, 1)` → `XDP_PASS`
- [ ] TC program (`SEC("tc")`) calling `account_packet(data, data_end, 0)` → `TC_ACT_OK`

**Phase 3: IPFIX exporter** (`src/user/ipfix.h` + `ipfix.c`)
- [ ] Define IPFIX wire structs (msg header, set header), template IDs, IANA IEs, enterprise IEs with PEN
- [ ] Define `ipfix_exporter` context struct (sockfd, collector addr, seq_number, obs_domain_id, my_region_id)
- [ ] Implement `ipfix_init` — UDP socket via getaddrinfo
- [ ] Implement `ipfix_close`
- [ ] Implement internal buffer management: `buf_reset`, `buf_append`, `put16`/`put32`/`put64` helpers
- [ ] Implement template sending — single template set with all 3 templates
- [ ] Implement data set batching: `data_set_begin`/`data_set_end`, `ensure_data_set` (auto-open/close sets when template changes or buffer full), `close_current_set`
- [ ] Implement `ipfix_export_v4` (29-byte record), `ipfix_export_v6` (41-byte), `ipfix_export_vni` (33-byte) — each calls `ensure_data_set` then appends record
- [ ] Implement `ipfix_flush` — close open set, send message
- [ ] `my_region_id & 0xFFFF` masking in v4/v6 records, full 32-bit in VNI records

**Phase 4: Userspace daemon** (`src/user/main.c`)
- [ ] Config parser: `[general]` (interface, vxlan_port, vxlan_vni, my_region_id with hex support, poll_interval, direction, collector IP[:port])
- [ ] Config parser: `[region Continent/Name]` sections with `id 0xXXYY` + CIDR lines; `[region Continent/Name/N]` for infra (auto-calc dst_region_id = region_id | N<<16)
- [ ] BPF object open/load, find programs and all 10 map fds
- [ ] Map population: config array, region LPM tries, infra LPM tries
- [ ] `get_iface_ip_as_id` — derive obs_domain_id from interface address
- [ ] Counter polling: iterate each PERCPU_HASH, sum per-CPU values, export via IPFIX (or print if verbose), delete entry
- [ ] `poll_counters` orchestrator: send templates, poll egress v4/v6, ingress v4/v6, VNI, flush
- [ ] XDP/TC attach/detach helpers
- [ ] Signal handling (SIGINT/SIGTERM), main loop with sleep, cleanup

**Phase 5: Build & config**
- [ ] Makefile: clang for BPF (`-target bpf`), cc for userspace (`-lbpf -lelf -lz`), `-Wall -Werror`
- [ ] `config.example` with documented sample
- [ ] README.md

### Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| PERCPU_HASH over HASH | Lock-free updates at 200Gbps, sum at read time |
| LPM_TRIE + NO_PREALLOC | Memory-efficient prefix matching, dynamic population |
| Separate egress/ingress counter maps | Avoids adding direction to per-packet key (saves map space) |
| Inner payload size only | Encap overhead is constant, doesn't reflect actual traffic |
| Delete-after-read counters | Keeps map size bounded, acts as delta export |
| Data set batching in IPFIX | Saves 4 bytes/record overhead, fits more in one UDP datagram |
| Static 8K IPFIX buffer | Conservative UDP payload, single-threaded so no contention |
| Templates every poll cycle | Ensures collector can decode after restart, per RFC recommendation |
