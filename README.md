# VXLAN traffic account

High-performance VXLAN traffic accounting using XDP/eBPF. Accounts packets and bytes per `[source_IP, dst_region_id]` pair by parsing inner (encapsulated) headers. Exports via IPFIX to a remote collector.

## Features

- **XDP ingress** + **TC egress** hooks for minimal overhead at 200 Gbps+
- Per-CPU lock-free counters (no contention across cores)
- Atomic map-swap polling — zero packet loss between read cycles
- LPM trie for efficient subnet-to-region mapping
- **IPv4 and IPv6** inner packet support (separate counter maps)
- **IPv4 and IPv6** outer tunnel support
- Per-VNI total accounting for non-primary VNIs (optional)
- IPFIX export (RFC 7011) with enterprise IEs (PEN 99999)
- Configurable VXLAN port (default 4789)
- Configurable poll interval (default 30s)
- Accounts inner IP payload size (excludes encapsulation overhead)
- Non-VXLAN traffic passes through untouched
- SIGHUP config reload (add/remove subnets without restart)

## Requirements

- Linux kernel 5.10+ (XDP, TC, LPM trie, per-CPU hash maps, array-of-maps)
- clang, llvm-strip (BPF compilation)
- libbpf-dev, libelf-dev, zlib1g-dev (userspace)
- bpftool (optional, for debugging)

## Build

```bash
make
```

Produces:
- `build/traffic_account.bpf.o` — BPF object (XDP + TC programs)
- `build/traffic-account` — userspace daemon

## Configuration

Copy and edit `config.example`:

```ini
[general]
interface   eth0         # network interface to attach to
vxlan_port  4789         # VXLAN UDP destination port
vxlan_vni   100          # primary VNI for per-IP accounting
my_region_id 0x00010101  # this node's location: region_id | (AZ << 16)
poll_interval 30         # counter poll interval in seconds
direction     both       # both, ingress, or egress
collector   10.0.0.100:4739  # IPFIX collector IP[:port] (omit to disable)

# Region sections define destination subnet-to-region mapping.
# [region Continent/Name] — public subnets (inner traffic)
#   id 0xXXYY — continent (XX) + region (YY)
#   Followed by CIDRs, one per line
# [region Continent/Name/N] — infrastructure subnets (per-VNI)
#   dst_region_id auto-calculated as region_id | (N << 16)
#   No id line needed; N comes from section header

[region Europa/FRA]
id 0x0101
192.168.0.0/16
10.10.0.0/16

[region Europa/FRA/1]
10.100.0.0/16

[region US-East/NYC]
id 0x0201
10.0.0.0/8
2001:db8::/32

[region US-East/NYC/1]
10.200.0.0/16
```

## Usage

```bash
# Run as root (required for XDP/TC attachment)
sudo ./build/traffic-account -c config.example [-v]
```

Options:
- `-c <config>` — config file path (required)
- `-v` — verbose: print counters to stdout (auto-enabled when no collector configured)

The BPF object file (`traffic_account.bpf.o`) must be in the working directory.

## Output

### Console (verbose mode)

```
2026-02-12T12:00:00+0000 dir=egress ip=10.0.0.1 region=257 packets=154230 bytes=198456320
2026-02-12T12:00:00+0000 dir=ingress ip=fd00::1 region=513 packets=8420 bytes=12630000
2026-02-12T12:00:00+0000 dir=egress vni=200 dst_region_id=65793 packets=5000 bytes=7500000
```

### IPFIX

Three template types are exported:
- **Template 256** — IPv4 per-region: `sourceIPv4Address`, `dst_region_id`, packets, bytes, direction, `my_region_id` (masked to 0xXXYY)
- **Template 257** — IPv6 per-region: same fields with `sourceIPv6Address`
- **Template 258** — Per-VNI total: VNI, packets, bytes, direction, `my_region_id` (full 32-bit), `dst_region_id`

`obs_domain_id` is auto-derived from the interface IPv4 address (e.g. 10.0.0.1 → 0x0a000001).

Counters are collected via atomic map swap — no packets are lost between poll cycles. A `dst_region_id` of `0xFFFFFFFF` means the destination IP did not match any defined region.

## Architecture

```
Packet path (per-packet, in kernel):
  Outer Eth → Outer IP → UDP (VXLAN port check) → VXLAN hdr → VNI check
    Primary VNI:
      → Inner Eth → Inner IP → extract src_ip, dst_ip
      → LPM trie: dst_ip → dst_region_id
      → ARRAY_OF_MAPS[dir] → PERCPU_HASH[{src_ip, dst_region_id}] += {1, inner_ip_len}
    Non-primary VNI:
      → Outer dst IP → infra LPM → dst_region_id
      → ARRAY_OF_MAPS[0] → PERCPU_HASH[{vni, dst_region_id, dir}] += {1, inner_ip_len}
  → XDP_PASS / TC_ACT_OK (no interference with forwarding)

Userspace (every N seconds):
  create fresh empty inner maps
  → swap into ARRAY_OF_MAPS (atomic, BPF sees new maps immediately)
  → wait 10ms RCU grace period (drain in-flight BPF programs)
  → iterate old maps (read-only, no contention) → sum per-CPU values → export via IPFIX
  → close old maps (kernel frees memory)
```

## License

GPL-2.0
