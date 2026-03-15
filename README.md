# IronClaw — VIRP Reference Implementation

**Cryptographic trust for AI network operations.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Language: C11](https://img.shields.io/badge/language-C11-blue)]()
[![Protocol: VIRP](https://img.shields.io/badge/protocol-VIRP-green)]()

---

## The Problem

AI agents are starting to manage network infrastructure — routers, firewalls, hypervisors. The problem is **AI fabricates output**.

During development of an AI operations platform, we caught the AI:

- **Fabricating three complete firewall policies** with realistic UUIDs that never existed
- **Inventing fake security alerts** using RFC 5737 documentation IPs as "attackers"
- **Presenting all of it as "Confidence: HIGH"**

HMAC signing on the executor wasn't enough. The AI could still generate plausible-looking data that *felt* real but had zero cryptographic backing. We needed verification at the protocol level.

## The Solution

**VIRP** (Verified Infrastructure Response Protocol) is a cryptographic trust layer that signs every device observation at collection time using HMAC-SHA256, before the AI ever sees it. IronClaw is the reference agent that implements VIRP.

Every claim the AI makes about your network is either **backed by a signed observation** or **flagged as unverified**. There is no middle ground.

## Architecture

```
┌──────────────────────────────────────────────────┐
│                   AI Agent (IronClaw)             │
│         Natural language → structured intent      │
├──────────────────────────────────────────────────┤
│              VIRP Trust Layer (C library)         │
│     HMAC-SHA256 signing · chain.db · trust tiers │
├──────────────────────────────────────────────────┤
│              O-Node (Observation Node)            │
│   SSH to devices · sign at collection · store     │
├────────────┬────────────┬────────────────────────┤
│  Cisco IOS │  FortiGate │  PAN-OS  │  ASA  │ ... │
└────────────┴────────────┴──────────┴───────┴─────┘
```

**Two-channel separation:**
- **Observation Channel** — Read-only. Device output signed with HMAC-SHA256 at collection time. Immutable.
- **Intent Channel** — Write operations. Tiered authorization: GREEN (read) / YELLOW (non-disruptive) / RED (service-affecting) / BLACK (denied).

**Two-container deployment:**
- `ironclaw-ai` — Python/MCP AI layer, natural language processing
- `ironclaw-onode` — C-level O-Node daemon, HMAC signing, chain.db

The AI container cannot reach devices directly. All device communication routes through the O-Node.

## Trust Tiers

| Tier | Authorization | Example |
|------|--------------|---------|
| **GREEN** | Auto-approved | `show ip bgp summary`, `get system status` |
| **YELLOW** | Logged, proceed | `show running-config`, interface stats |
| **RED** | Requires approval | `shutdown`, route changes, ACL modifications |
| **BLACK** | Denied always | `write erase`, factory reset, key deletion |

## Verified Vendors

| Vendor | Driver | Method | Status |
|--------|--------|--------|--------|
| Cisco IOS/IOS-XE | `driver_cisco.c` | SSH (exec channel) | ✅ Production |
| Fortinet FortiOS | `driver_fortigate.c` | SSH (C executor) | ✅ Production |
| Palo Alto PAN-OS | `driver_panos.c` | SSH | ✅ Production |
| Cisco ASA | `driver_asa.c` + `parser_asa.c` | SSH | ✅ Tested |
| Linux | `driver_linux.c` | SSH | ✅ Tested |

## The 7 Trust Primitives

1. **Verified Observation** ✅ — HMAC-signed device output at collection time
2. **Tiered Authorization** ✅ — GREEN/YELLOW/RED/BLACK command classification
3. **Verified Intent** — Structured signed proposals before execution
4. **Verified Outcome** — Automatic post-change observation and diff
5. **Baseline Memory** — Deviation detection from signed history
6. **Trust Chain** — Cryptographic audit trail across all operations
7. **Trust Federation** — Ed25519 multi-tenant trust across organizations

## Quick Start

### Build the C library

```bash
make clean && make CISCO=1 FORTIGATE=1 PANOS=1
```

### Run tests

```bash
make test
```

### Start the O-Node

```bash
./build/virp-onode-prod \
  -k /etc/virp/keys/onode.key \
  -s /tmp/virp-onode.sock \
  -d /etc/virp/devices.json
```

### Device configuration

Copy `devices.example.json` and add your devices:

```json
{
    "devices": [
        {
            "hostname": "core-rtr-1",
            "host": "192.168.1.1",
            "port": 22,
            "vendor": "cisco_ios",
            "username": "virp-agent",
            "password": "your-password",
            "enable": "your-enable",
            "node_id": "01010101"
        }
    ]
}
```

## Repository Structure

```
ironclaw/
├── include/          C headers (virp.h, virp_onode.h, virp_chain.h, ...)
├── src/              C source (O-Node, crypto, chain, drivers)
│   └── drivers/      Vendor-specific SSH drivers
├── tests/            C test suite + Python verification tests
├── api/              Python bridge (server.py, virp_bridge.py, virp_verify.py)
├── implementations/
│   └── go/           Go implementation
├── integrations/
│   ├── prometheus/   VIRP metrics exporter
│   └── netbox/       NetBox device sync (planned)
├── deploy/           systemd service files
├── docs/             VIRP RFC, wire format spec, trust primitives
├── Makefile
└── LICENSE           Apache 2.0
```

## Protocol Specification

The full VIRP protocol specification is in [`docs/VIRP-SPEC-RFC-v2.md`](docs/VIRP-SPEC-RFC-v2.md).

Wire format: [`docs/VIRP-WIRE-FORMAT.md`](docs/VIRP-WIRE-FORMAT.md)

IETF submission: `draft-howard-virp-01` (RATS working group)

DOI: Registered on [Zenodo](https://zenodo.org)

## Scale

Tested against 35 routers across 13 autonomous systems with sub-60 second full-topology analysis using 16-thread batch executor.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

If you find a vulnerability in the cryptographic verification path, **do not open a public issue.** See [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Author

**Nathan M. Howard** — Third Level IT LLC — nhoward@thirdlevelit.com

*Everyone's building AI that talks to infrastructure. Nobody's verifying what it says. We are.*
