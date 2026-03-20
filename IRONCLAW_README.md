# IronClaw

**A cryptographically verified AI network agent built for secure production environments.**

IronClaw is an autonomous network engineering agent powered by [VIRP](https://github.com/nhowardtli/virp) (Verified Infrastructure Response Protocol) — a cryptographic trust layer that ensures every observation the AI makes is signed at collection time, preventing hallucination and fabrication at the architectural level. Built on the [OpenClaw](https://github.com/openclaw/openclaw) agent framework, IronClaw operates across multi-vendor enterprise networks with full audit trail support.

> VIRP was originally developed at Third Level IT as part of the TLI Ops Center. IronClaw is its reference implementation as an open-source agent.

---

## The Problem

AI network agents are on the honor system. The agent runs a command, reports the output, and you trust it. In a lab, that's fine. In a production network, that's a liability — there's no way to prove what the AI actually saw versus what it inferred, fabricated, or got wrong.

IronClaw solves this. Every observation is cryptographically signed the moment it's captured — before it ever reaches the AI. If the AI can't produce a valid HMAC-signed observation, it cannot make a claim. Evidence-gated by design.

---

## Architecture

IronClaw runs across two isolated containers:

```
┌──────────────────────────────────────────────────┐
│  CT 210 — ironclaw-ai (Python / OpenClaw)        │
│                                                  │
│  Natural language interface                      │
│  Intent routing and tier enforcement             │
│  Cannot fabricate. Cannot bypass.                │
└──────────────────────┬───────────────────────────┘
                       │ socat TCP bridge (port 9999)
┌──────────────────────▼───────────────────────────┐
│  CT 211 — ironclaw-onode (C daemon)              │
│                                                  │
│  HMAC-SHA256 signing at collection time          │
│  Trust tier classification                       │
│  chain.db — SQLite cryptographic audit trail     │
│  age-encrypted devices.json                      │
│  Key isolation (mlock) — AI never sees keys      │
└──────────────────────┬───────────────────────────┘
                       │ SSH
┌──────────────────────▼───────────────────────────┐
│  Network Devices                                 │
│                                                  │
│  Cisco IOS / IOS-XE    │  FortiOS               │
│  PAN-OS                │  Cisco ASA             │
│  Linux / SIEM          │  (more drivers planned) │
└──────────────────────────────────────────────────┘
```

The O-Node is the only component that touches devices. The AI layer never has direct network access to managed infrastructure.

---

## How It Works

```
1. You type:    "Check the FortiGate firewall policies"

2. IronClaw sends an intent to the O-Node (CT 211)

3. O-Node classifies the intent:
   GREEN  — read-only, executes automatically
   YELLOW — potentially impactful, proceeds with logging
   RED    — destructive or config-changing, requires your approval
   BLACK  — blocked outright

4. O-Node SSHes to the device via C executor

5. Raw output is signed with HMAC-SHA256 using a key the AI never sees

6. Signed observation is chained to chain.db (monotonic, tamper-evident)

7. IronClaw receives the signed observation and reasons about it

8. IronClaw reports findings with evidence:
   "Policy 2 allows all traffic with no AV/IPS profile applied"
   HMAC: da383afe...c18 | Chain seq: 1 | Session: 3b579a43

9. If you ask "shut down that interface" — RED tier, held for your approval
```

---

## VIRP Trust Tiers

| Tier | Meaning | Behavior |
|------|---------|----------|
| GREEN | Read-only, safe | Executes automatically |
| YELLOW | Potentially impactful | Executes with full logging |
| RED | Config change or destructive | Requires explicit human approval |
| BLACK | Out of scope or prohibited | Blocked, no execution |

---

## The Cage — Structural Security

IronClaw's security model is structural, not behavioral. Four walls:

- **Wall 1** — CT 210 network isolation (AI has no direct device access)
- **Wall 2** — Device-side ACLs restricting SSH to O-Node IP only
- **Wall 3** — O-Node Unix socket enforcement (agent cannot call O-Node directly)
- **Wall 4** — Landlock kernel-level filesystem sandbox (irreversible, even root cannot undo)

The AI cannot bypass VIRP. The architecture makes it impossible, not just discouraged.

---

## Vendor Coverage

| Platform | Driver | Transport |
|----------|--------|-----------|
| Cisco IOS / IOS-XE | driver_cisco.c | SSH |
| FortiOS | driver_fortigate.c | SSH |
| PAN-OS | driver_panos.c | SSH |
| Cisco ASA | driver_asa.c | SSH (enable mode) |
| Linux / Wazuh | driver_linux.c | SSH |

---

## Production Numbers

Validated on live hardware, not simulations:

- **40 devices** under active management across 5 vendor platforms
- **35-router scale test** — 13 autonomous systems, full BGP mesh, all HMAC-verified in under 60 seconds using 16-thread parallel executor
- **Per-device latency** — 2–4 seconds including SSH, execution, HMAC signing, and chain write
- **FortiGate audit** — 15 real findings, zero false positives
- **15/15 VIRP VERIFIED** end-to-end on FortiGate 200G
- **Zero fabricated findings** — the architecture makes fabrication structurally impossible

---

## VIRP Protocol

IronClaw implements VIRP — a standalone open protocol published separately:

- **GitHub:** [github.com/nhowardtli/virp](https://github.com/nhowardtli/virp)
- **RFC Draft:** draft-howard-virp-01
- **DOI:** Published via Zenodo
- **IETF RATS Working Group:** Submission made March 2026

VIRP defines two channels: **Observation** (what the network said) and **Intent** (what the AI wants to do). These are cryptographically separate. The session handshake (HELLO → HELLO_ACK → SESSION_BIND) converts VIRP from a signing library into a stateful protocol.

---

## The 7 Trust Primitives

| # | Primitive | Status |
|---|-----------|--------|
| 1 | Verified Observation | ✅ Complete |
| 2 | Tiered Authorization | ✅ Complete |
| 3 | Verified Intent | 🔲 Planned |
| 4 | Verified Outcome | 🔲 Planned |
| 5 | Baseline Memory | 🔲 In progress |
| 6 | Trust Chain | 🔲 Planned |
| 7 | Trust Federation | 🔲 Planned |

Build order: 5 → 3 → 4 → 6 → 7

---

## Who This Is For

IronClaw is built for environments where an AI making an unverified claim about a router is a liability, not an annoyance:

- Enterprise network operations centers
- Federal and government agencies
- Critical infrastructure operators
- Financial institutions with strict change control
- Any organization subject to compliance requirements that demands a verifiable audit trail of AI-assisted network operations

This is not a home lab tool. If you don't need to prove what the AI saw, you probably don't need IronClaw.

---

## Credits

IronClaw stands on the shoulders of two projects:

**[OpenClaw](https://github.com/openclaw/openclaw)** by Peter Steinberger — the agent framework, skill system, MCP infrastructure, and gateway that makes natural language infrastructure operations possible.

**[NetClaw](https://github.com/automateyournetwork/netclaw)** by John Capobianco — the CCIE-level networking agent that validated the direction and contributed the foundation of IronClaw's network engineering skill set.

**[VIRP](https://github.com/nhowardtli/virp)** — the Verified Infrastructure Response Protocol. Designed and built by Nate Howard at [Third Level IT LLC](https://thirdlevelit.com). The cryptographic trust framework that makes all of it honest.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

IronClaw is built on [OpenClaw](https://github.com/openclaw/openclaw) (MIT) and [NetClaw](https://github.com/automateyournetwork/netclaw) (Apache 2.0). VIRP is independently licensed Apache 2.0 at [github.com/nhowardtli/virp](https://github.com/nhowardtli/virp).

---

## Status

Active development. Trust primitives 1 and 2 are production-validated. Primitives 3–7 are in the build queue.

For questions, collaboration, or enterprise deployment inquiries: **nhoward@thirdlevelit.com**
