# Architecture Decision Record (ADR) — Scan Worker Sandboxing & Isolation

**Status:** ACCEPTED  
**Date:** 2026-09-06  
**Deciders:** Core Engineering & Security Architecture  
**Context:** Roadmap §C.2 (§5: Worker Sandboxing Decision)

---

## 1. Context & Threat Model

PLIŌRA Threat Monitor scan workers execute continuous attack-surface reconnaissance across discovered subdomains, root domains, and open ports. In addition to HTTP probes, workers make raw TCP connections (`safeTcpConnect` from Wave 3) and DNS queries.

### Threat Vectors Considered
1. **SSRF / Lateral Movement**: An attacker crafting malicious DNS responses (e.g. DNS rebinding) to cause scan workers to probe internal cluster services or cloud instance metadata (`169.254.169.254`).
2. **Egress Abuse**: Compromised worker code or upstream library vulnerabilities utilized to launch outbound attacks or pivot across internal infrastructure.
3. **Container Escape**: Vulnerabilities in network parser libraries or kernel primitives allowing container breakout to the host system.

---

## 2. Decision: Container-Level Network Policy (Layer 4 Hardening)

For the current growth stage (beta through 500 organizations), PLIŌRA adopts **hardened, unprivileged container isolation with Kubernetes/Docker network egress policies**, rather than deploying heavy microVM (Firecracker) infrastructure immediately.

### Enforced Controls in Production:
1. **Zero Inbound Attack Surface**:
   - Scan worker containers run in worker-pull mode via Redis/BullMQ.
   - Zero inbound listening ports (`EXPOSE` is disabled, firewall blocks all inbound traffic).
2. **Pre-Flight DNS Pinning & Anti-SSRF Socket Layer**:
   - Every outbound connection invokes `assertSafeTargetHostname()` and `resolveAndPinTarget()`.
   - Outbound requests to IPv4/IPv6 loopback (`127.0.0.0/8`, `::1`), RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and AWS/GCP/Azure link-local metadata (`169.254.169.254`) are terminated immediately at socket creation.
3. **Non-Root Execution**:
   - Container filesystem is mounted read-only with a temporary `/tmp` tmpfs.
   - Processes execute under unprivileged UID `10001:10001` with `drop: ['ALL']` capabilities.
4. **Internal Service Egress Restriction**:
   - In production Kubernetes clusters, a `NetworkPolicy` isolates scan worker pods from reaching internal database pods directly, restricting egress strictly to the Redis queue port and public WAN (0.0.0.0/0 minus private CIDRs).

---

## 3. Explicit Revisit Trigger for MicroVMs (Firecracker / gVisor)

We will formally revisit and transition to microVM-based execution under either of the following conditions:

1. **Scale Trigger**: Platform reaches **500 active monitored customer organizations** (or >10,000 daily scans).
2. **Capability Trigger**: Introduction of **dynamic user-supplied scripts**, **headless browser JavaScript execution** (e.g. Chromium / Puppeteer for DOM-based XSS or screenshotting), or **active authenticated fuzzing**.

Until either trigger is met, the current container isolation provides defense-in-depth without the operational overhead and cold-start latency of microVM pooling.
