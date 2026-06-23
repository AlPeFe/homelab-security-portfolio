# Homelab Security Architecture Portfolio

> **Security-first self-hosted infrastructure** — Zero open ports, defense in depth, and principle of least privilege applied to a real-world homelab environment.

[Live Diagram](https://alpefe.github.io/homelab-security-portfolio/) · [Remediation Playbook](remediation-playbook.md) · [OAuth2 Deep Dive](oauth2-deep-dive.md)

---

## Executive Summary

This repository documents the security architecture of my personal homelab infrastructure. The primary threat model is **exposure of self-hosted services to the public internet** while maintaining usability and access control for legitimate users. All remediation decisions follow the principle of **defense in depth**: no single point of failure should compromise the entire stack.

Key security principles implemented:
- **Zero inbound open ports** — Public services are exposed exclusively via Cloudflare Tunnel reverse proxy.
- **Segmented network architecture** — Windows and Linux workloads are isolated across different physical/VM hosts.
- **Authentication tiering** — OAuth2 for sensitive admin tools, native auth for public media services.
- **Geographic access restrictions** — Traffic filtering at the edge to reduce attack surface.
- **Mesh VPN for emergency access** — Tailscale provides direct LAN access without punching holes in the firewall.

---

## Table of Contents

1. [Network Topology & Segmentation](#1-network-topology--segmentation)
2. [Threat Analysis: Initial Risks](#2-threat-analysis-initial-risks)
3. [Remediation Strategy](#3-remediation-strategy)
4. [Cloudflare Tunnel: Zero Trust Ingress](#4-cloudflare-tunnel-zero-trust-ingress)
5. [Access Control Matrix](#5-access-control-matrix)
6. [Tailscale: Emergency Mesh VPN](#6-tailscale-emergency-mesh-vpn)
7. [Cloudflare Zero Trust Rules](#7-cloudflare-zero-trust-rules)
8. [Lessons Learned](#8-lessons-learned)

---

## 1. Network Topology & Segmentation

The homelab is built on two logically separated nodes to reduce blast radius in case of host compromise.

```
┌─────────────────────────────────────────────────────────────────────┐
│                         HOME NETWORK                                │
├─────────────────────────────┬───────────────────────────────────────┤
│                             │                                       │
│   ┌─────────────────┐      │     ┌─────────────────────────┐       │
│   │   SERVER A      │      │     │    SERVER B             │       │
│   │   (Windows)     │      │     │    (Proxmox / Debian)   │       │
│   │                 │      │     │                         │       │
│   │  • Hermes        │      │     │  • Portainer            │       │
│   │  • n8n           │      │     │  • Komga                │       │
│   │                 │      │     │  • Navidrome            │       │
│   └─────────────────┘      │     │  • IT Tools             │       │
│                             │     │  • BentoPDF             │       │
│    Automation & AI Layer   │     └─────────────────────────┘       │
│                             │              Media & Tools Layer       │
│                             │                                       │
└─────────────────────────────┴───────────────────────────────────────┘
```

**Rationale for segmentation:**

| Segmentation Dimension | Server A (Windows) | Server B (Proxmox) |
|---|---|---|
| **Operating System** | Windows 10 | Debian (Proxmox VE) |
| **Primary Role** | Automation, AI orchestration | Media hosting, utility services |
| **Containerization** | WSL2 + direct host processes | Docker via Portainer |
| **Public Exposure** | None directly | Via Cloudflare Tunnel only |
| **Privilege Model** | Local admin + service accounts | Docker socket isolation |

*Both servers live on the same LAN subnet but serve fundamentally different trust boundaries.*

---

## 2. Threat Analysis: Initial Risks

Before remediation, the infrastructure had the following critical vulnerabilities:

| Risk ID | Threat | Attack Vector | Severity |
|---|---|---|---|
| **R1** | Direct exposure of Docker services via port-forwarding | Mass scanning, CVE exploitation on Komga/Navidrome/etc. | **Critical** |
| **R2** | No centralized authentication on admin tools | Anyone with the URL could access IT Tools or BentoPDF | **High** |
| **R3** | Global accessibility = global attack surface | Brute-force, bot scraping, credential stuffing from any IP worldwide | **High** |
| **R4** | Single point of network access failure | If Cloudflare had an outage or tunnel broke, no remote access possible | **Medium** |
| **R5** | Unrestricted scraper / bot access to public media services | Bandwidth abuse, content enumeration, potential DDoS | **Medium** |

---

## 3. Remediation Strategy

### 3.1. Decision Matrix: Authentication Model

| Service | Sensitivity | Auth Model | Reasoning |
|---|---|---|---|
| **Komga** | Low (read-only media library) | Native basic auth | Publicly shareable; built-in auth sufficient |
| **Navidrome** | Low (music streaming) | Native basic auth | Same as above; Streamsonic API already requires auth |
| **IT Tools** | **High** (sysadmin utilities, encoders, generators) | **OAuth2 via Google** | Admin-tier capabilities; no native RBAC |
| **BentoPDF** | **High** (file upload / PDF processing) | **OAuth2 via Google** | File upload vector = code execution risk |

*Services with write/admin capabilities or file-processing pipelines receive identity federation. Read-only media consumers do not.*

### 3.2. Remediation Steps (Chronological)

```
PHASE 1 — REMOVE DIRECT EXPOSURE
├─ 1.1  Disable all router port-forwarding (80/443, custom service ports)
├─ 1.2  Verify via external port scanner (nmap from VPS) that no ports are open
└─ 1.3  Document baseline: "Zero inbound ports confirmed"

PHASE 2 — DEPLOY CLOUDFLARE TUNNEL
├─ 2.1  Install cloudflared daemon on Server B (Proxmox host, Debian)
├─ 2.2  Authenticate tunnel to Cloudflare account via one-time token
├─ 2.3  Configure local ingress rules: map public hostname → local Docker service:port
├─ 2.4  Verify: curl from internet hits Cloudflare edge, then tunnel, then local container
└─ 2.5  Confirm no port forwarding required at router level

PHASE 3 — CONFIGURE AUTHENTICATION TIERS
├─ 3.1  In Cloudflare Zero Trust Dashboard, enable "Cloudflare Access"
├─ 3.2  Create External Identity Provider → Google OAuth2
├─ 3.3  Build Access Groups:
│       ├─ "Media Consumers" → no restriction (Komga, Navidrome direct)
│       └─ "Admins" → Google OAuth2 challenge (IT Tools, BentoPDF)
├─ 3.4  Assign policies per public hostname
└─ 3.5  Test: unauthenticated user hitting admin service → blocked with Google login prompt

PHASE 4 — IMPLEMENT EDGE SECURITY FILTERS
├─ 4.1  Cloudflare WAF → Block known bad bots, scrapers, crawlers
├─ 4.2  Country firewall → Whitelist EU IPs only (geographic restriction)
├─ 4.3  Rate limiting → Throttle requests per IP to prevent enumeration
└─ 4.4  Bot Fight Mode → Managed challenge for automated traffic

PHASE 5 — DEPLOY MESH VPN FALLBACK
├─ 5.1  Install Tailscale on Server B (Proxmox Debian host)
├─ 5.2  Generate ACL policy: tag-based grants for admin devices only
├─ 5.3  Configure Tailscale as "subnet router" for entire LAN access
├─ 5.4  Test: mobile client on cellular → Tailscale tunnel → direct HTTP to local services
└─ 5.5  Verify traffic never touches public ingress when on VPN

PHASE 6 — AUDIT & HARDEN
├─ 6.1  Review Cloudflare Access logs: identify any blocked brute-force attempts
├─ 6.2  Enable notification alerts for new device authorizations in Tailscale
└─ 6.3  Quarterly review of Access Groups and ACL grants
```

---

## 4. Cloudflare Tunnel: Zero Trust Ingress

**Architecture principle:** All public-facing traffic terminates at Cloudflare's edge network. There are **zero open inbound ports** on the home router.

```
Internet User ──> Cloudflare Edge (TLS 1.3) ──> cloudflared daemon ──> Docker container
                         │                              │
                         ├─ WAF Rules                   └── Runs on Server B (Debian)
                         ├─ Bot Fight Mode
                         ├─ Geo-blocking (EU only)
                         └─ OAuth2 challenge (admin services)
```

**Why this beats port-forwarding:**
- **No public IP exposure** — Home IP never appears in DNS A records (Cloudflare anonymizes it).
- **DDoS mitigation by default** — Traffic absorbed at Cloudflare edge before reaching the tunnel.
- **Certificate management automated** — Cloudflare handles TLS termination; no Let's Encrypt or self-signed certs needed locally.
- **Audit trail** — Every request logged in Cloudflare dashboard with user identity (when OAuth2 enforced).

**Tunnel ingress configuration (anonymized):**
```yaml
# /etc/cloudflared/config.yml — conceptual representation
# Public hostname → local Docker service mapping

- hostname: media.service.example
  service: http://komga:25600
  # No Access policy → direct native auth

- hostname: music.service.example
  service: http://navidrome:4533
  # No Access policy → direct native auth

- hostname: admin-tools.service.example
  service: http://it-tools:80
  # Cloudflare Access applies here → Google OAuth2 required

- hostname: pdf.service.example
  service: http://bentopdf:80
  # Cloudflare Access applies here → Google OAuth2 required
```

---

## 5. Access Control Matrix

| Service | URL Path | OAuth2 Required | Native Auth | Audience |
|---|---|:---|:---|:---|
| Komga | `manga.example.com` | ❌ | ✅ Basic Auth | Media consumers |
| Navidrome | `music.example.com` | ❌ | ✅ Basic Auth | Media consumers |
| IT Tools | `tools.example.com` | ✅ Google | ❌ (OAuth replaces) | Admin only |
| BentoPDF | `pdf.example.com` | ✅ Google | ❌ (OAuth replaces) | Admin only |

*The split-auth model reduces cognitive overhead for users (no unnecessary login) while enforcing strong identity verification for anything that can modify state or process files.*

---

## 6. Tailscale: Emergency Mesh VPN

**Use case:** Cloudflare Tunnel is the primary remote access path. Tailscale exists as a **redundant, lower-latency fallback** with these properties:

| Property | Cloudflare Tunnel | Tailscale |
|---|---|---|
| **Path** | Public internet → edge → tunnel | P2P WireGuard mesh or relay |
| **DNS** | Cloudflare-managed public hostname | MagicDNS (`*.tailnet-name.ts.net`) |
| **Auth** | OAuth2 per request | Device key + Tailscale ACL grants |
| **Granularity** | Per-service policies | Per-device, per-tag network ACLs |
| **Best for** | Public sharing, web apps | Admin SSH, emergencies, mobile streaming |

**Tailscale ACL (conceptual):**
```json
{
  "acls": [
    {
      "action": "accept",
      "src": ["tag:admin-devices"],
      "dst": ["tag:proxmox-server:80,443,22", "tag:proxmox-server:4533,25600"]
    }
  ],
  "tagOwners": {
    "tag:admin-devices": ["admin-user@example.com"],
    "tag:proxmox-server": ["admin-user@example.com"]
  }
}
```

**Grants model:** Devices must be explicitly tagged. Untagged devices have zero network access. Granular port rules mean even a compromised admin mobile device cannot SSH to the host unless explicitly authorized.

---

## 7. Cloudflare Zero Trust Rules

### 7.1. Bot / Scraper Mitigation

| Rule | Action | Trigger |
|---|---|---|
| Managed Challenge | Managed Challenge | Threat score ≥ 10 |
| Block Scanners | Block | User-Agent contains known scanner signatures |
| Rate Limit | Temp block | > 100 requests / 10 min from same IP |

### 7.2. Geographic Restriction

- **Policy:** Allow only requests originating from European IP ranges.
- **Rationale:** All legitimate users are based in the EU. Traffic from non-EU regions represents 100% of automated scanning and brute-force noise in logs.
- **Bypass:** None. Tailscale exists for legitimate travel outside the EU.

### 7.3. Request Flow Diagram

```
Internet Request
       │
       ▼
┌──────────────────┐
│  Cloudflare Edge │
└────────┬─────────┘
         │
    ┌────┴────┬─────────────┬──────────────┐
    ▼         ▼             ▼              ▼
 EU IP?   Bot/Scraper?   OAuth2 needed?   Rate limit?
  Yes        No            Service check   Under cap
    │         │              │               │
    ▼         ▼              ▼               ▼
  ALLOW   Continue    ┌─────────┐      Continue
              │       │ Komga   │         │
              ▼       │ Navid.  │         ▼
         ┌─────────┐  └─────────┘    ┌──────────┐
         │ Google  │←── No           │  BLOCK   │
         │  OAuth2 │                  └──────────┘
         └────┬────┘
              │
         ┌────┴────┐
         │ IT Tools│
         │BentoPDF │
         └─────────┘
```

---

## 8. Lessons Learned

| Lesson | Detail |
|---|---|
| **Native auth is not enough for admin tools** | Tools like IT Tools and BentoPDF have no RBAC. Relying on "security through obscurity" (unpublished URL) failed — any leaked URL or referrer exposure grants full access. |
| **Geographic filtering is surprisingly effective** | Post-implementation log review showed >90% of blocked traffic originated from non-EU IPs. This single rule eliminated the majority of scanning noise. |
| **Redundancy matters** | During a Cloudflare edge incident in my region, Tailscale provided uninterrupted access. A single-path architecture would have left all services unreachable. |
| **Split-auth reduces friction** | Media consumers (friends, family) were confused by OAuth2. Keeping direct native auth for Komga/Navidrome while enforcing OAuth2 for admin tools was the correct UX/security balance. |

---

## Technical Artifacts

All configuration files, diagrams, and documentation in this repository are **anonymized** — no real hostnames, IPs, ports, tokens, or account identifiers are exposed. This is itself a security practice: a public portfolio should never leak operational details that could aid reconnaissance.

---

*Author: [Redacted] · Homelab Security Portfolio · 2026*
