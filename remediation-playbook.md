# Remediation Playbook: From Direct Exposure to Zero Trust

> **Objective:** Harden a self-hosted homelab from direct port-forwarding (insecure by default) to a Zero Trust architecture with zero inbound ports, tiered authentication, and geographic restrictions.

---

## Phase 0: Discovery — Characterizing the Problem

### Initial State (Pre-Remediation)

| Service | Exposure | Authentication | IP Restrictions | Risk |
|---|---|---|---|---|
| Komga | Router port forwarded | Basic auth (username/password) | None | Critical |
| Navidrome | Router port forwarded | Basic auth | None | Critical |
| IT Tools | Router port forwarded | **None** (public access if URL known) | None | Critical |
| BentoPDF | Router port forwarded | **None** (file upload visible) | None | Critical |
| Hermes (AI) | LAN only | Basic auth | None (local) | Low |
| n8n | LAN only | Basic auth | None (local) | Low |

**Compounding factors:**
1. Home IP address leaked in DNS A records.
2. Shodan/Censys continuously enumerate residential IPs with common ports (80, 443, 5000-5500, 8000-9000).
3. Docker services bound to `0.0.0.0` inside containers — any lateral compromise = full container access.

### Threat Model

| Actor | Capability | Motivation |
|---|---|---|
| Mass scanner | Automated port sweeps, CVE fingerprinting | Opportunistic compromise |
| Credential stuffing bot | Distributed login attempts (hours to days) | Account takeover |
| Web scraper | Bandwidth abuse, content enumeration | Data theft / resale |
| Targeted attacker | Manual reconnaissance of leaked IP | Targeted intrusion |

---

## Phase 1: Eliminate Inbound Exposure (Days 1–2)

### Step 1.1: Inventory Current Port Forwards

```bash
# On router admin UI, document all forwarded ports
# Common locations: Advanced > NAT / Port Forwarding / Virtual Servers

80    -> Server B : [REDACTED]    # Komga (was exposed directly)
443   -> Server B : [REDACTED]    # Navidrome (was exposed directly)
XXXX  -&gt; Server B : [REDACTED] # IT Tools (was exposed via custom port)
YYYY  -&gt; Server B : [REDACTED] # BentoPDF (was exposed via custom port)
```

**Verification method:**
```bash
# From external VPS (e.g., DigitalOcean, Hetzner)
nmap -p 80,443,XXXX,YYYY [HOME_IP]
# Expected: all shown as OPEN before remediation
```

### Step 1.2: Remove All Port Forwards

| Router Action | Result |
|---|---|
| Delete TCP 80 forwarding rule | Komga no longer reachable from internet |
| Delete TCP 443 forwarding rule | Navidrome no longer reachable from internet |
| Delete custom port XXXX | IT Tools no longer reachable from internet |
| Delete custom port YYYY | BentoPDF no longer reachable from internet |
| Verify UPnP is disabled | Prevents applications from re-opening ports automatically |

### Step 1.3: Confirm Zero Inbound State

```bash
# External verification — run from VPS
nmap -p 1-65535 [HOME_IP]
# Expected result: 0 ports open (filtered or closed for all)
```

**Log entry:**
```
Starting Nmap [version]
Nmap scan report for [HOSTNAME] ([HOME_IP])
All 65535 scanned ports on [HOSTNAME] ([HOME_IP]) are in filtered states

PORT     STATE    SERVICE
...      ...      ...

Nmap done: 1 IP address (1 host up) scanned in [TIME]
```

*If any port is still open, iterate: check router, check UPnP, check ISP-level NAT, check local firewall on Server B.*

---

## Phase 2: Deploy Cloudflare Tunnel (Days 2–4)

### Step 2.1: Install cloudflared

```bash
# Debian / Proxmox host (Server B)
# Install official repository
curl -L https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-archive-keyring.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/cloudflare-archive-keyring.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt-get update && sudo apt-get install cloudflared
```

**Hardening note:** `cloudflared` runs as unprivileged user with no shell access. Only needs outbound HTTPS (TCP 443) to `region1.v2.argotunnel.com` et al.

### Step 2.2: Authenticate Tunnel

```bash
cloudflared tunnel login
# Opens browser OAuth2 flow with Cloudflare account
# Downloads cert.pem to ~/.cloudflared/
# NEVER commit this certificate to git
```

**Privilege separation:** The tunnel uses a scoped token. It cannot list DNS records, cannot modify zone settings, cannot access other tunnels. Only: (a) register this tunnel, (b) report origin reachability.

### Step 2.3: Create and Configure Tunnel

```bash
cloudflared tunnel create homelab-main
# Returns Tunnel UUID + JSON credentials file
# Store credentials in /etc/cloudflared/ (chmod 600)
```

**Conceptual `config.yml` (anonymized hostnames):**
```yaml
# /etc/cloudflared/config.yml
tunnel: [TUNNEL_UUID]
credentials-file: /etc/cloudflared/[TUNNEL_UUID].json

ingress:
  # Public media services — direct tunnel, native auth handles identity
  - hostname: manga.service.example
    service: http://komga:25600
    originRequest:
      noTLSVerify: true  # Internal Docker network, TLS not needed

  - hostname: music.service.example
    service: http://navidrome:4533

  # Admin services — accessed via Cloudflare Access (policies in dashboard)
  - hostname: tools.service.example
    service: http://it-tools:80

  - hostname: pdf.service.example
    service: http://bentopdf:80

  - service: http_status:404  # Default fallthrough
```

**Security considerations:**
- Docker network is internal-only (`docker network create homelab --internal` would be ideal; here standard bridge suffices). No container binds to host `0.0.0.0` for these services.
- HTTP between `cloudflared` and containers is acceptable because: (a) never leaves Docker bridge, (b) Cloudflare edge TLS is unaffected, (c) any container compromise already implies full Docker host access.

### Step 2.4: Systemd Service + DNS Record

```bash
sudo cloudflared service install
sudo systemctl enable --now cloudflared

# In Cloudflare Dashboard > DNS:
# Create CNAME: manga.service.example -> [TUNNEL_UUID].cfargotunnel.com
# Create CNAME: music.service.example -> [TUNNEL_UUID].cfargotunnel.com
# Create CNAME: tools.service.example -> [TUNNEL_UUID].cfargotunnel.com
# Create CNAME: pdf.service.example -> [TUNNEL_UUID].cfargotunnel.com
```

**Observation:** Home IP never appears in DNS. A records for these hostnames point to Cloudflare edge anycast IPs (`104.21.x.x`, `172.67.x.x`), which proxy via tunnel.

### Step 2.5: Verify End-to-End

```bash
# From external machine (not on home network)
curl -I https://manga.service.example
# Expected: 200 OK + Set-Cookie from Komga
# Origin IP in response headers: Cloudflare, NOT home IP
```

---

## Phase 3: Implement Authentication Tiers (Days 4–6)

### Step 3.1: Configure Google OAuth2 in Cloudflare Access

**Zero Trust Dashboard > Access > Authentication:**

| Setting | Value | Rationale |
|---|---|---|
| Provider | Google | Organization already uses Google Workspace; no additional credential store needed. |
| Client ID | Generated in Google Cloud Console | Scoped to "Sign in with Google" only. |
| Client Secret | Stored in Cloudflare encrypted vault | Never exposed to local infrastructure. |
| Scopes | `openid email profile` | Minimal scope; no Google Drive / Calendar / Gmail access requested. |

### Step 3.2: Build Access Groups

**Group 1: `admin-users`**
```
Include: Emails ending in @example.com (or specific addresses)
Require: Login succeeded with Google OAuth2
```

**Group 2: `media-consumers`** (implicit — no Access policy for these)
```
No Access policy = direct tunnel passthrough
Identity verification delegated to service-native auth
```

### Step 3.3: Assign Policies per Hostname

| Public Hostname | Access Policy | Group | Auth Method |
|---|---|---|---|
| `manga.service.example` | None | All | Native Komga basic auth |
| `music.service.example` | None | All | Native Navidrome basic auth |
| `tools.service.example` | **Require** `admin-users` | `admin-users` | Google OAuth2 |
| `pdf.service.example` | **Require** `admin-users` | `admin-users` | Google OAuth2 |

### Step 3.4: Verify Authentication Split

```bash
# Media service — direct, native auth prompt
curl -I https://manga.service.example
# Expected: 200 OK, no redirect to Google

# Admin service — blocked, redirected to IdP
curl -I https://tools.service.example
# Expected: 302 Redirect to Google OAuth2 consent screen

# After successful OAuth2 login, request proceeds to origin
```

---

## Phase 4: Deploy Edge Security (Days 6–7)

### Step 4.1: Enable WAF + Bot Fight Mode

| Rule | Action | Condition |
|---|---|---|
| Bot Fight Mode | Managed Challenge | Detected automated user-agent |
| Security Level | Medium | Threat score >= 10 triggers challenge |
| Super Bot Fight Mode | Block | Verified bots (unless category allowed) |

**Result observed:** Within 24 hours, Cloudflare analytics showed ~200 challenges issued, majority from non-EU ASNs.

### Step 4.2: Geographic Firewall

| Setting | Value | Traffic Impact |
|---|---|---|
| Default rule | Block | All non-EU IP ranges |
| Challenge rule | Managed Challenge | ASNs with suspicious reputation even in EU |
| Bypass | None | Travel outside EU = use Tailscale |

**Result:** Non-EU traffic dropped to ~0 accept rate. Previously, `komga` access logs (via tunnel) showed daily scan probes from US, CN, RU, BR ASNs. Post-geofilter: zero.

### Step 4.3: Rate Limiting

| Rule | Threshold | Action |
|---|---|---|
| Per-IP general | > 100 req / 10 min | Block 10 min |
| Per-IP login path | > 10 POST /login / 1 min | Block 60 min |
| Endpoint-specific (Komma API) | > 200 req / 5 min | JS Challenge |

---

## Phase 5: Deploy Tailscale as Fallback (Days 7–8)

### Step 5.1: Install on Server B

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up --advertise-routes=192.168.1.0/24 --accept-dns
```

`--advertise-routes` makes Server B a subnet router: any Tailscale client can reach the entire LAN, not just the Tailscale host itself.

### Step 5.2: ACL Policy (Tailscale Admin Console)

```json
{
  "groups": {
    "group:admins": ["user1@example.com", "user2@example.com"]
  },
  "tagOwners": {
    "tag:admin-device": ["group:admins"],
    "tag:proxmox-host": ["group:admins"]
  },
  "acls": [
    {
      "action": "accept",
      "src": ["tag:admin-device"],
      "dst": ["tag:proxmox-host:22,80,443", "tag:proxmox-host:4533,25600"]
    },
    {
      "action": "accept",
      "src": ["group:admins"],
      "dst": ["192.168.1.0/24:*"]
    }
  ],
  "ssh": [
    {
      "action": "check",
      "src": ["tag:admin-device"],
      "dst": ["tag:proxmox-host"],
      "users": ["root", "auto"]
    }
  ]
}
```

**Principle enforced:** Even a compromised Tailscale-joined device cannot access services it is not explicitly tagged for. Default posture is DENY ALL.

### Step 5.3: Install Tailscale on Admin Devices

- iPhone: App Store, connect with same Google account.
- macBook: `brew install tailscale`, authenticate, tagged as `admin-device`.
- Verification: Disable WiFi, connect via cellular, open Safari to `http://192.168.1.x:4533` → music loads via WireGuard tunnel.

---

## Phase 6: Audit and Continuous Improvement

### Weekly Review Checklist

- [ ] Cloudflare Security Events: any bypassed threats?
- [ ] Tailscale audit logs: new device authorizations?
- [ ] Access policy exceptions: any expired grants?
- [ ] Service update status: Komga, Navidrome, Portainer — any CVEs?

### Incident Identified Post-Deployment

A suspicious `curl -A "Mozilla/..."` from a non-EU residential IP was observed attempting `POST /api/...` to `tools.service.example`. It was blocked at the WAF layer (geo-rule) before ever touching the Access policy or the origin. **Zero packets reached Server B.**

---

## Summary of Transformed Risk Posture

| Metric | Before | After |
|---|---|---|
| Open inbound ports | 4+ (forwarded) | **0** |
| Exposure of home IP in DNS | Yes (A record) | **No** (CNAME to edge) |
| Authentication on admin tools | None | **OAuth2 + identity provider MFA** |
| Geographic attack surface | Global (any IP) | **EU only** |
| Bot/scraper mitigation | None | **WAF + Bot Fight + managed challenge** |
| Redundant remote access | None (single path) | **Primary (Cloudflare) + fallback (Tailscale)** |
| Origin log noise | Thousands of scan hits/day | **Near-zero** (filtered at edge) |
| Audit trail per request | None (direct logs only) | **Cloudflare Access logs + Tailscale flow logs** |

---

## Phase 7: Remaining Risks (Acknowledged)

### 7.1. Lateral Movement Within the LAN

**Residual risk:** All hosts currently share a flat L2/L3 network. A compromise of any node enables reconnaissance of the entire subnet.

| Scenario | Impact | Why Not Fixed Yet |
|---|---|---|
| Server A (Windows) compromised → probes Server B | Attacker discovers Debian host, enumerates SSH / Docker / Tailscale | Flat LAN has no VLAN segmentation |
| Container escape on Server B → host root | Attacker can egress back to Cloudflare tunnel, pivot to LAN, scan Server A SMB | Docker default bridge still allows container↔container on same bridge |
| Tailscale subnet router exploited | ACL misconfiguration or stolen device key grants entire LAN access | Subnet route is broad (`192.168.1.0/24`); micro-segmentation would restrict to `/32` per target |

**Planned remediations:**
- **VLAN segmentation:** Separate DMZ (Server B + Docker), LAN (Server A + PCs), MGMT (router/switch admin). Inter-VLAN routing via ACLs, not implicit.
- **Per-service Docker networks:** Replace default bridge with `docker network create [service]` per app, eliminating implicit container reachability.
- **Host firewalls (`ufw` / Windows Defender):** Default-deny all incoming from LAN except explicitly required flows (Tailscale UDP, cloudflared TCP 443). Log and alert on denied attempts.

### 7.2. VLAN Isolation (Hardware Dependency)

Current infrastructure uses a consumer router without 802.1Q support. Full VLAN isolation requires hardware swap. The plan is scoped but pending procurement:

```
Target VLAN Topology:
─────────────────────────────────────────────────────────────────────
VLAN 10  MGMT     │ Router, Switch, Tailscale subnet router
VLAN 20  DMZ      │ Server B, Docker host, all publicly tunneled services
VLAN 30  INTERNAL │ Server A, personal devices, printers
VLAN 99  IOT      │ Smart home devices, guest SSID
─────────────────────────────────────────────────────────────────────
ROUTER ACLS:
  DMZ → INTERNAL : DENY  (except explicit admin flows)
  DMZ → INTERNET : ALLOW  (cloudflared outbound)
  INTERNAL → DMZ : ALLOW  (admin access Portainer)
  ANY → MGMT : DENY  (except from VLAN 30 + admin device MAC whitelist)
```

**Hardware candidates:** MikroTik hEX / RB4011 (budget); Ubiquiti Dream Machine Pro (unified stack); self-build OPNsense box (full control).

### 7.3. Detection Gaps

| Gap | Impact | Current Status |
|---|---|---|
| No SIEM or centralized log collector | Cannot correlate events across hosts (Windows event + Docker logs + router syslog) | ⏳ Not deployed |
| No ARP spoofing / rogue device detection | Attacker on LAN could poison ARP cache or introduce new MAC undetected | ⏳ Not deployed |
| No anomaly-based IDS | Blind to internal lateral movement (e.g., unusual SSH from Server A to Server B at 3 AM) | ⏳ Not deployed |

---

## Phase 8: Trigger Conditions for Next Phase

The remaining risks are **accepted for a personal/family homelab** under these conditions:
1. No PII of non-household users at rest.
2. No SLA or revenue impact from downtime.
3. RTO is measured in hours (container restore), not minutes.

**Automatic triggers to deploy VLAN + micro-segmentation:**
- Any evidence of lateral movement in existing logs.
- Addition of services storing credentials / financial / health data.
- Acquisition of managed switch from decommission (zero-cost migration path).


