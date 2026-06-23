# OAuth2 Authentication Flow — Deep Dive

> **Documented defense:** How identity verification is enforced for administrative services before a single packet reaches the origin server.

---

## The Problem: Admin Tools Without RBAC

Services like **IT Tools** and **BentoPDF** are designed as single-user or small-team utilities. They ship with:
- No built-in user management
- No session management beyond a browser cookie
- No MFA support
- No brute-force rate limiting

**Attacker scenario:** If the URL leaks (browser history, referrer header, screenshot, phishing), anyone with the link has full access to encode/decode utilities, regex testers, or PDF generators — and in BentoPDF's case, **file upload capabilities**.

### File Upload = Arbitrary Write Risk

BentoPDF accepts user uploads to process them into PDF format. Without upstream authentication:
1. Attacker discovers `https://pdf.service.example`
2. In absence of auth, uploads arbitrary file
3. Depending on backend processing logic, potential for:
   - Denial of service (garbage upload, resource exhaustion)
   - Path traversal if file naming is not sanitized
   - Supply chain risk if the uploaded content triggers external library calls

**Decision:** All file-upload-capable or admin-utility services MUST authenticate via an upstream identity proxy before packet reaches origin.

---

## Architecture: Cloudflare Access as Identity-Aware Proxy

```
┌─────────────────────────────────────────────────────────────────────┐
│                         USER REQUEST                                │
│                          (any device)                               │
└─────────────────────────┬───────────────────────────────────────────┘
                          │  HTTPS to tools.service.example
                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    CLOUDFLARE EDGE (Global)                         │
│                                                                     │
│  Step 1: DNS resolves to Cloudflare anycast IP (not home IP)       │
│                                                                     │
│  Step 2: Cloudflare checks Access Policy:                           │
│          ├─ Is there an Access policy for this hostname? ─→ YES   │
│          ├─ Does the request carry valid CF-Authorization cookie? │
│          │   └─ No → Return 302 to Google OAuth2 consent screen   │
│          │   └─ Yes + expired → Return 302 to re-authenticate      │
│          │   └─ Yes + valid → Continue to Step 3                   │
│                                                                     │
│  Step 3: Inject identity headers into forwarded request:            │
│          CF-Access-Authenticated-User-Email: user@example.com       │
│          CF-Access-Jwt-Assertion: [validated JWT]                 │
│                                                                     │
│  Step 4: Send request via cloudflared tunnel → origin               │
└─────────────────────────────────────────────────────────────────────┘
                          │  (tunnel connection, outbound-initiated)
                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         ORIGIN SERVER B                             │
│                                                                     │
│  cloudflared daemon receives request on Docker network              │
│                                                                     │
│  Injects request to it-tools:80 or bentopdf:80                      │
│  Container sees: request came from cloudflared IP (172.x.x.x)      │
│  Container NEITHER sees: user identity, unless consuming CF header   │
│                                                                     │
│  Optional: configure container to trust CF-Access-Jwt only          │
└─────────────────────────────────────────────────────────────────────┘
```

## Identity Verification: Google OAuth2 + OIDC

Cloudflure Access implements **OpenID Connect (OIDC)** with Google as the identity provider. The sequence per unauthenticated request:

```
1. User -> https://tools.service.example (no valid session)
2. Cloudflare returns 302 to:
   https://accounts.google.com/o/oauth2/v2/auth?
     client_id=[REDACTED]
     &redirect_uri=https://[team-name].cloudflareaccess.com/cdn-cgi/access/callback
     &response_type=code
     &scope=openid%20email%20profile
     &state=[CSRF nonce]
     &nonce=[replay protection]

3. User authenticates with Google (MFA enforced at Google level)
4. Google returns authorization code to Cloudflare callback
5. Cloudflare exchanges code for tokens, validates signature against
   Google public keys (JWKS endpoint)
6. Cloudflare sets encrypted session cookie (CF_Authorization)
7. Redirects user back to original URL
8. Subsequent requests: cookie validated locally (no round-trip to Google)
9. JWT lifetime: 24 hours (configurable)
```

**Security properties:**
- **Confidentiality:** Authorization code is single-use and short-lived.
- **Integrity:** ID token signed by Google RS256; Cloudflare verifies via JWKS.
- **Availability:** Even if Google is down, existing sessions continue (local cookie validation). New logins temporarily blocked.

## Session Continuity and Revocation

| Scenario | Behavior |
|---|---|
| User closes browser | Session cookie persists (HttpOnly, Secure, SameSite=Lax) |
| User clears cookies | Must re-authenticate via Google OAuth2 |
| Admin revokes user in Google Workspace | Next token validation fails at Google; Cloudflare session expires within ~5 min (no explicit revocation in standard OIDC; depends on short session lifetime) |
| Device stolen | Attacker needs unlocked device + browser cookie + no account-level MFA re-prompt at Google. Mitigated by `CF-Access-Authenticated-User-Email` appearing in all origin logs for audit. |

## Why Not Use Service-Native Auth?

| Dimension | Native Auth (None / Basic) | OAuth2 via Cloudflare Access |
|---|---|---|
| Credential storage | Local database or nginx htpasswd | Google's hardened infrastructure |
| MFA support | None (or manual TOTP setup per service) | Enabled at IdP level, covers all services |
| Brute-force resistance | Depends on nginx fail2ban or app logic | Handled by Google + Cloudflare WAF |
| Breach notification | None | Google Security alerts |
| Central revocation | Per-service password change | One click in Google Admin Console |
| Audit trail | Local logs only (if any) | Cloudflare Access audit + Google login audit |

---

## Request Flow Diagram (Happy Path vs. Blocked)

```
                                                            BLOCKED AT EDGE
                                                                  │
Internet                                                      ┌────▼────┐
  User ──▶ GET tools.service.example                      ┌───│ Geo ≠ EU │───▶ 403 Blocked
              │                                             │   └─────────┘
              ▼                                             │
    ┌──────────────────┐                              ┌───▶ Cloudflare WAF
    │  Edge Data Center │                                  │      detects bot
    │  TLS 1.3 terminates │                                  │   ┌────────────┐
    └────────┬──────────┘                                  └───│  Captcha/JS  │──▶ Blocked
             │                                                  │   Challenge  │
    ┌────────▼──────────┐                                      └────────────┘
    │ Access Policy Check │
    │  Cookie valid?     │── Yes ──▶ Continue to origin
    │  Cookie missing?   │
    │  Cookie expired?   │
    └────────┬──────────┘
             │ No
             ▼
    ┌──────────────────┐
    │ 302 Redirect to  │
    │ Google OAuth2    │
    └────────┬──────────┘
             │
             ▼
    ┌──────────────────┐                    ┌──────────────────┐
    │ User authenticates │──── success ──────▶│ CF sets session  │
    │ with Google (MFA)  │                    │ cookie, forwards │
    └──────────────────┘                    │ to origin        │
                                              └────────┬──────────┘
                                                       │
                                          ┌────────────▼────────────┐
                                          │ Origin receives request │
                                          │ with identity headers   │
                                          │ CF-Access-User-Email    │
                                          └─────────────────────────┘
```

---

## Hardening Recommendations (Future States)

| Improvement | Effort | Security Gain |
|---|---|---|
| **Require Google Workspace enrollment** | Low | Device posture check: only corporate-managed devices can authenticate. |
| **Shorten session lifetime to 4h** | Very low | Reduces window of stolen-cookie abuse. |
| **Inject JWT to origin, validate there** | Medium | Prevents bypass if tunnel is misconfigured (`cf-intel` library available). |
| **Add Duo / hardware key step-up** | Medium | Protects against Google account takeover with phishing-resistant MFA. |
| **Separate Access policies by device posture** | Medium | Mobile devices get read-only IT Tools; desktop gets full access. |

