using System.Text.Json;

namespace TruthGate_Web.Utils
{
    public static class TgpTemplates
    {
        private const string RedirectDoc = "QmRAy95PUSX58yNRLh5grYuz3x5JLwmF4UqJnBtQeqZK4u";

        // Optional: call IndexHtml("https://truthgate.io")
        // If null (default), it always uses dweb.link.
        public static string IndexHtml(string? overrideBaseUrl = null) => $@"<!doctype html>
<meta charset=""utf-8"">
<meta name=""viewport"" content=""width=device-width, initial-scale=1"">
<title>Resolving…</title>
<style>
  html,body {{ height:100%; margin:0; background:#0b0b0b; color:#ddd; font:14px/1.4 system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, sans-serif; }}
  .wrap {{ position:fixed; inset:0; display:grid; place-items:center; }}
  .msg {{ opacity:.85; letter-spacing:.2px; }}
  iframe {{ position:fixed; inset:0; width:100vw; height:100vh; border:0; }}
  .sr-only {{ position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden; clip:rect(0,0,0,0); white-space:nowrap; border:0; }}
</style>
<script>
(async () => {{
  const OVERRIDE = {(overrideBaseUrl is null ? "null" : $"'{overrideBaseUrl.Replace("'", "\\'")}'")};

  const params = new URLSearchParams({{
    autoadapt: '0',
    requiresorigin: '1',
    web3domain: '0',
    immediatecontinue: '1',
    magiclibraryconfirmation: '0',
    resolveweb3domain: '0'
  }});

  // 1) Locate tgp.json (root → same dir → relative)
  const origin = location.origin;
  const path = location.pathname;
  const baseDir = path.endsWith('/') ? path : path.slice(0, path.lastIndexOf('/') + 1);
  const candidates = [
    origin + '/tgp.json',
    origin + baseDir + 'tgp.json',
    'tgp.json'
  ];

  let meta = null;
  for (const url of candidates) {{
    try {{
      const res = await fetch(url, {{ cache: 'no-store' }});
      if (!res.ok) continue;
      const m = await res.json();
      if (m && m.current) {{ meta = m; break; }}
    }} catch {{ /* continue */ }}
  }}
  if (!meta || !meta.current) {{
    document.body.innerHTML = '<div class=""wrap""><div class=""msg"">Failed to resolve pointer.</div></div>';
    return;
  }}

  const current = meta.current.startsWith('/ipfs/')
    ? meta.current.slice(6)
    : meta.current;

  const buildDweb = (cid) =>
    `https://dweb.link/ipfs/{RedirectDoc}?redirectURL=${{encodeURIComponent(cid)}}&${{params.toString()}}`;

  const trimSlash = (s) => s.replace(/\/+$/,'');
  const buildOverride = (base, cid) =>
    `${{trimSlash(base)}}/index.html?redirectURL=${{encodeURIComponent(cid)}}&${{params.toString()}}`;

  // 2) Decide which URL to iframe
  let src = buildDweb(current);

  if (OVERRIDE) {{
    try {{
      // NOTE: requires CORS enabled on the override host for this HEAD to be readable (Access-Control-Allow-Origin: *).
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 2500); // quick failover
      const head = await fetch(`${{trimSlash(OVERRIDE)}}/index.html`, {{
        method: 'HEAD',
        mode: 'cors',
        cache: 'no-store',
        signal: ctrl.signal
      }});
      clearTimeout(t);
      if (head && head.ok) {{
        src = buildOverride(OVERRIDE, current);
      }}
    }} catch {{
      // swallow and keep dweb
    }}
  }}

  // 3) Render the iframe full-screen
  const iframe = document.createElement('iframe');
  iframe.src = src;
  iframe.referrerPolicy = 'no-referrer';
  iframe.setAttribute('loading', 'eager');
  // Minimal sandbox; expand if you need forms/downloads inside the iframe.
  iframe.setAttribute('sandbox', 'allow-scripts allow-same-origin');
  document.body.innerHTML = '';
  document.body.appendChild(iframe);
}})();
</script>
<noscript>
  <div class=""wrap""><div class=""msg"">JavaScript is required to resolve the latest content.</div></div>
</noscript>
<body>
  <div class=""wrap""><div class=""msg"">Resolving latest…</div></div>
</body>";


        public static string TgpJson(string currentCid) =>
            JsonSerializer.Serialize(new
            {
                tgp = 1,
                ts = DateTimeOffset.UtcNow.ToString("o"),
                current = currentCid,
                legal = "/legal.md"
            }, new JsonSerializerOptions { WriteIndented = true });

        public static string LegalMd(string domain) =>
    $@"# TruthGate Pointer Legal Notice & License (TGP-LN v1.0)

**Last Updated:** 2025-08-17
**Applies To:** Any IPNS name that publishes a `/tgp.json` file per the TruthGate Pointer (TGP) protocol v1.
**Purpose:** To clarify that this IPNS name acts as a *pointer* to the current CID only; it is not an index, archive, or host of prior content.

---

## 1) Definitions

* **Operator**: The person or entity controlling this IPNS name.
* **Pointer**: The `/tgp.json` file at the root of this IPNS name that indicates the **current** `/ipfs/<cid>` to which users should resolve.
* **Current CID**: The CID referenced by the `current` field in `/tgp.json` at the time of access.
* **Legacy Content**: Any historical CID(s) previously referenced by this IPNS name or otherwise existing on distributed storage networks that are not the Current CID.
* **User**: Any person or automated agent that requests, resolves, crawls, or consumes content via this IPNS name.

---

## 2) Nature of This IPNS Name (Pointer Only)

1. This IPNS name is a **live pointer**, not an archive. It publishes a small JSON file (`/tgp.json`) that **only** identifies the Current CID.
2. The Operator does **not** commit to host, pin, seed, mirror, or otherwise provide Legacy Content.
3. The presence of immutable historical CIDs on third-party networks does **not** imply that the Operator hosts or endorses them, nor that such content is discoverable via this IPNS name.
4. Any access to Legacy Content occurs—if at all—via **independent third parties** and **outside** the Operator’s control.

---

## 3) No Hosting or Endorsement of Legacy Content

1. The Operator **does not advertise**, index, surface, or facilitate retrieval of Legacy Content through this IPNS name.
2. The Operator may actively **de-pin, purge, or refuse** to serve any content the Operator deems unlawful, harmful, infringing, or otherwise objectionable.
3. References to prior states may persist on decentralized networks due to the nature of such systems; **this does not constitute hosting** by the Operator.
4. The Operator may implement technical measures to ensure that requests made **under this IPNS name** are served **only** from the Current CID.

---

## 4) User Responsibilities & Acceptable Use

1. Users must not employ this IPNS name to locate, solicit, or retrieve unlawful, infringing, or harmful content, including but not limited to content that violates intellectual property, privacy, child protection, counter-terrorism, hate speech, or other applicable laws.
2. Users acknowledge that decentralized networks may contain third-party material independent of the Operator. Users assume all risk for any off-pointer retrieval or exploration.
3. Users agree not to attempt to misrepresent or forge the Pointer, to bypass or subvert the Operator’s moderation choices, or to use this IPNS name to launder access to Legacy Content.

---

## 5) Moderation, Takedown, and Legal Process

1. The Operator may remove, refuse, or change the Current CID at any time, with or without notice.
2. Where applicable law provides a notice-and-takedown or similar process (e.g., safe-harbor regimes), the Operator **will act in good faith** to remove or cease serving content from the Current CID upon receiving a valid legal notice that complies with the requirements of the Operator’s jurisdiction.
3. The absence of contact information in this file does **not** waive any rights, defenses, or obligations. If a reporting channel exists, it will typically be disclosed on the **live site** at the Current CID.
4. Nothing in this document requires the Operator to host counter-notices, anonymize complainants, or retain logs beyond what is required by law.

---

## 6) Intermediary / Conduit Position

1. The Operator’s role under this IPNS name is functionally akin to a DNS-style **pointer** or **routing instruction**.
2. The Operator is **not a publisher** of Legacy Content and is **not** an information location tool for Legacy Content.
3. To the extent permitted by law, the Operator claims the protections available to intermediaries, conduits, and hosting providers under applicable safe-harbor and intermediary-liability regimes (including, where relevant, but not limited to: online intermediary provisions, platform safe harbors, or equivalent frameworks in the Operator’s jurisdiction).

---

## 7) No General Duty to Monitor

1. The Operator does **not** undertake a general obligation to monitor content across decentralized networks, nor to proactively seek illegal activity beyond what is required by applicable law.
2. The Operator’s moderation and pointer updates are discretionary and may be automated or manual. No warranty is made that any particular content will be reviewed, detected, or removed.

---

## 8) Caching, Mirroring, and Third-Party Services

1. Gateways, mirrors, indexers, crawlers, or other third-party services may cache or rehost content, including prior CIDs, **without** the Operator’s involvement or consent.
2. The Operator is **not responsible** for third-party caching, mirroring, or rehosting, and has no obligation to require third parties to purge copies.
3. Users should assume that decentralized systems can persist data outside of this pointer and outside the control of the Operator.

---

## 9) No Waiver of Rights; Reservation of Remedies

1. The Operator reserves all rights to pursue civil, administrative, or criminal remedies for misuse of this IPNS name, abuse of process, fraudulent notices, or unlawful conduct.
2. No provision herein waives any defense, privilege, or right of the Operator, including defenses under intermediary-liability or safe-harbor laws.

---

## 10) No Legal Advice; No Attorney-Client Relationship

1. This document is a **standardized legal notice** intended to describe the Operator’s pointer-only posture. It is provided “as-is” without warranty and does **not** constitute legal advice to any party.
2. Use of this notice does not create an attorney-client relationship between any reader, User, or Operator and any other party.
3. Operators are encouraged to obtain jurisdiction-specific legal counsel when necessary.

---

## 11) Jurisdiction-Neutral Application

1. This notice is designed to be **jurisdiction-neutral** and to operate alongside, not in conflict with, applicable local law.
2. In the event of conflict with mandatory local law, that law controls to the extent of the conflict, and the remaining provisions of this notice remain in force.
3. References to legal regimes (e.g., “safe harbor,” “intermediary”) are **descriptive**; the availability and scope of such protections depend on local law and facts.

---

## 12) No License to Content; License to This Notice

1. **No license** to any content at the Current CID or elsewhere is granted by this notice. Content licenses, if any, are stated at the Current CID.
2. **License to this notice**: Permission is hereby granted, free of charge, to any person obtaining a copy of this **TruthGate Pointer Legal Notice & License (TGP-LN v1.0)** to use, reproduce, and distribute it verbatim or with faithful adaptations limited to formatting, date, and optional addition of Operator-specific details (e.g., contact lines), subject to the following conditions:

   * Derivative versions must not misrepresent the pointer-only posture described herein; and
   * Any material changes that weaken the pointer-only posture must be clearly identified.

---

## 13) Representations & Disclaimers

1. **Accuracy**: The Operator endeavors to keep `/tgp.json` accurate as of the stated timestamp, but **no warranty** is made that any given client, gateway, or resolver will retrieve the freshest state due to network propagation delays or caching.
2. **Availability**: The Operator does not warrant uninterrupted availability of the IPNS name or the Current CID.
3. **Integrity**: If a third party tampers with the pointer or attempts to impersonate the Operator, Users should rely on trusted gateways, cryptographic verification mechanisms, or the Operator’s official channels (if any).

---

## 14) Enforcement; Severability; Entire Notice

1. If any provision of this notice is held unlawful, void, or unenforceable, that provision shall be enforced to the maximum extent permissible and the remaining provisions shall remain in full force and effect.
2. This document constitutes the **entire legal notice** of the Operator regarding the pointer-only nature of this IPNS name and supersedes any prior or contemporaneous statements on that subject, except as superseded by mandatory local law.
3. Headings are for convenience only and do not affect interpretation.

---

## 15) Optional Operator Add-Ons (Not Required)

> The following lines are **optional** and may be added by Operators who wish to disclose more detail. Their omission does **not** waive any right or defense.

* **Contact (Abuse/Notices):** *Add an email or web form URL here if you maintain one.*
* **Jurisdiction / Governing Law:** *Add if you wish to designate, subject to local law.*
* **Data/Log Retention:** *Add if you maintain retention policies relevant to notices or disputes.*
* **Transparency Page:** *Add a URL if you publish reports about pointer updates or takedowns.*

---

## 16) Practical Summary (Non-Binding)

* This IPNS name publishes a **pointer** (`/tgp.json`) to a single **Current CID**.
* The Operator does **not** host or surface prior CIDs through this IPNS name.
* Any Legacy Content accessible elsewhere is **outside** the Operator’s control.
* Users must not exploit this IPNS name to access or promote unlawful content.
* This notice is provided to clarify roles, limit misunderstandings, and align expectations worldwide.

---

**End of TruthGate Pointer Legal Notice & License (TGP-LN v1.0)**";
    }

}
