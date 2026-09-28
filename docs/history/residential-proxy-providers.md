# Residential proxy providers: a classification taxonomy

> **History.** Kept as written for the record; it describes an earlier version and is not a current runbook. Current docs: [docs index](../README.md).

A field map of the residential proxy market, built to answer five questions about every provider I could find: how they get the IPs, how you route traffic through them, what they accept for payment (crypto especially), whether they make you identify yourself, and whether they can read what you send.

This sits alongside [`residential-proxies.md`](residential-proxies.md) in this repo. That report argued the thesis. This one enumerates the market and classifies it.

**Method.** A multi-agent swarm fanned out across eight discovery angles (market leaders, comparison-site long tail, crypto and no-KYC specialists, the P2P supply side, mobile and SOCKS5 niches, cheap resellers, forum and underground vendors, and enterprise scraping platforms), then deduplicated to a unique set, then profiled each provider across the five dimensions and ran a second independent agent to adversarially verify the two most-lied-about claims per provider: how the IPs are sourced, and whether the provider can decrypt your traffic. Totals: 212 raw mentions, 137 unique providers found, 58 fully profiled and verified here. 131 sub-agents, roughly 5M tokens of research.

**Date.** 2026-06-01. The market churns fast (rebrands, takedowns, new entrants every month), so treat status as a snapshot.

**One caveat up front.** Almost every claim a residential proxy provider makes about itself is marketing. "Ethically sourced," "100% consent," "no logs," "anonymous" are unenforced terms. Where a verifier could confirm a claim against primary evidence I say so. Where it is self-attestation I flag it. The per-provider detail behind this matrix carries the confidence ratings; the matrix cells are the headline, not the whole story.

---

## What I found, in six lines

1. **Sourcing is structurally dishonest.** The most valuable IP is the one whose owner does not know it is being used, so the incentive runs away from real consent. The biggest "compliance-forward" vendor is the direct descendant of the company that invented non-consensual exit-node resale.
2. **You route through them as a normal forward proxy.** HTTP, HTTPS, and SOCKS5 over a gateway endpoint, with credentials and geo targeting encoded in the username. This part is boring and standardized.
3. **Crypto is the mid-market default.** 44 of 58 take it, almost always through a hosted redirect processor (CoinGate is the confirmed one). The compliance majors are the crypto holdouts.
4. **No-KYC is common but is not anonymity.** 38 of 58 ask for nothing but an email. That hides you from a future paper trail, not from the provider, who watches every request you make in real time.
5. **They cannot read your HTTPS payload in normal use, but they can flip that switch.** Over a standard tunnel your content is safe end to end. The moment you use their "unlocker" or "scraping browser" product, or install their certificate, they decrypt everything. 21 of 58 sell exactly such a product.
6. **The whole category is an IP-reputation tool, not a privacy tool.** It moves the all-seeing observer from your ISP to a company that knows your billing identity. No collusion required for it to see everything except, in the good case, your payload bytes.

---

## The taxonomy: five axes

Every provider is placed on five axes. The matrix that follows scores all 58 on the headline value of each.

**Axis 1, sourcing.** Where the residential IPs come from.
- `SDK` bundled into free apps (VPNs, games, browser extensions). The device becomes an exit node, often with consent buried in a EULA or absent entirely. The gray zone, and the heart of the controversy.
- `Panel`, paid bandwidth-sharing proxyware (Honeygain, Pawns, PacketStream, Repocket). The user installs deliberately and is paid. The most defensible model, though consent is still thin.
- `P2P`, peer-to-peer client networks, mechanically similar to panels.
- `Reseller`, buys pooled supply from other networks or aggregators and rebrands it. Consent is laundered one hop up the chain.
- `Undisclosed`, asserts "ethically sourced" with no mechanism named. Treat as unknown.
- `DC-mislabel`, datacenter IPs sold as residential.

Most large pools are blends, so multiple tags is the norm.

**Axis 2, routing (how you send through).** Near-universal across the market: a backconnect **gateway endpoint** (`host:port`), authenticated by username and password, with country, city, ASN, session, and rotation flags encoded in the username string. Rotating (new IP per request) or sticky (hold one IP for a session) are both standard. Protocols are HTTP, HTTPS, and usually SOCKS5. The differentiators are targeting granularity (country only versus city and ASN and carrier) and access surface (raw gateway versus REST API versus browser extension). The matrix records the protocol set; the per-provider detail records targeting depth.

**Axis 3, payments and crypto.** Fiat is universal (card, PayPal, wallets, wire). Crypto is the variable. The matrix records yes, no, or unclear; the deep-dive records which coins and which processor.

**Axis 4, account and anonymity.** Every provider requires an account, because the gateway authenticates each request. The variable is verification:
- `mandatory`, KYC for everyone (ID, business docs, sometimes a video call).
- `conditional`, no KYC by default, triggered by sensitive targets, large orders, chargebacks, or unblocking restricted destinations.
- `none`, email signup, no identity check for standard use.

**Axis 5, traffic visibility (can they decrypt or view your traffic).** This axis is mostly universal, so it is not a per-row score in the obvious way. The verdict is the same for nearly everyone, and the one real differentiator is whether the provider also sells a server-side product that terminates your TLS. The matrix records that flag (`Unlocker`); the dedicated section below gives the full verdict.

---

## The master matrix

58 providers, sorted alphabetically. Cells are headline values derived from the verified profiles. Status is as of 2026-06-01.

| # | Provider | Status | Sourcing | Protocols | Crypto | KYC | Unlocker¹ |
|--:|---|---|---|---|:--:|---|:--:|
| 1 | 922Proxy / 922S5Proxy | defunct | SDK | HTTP/HTTPS/SOCKS5 | Yes | none | No |
| 2 | ABCProxy | rebranded | SDK | HTTP/HTTPS/SOCKS5 | Yes | mandatory | No |
| 3 | Apify Proxy | active | SDK+Panel+Reseller | HTTP/HTTPS/SOCKS5 | Yes | mandatory | Yes |
| 4 | ASocks | active | SDK | HTTP/HTTPS/SOCKS5 | Yes | none | No |
| 5 | BestProxy.net | active | Reseller | HTTP/HTTPS/SOCKS5 | Yes | none | No |
| 6 | Bright Data | active | SDK | HTTP/HTTPS/SOCKS5 | Unclear | mandatory | Yes |
| 7 | DataImpulse | active | SDK+Panel | HTTP/HTTPS/SOCKS5 | Yes | none | Yes |
| 8 | Decodo (formerly Smartproxy) | active | Panel | HTTP/HTTPS/SOCKS5 | Yes | conditional | Yes |
| 9 | Evomi | active | SDK+Panel+Reseller | HTTP/HTTPS/SOCKS5 | Yes | none | No |
| 10 | FloppyData | active | Undisclosed | HTTP/HTTPS/SOCKS5 | Yes | mandatory | No |
| 11 | Froxy | active | Reseller | HTTP/HTTPS/SOCKS5 | Yes | none | No |
| 12 | Geonix (geonix.com) | active | Reseller | HTTP/HTTPS/SOCKS5 | Yes | none | No |
| 13 | Geonode | active | SDK+Panel+Reseller | HTTP/HTTPS/SOCKS5 | Yes | conditional | Yes |
| 14 | GeoSurf | defunct | Panel+P2P+Reseller | HTTP/HTTPS | Unclear | none | No |
| 15 | GoLogin Proxy | active | Reseller | HTTP/HTTPS/SOCKS5 | Yes | none | No |
| 16 | GoProxy (now GloryCloud) | rebranded | Reseller | HTTP/HTTPS/SOCKS5 | Yes | none | No |
| 17 | Infatica | active | SDK | HTTP/HTTPS/SOCKS5 | Yes | conditional | Yes |
| 18 | IPBurger | active | Undisclosed | HTTP/HTTPS/SOCKS5 | Yes | none | No |
| 19 | IPCola | active | SDK+Reseller | HTTP/HTTPS/SOCKS5 | Yes | none | No |
| 20 | IPRoyal | active | Panel | HTTP/HTTPS/SOCKS5 | Yes | conditional | Yes |
| 21 | LightningProxies | active | Reseller | HTTP/HTTPS/SOCKS5 | Yes | none | No |
| 22 | Live Proxies | active | SDK | HTTP/SOCKS5 | No | none | No |
| 23 | LunaProxy | active | Reseller | HTTP/HTTPS/SOCKS5 | Yes | none | Yes |
| 24 | MarsProxies | active | Panel | HTTP/HTTPS/SOCKS5 | Yes | none | No |
| 25 | Massive (Joinmassive) | active | SDK | HTTP/HTTPS/SOCKS5 | No | none | Yes |
| 26 | MobileHop | active | Mobile/4G own-pool | HTTP/HTTPS/SOCKS5 | Yes | none | No |
| 27 | MobileProxyNow | active | SDK+Reseller | HTTP/HTTPS/SOCKS5 | Yes | mandatory | No |
| 28 | NetNut | active | Panel+P2P+Reseller | HTTP/HTTPS/SOCKS5 | Yes | mandatory | Yes |
| 29 | Nimble (NimbleWay) | active | SDK+Panel+Reseller | HTTP/HTTPS | No | mandatory | Yes |
| 30 | NodeMaven | active | Reseller | HTTP/HTTPS/SOCKS5 | Yes | none | Yes |
| 31 | NSocks (nsocks.net) | active | Reseller | HTTP/HTTPS/SOCKS5 | Yes | unclear | No |
| 32 | Oculus Proxies | active | Undisclosed | HTTP/HTTPS/SOCKS5 | No | none | No |
| 33 | Oxylabs | active | SDK+Reseller | HTTP/HTTPS/SOCKS5 | No | conditional | Yes |
| 34 | PacketStream | active | Panel | HTTP/HTTPS/SOCKS5 | Yes | none | No |
| 35 | Ping Proxies (now Byteful) | active | SDK+Panel | HTTP/HTTPS/SOCKS5 | Yes | conditional | No |
| 36 | PlainProxies | active | Reseller | HTTP/HTTPS/SOCKS5 | Yes | none | No |
| 37 | Prosox | active | Undisclosed | HTTP/HTTPS/SOCKS5 | Yes | none | No |
| 38 | Proxies.sx / SX.ORG | active | SDK+Panel | HTTP/HTTPS/SOCKS5 | Yes | none | No |
| 39 | Proxy-Cheap | active | Reseller | HTTP/HTTPS/SOCKS5 | Yes | none | No |
| 40 | Proxy-Seller | active | Panel | HTTP/HTTPS/SOCKS5 | Yes | none | No |
| 41 | PROXY.father (proxyfather.com) | active | Mobile own-pool | HTTP/HTTPS/SOCKS5 | Yes | none | No |
| 42 | Proxy.Market (Proxymarket) | active | Undisclosed | HTTP/HTTPS/SOCKS5 | Yes | none | No |
| 43 | ProxyEmpire | active | Undisclosed | HTTP/HTTPS/SOCKS5 | Yes | conditional | Yes |
| 44 | ProxyOmega | active | Reseller | HTTP/HTTPS/SOCKS5 | Yes | unclear | No |
| 45 | Proxyrack | active | Panel | HTTP/HTTPS/SOCKS5 | Unclear | mandatory | No |
| 46 | ProxyScrape | active | Undisclosed | HTTP/HTTPS/SOCKS5 | Yes | none | Yes |
| 47 | ProxySocks5 | active | Reseller+DC-mislabel | HTTP/HTTPS/SOCKS5 | Yes | none | No |
| 48 | ProxyWing | active | Undisclosed | HTTP/HTTPS/SOCKS5 | Yes | none | No |
| 49 | PYProxy (PYPROXY) | active | SDK | HTTP/HTTPS/SOCKS5 | Yes | none | No |
| 50 | RapidProxy | active | P2P | HTTP/HTTPS/SOCKS5 | Yes | none | No |
| 51 | Rayobyte (formerly Blazing SEO) | active | SDK+Panel+Reseller | HTTP/HTTPS/SOCKS5 | Unclear | mandatory | Yes |
| 52 | ScraperAPI | active | Undisclosed | HTTP/HTTPS | No | none | Yes |
| 53 | Shifter (formerly Microleaves) | active | Reseller | HTTP/HTTPS/SOCKS5 | Yes | none | No |
| 54 | SOAX | active | SDK | HTTP/HTTPS/SOCKS5 | Yes | conditional | Yes |
| 55 | Storm Proxies | active | Undisclosed | HTTP/HTTPS | Unclear | none | No |
| 56 | Thordata | active | Reseller | HTTP/HTTPS | Unclear | none | Yes |
| 57 | Webshare | active | Reseller | HTTP/HTTPS/SOCKS5 | No | none | Yes |
| 58 | Zyte (Smart Proxy Manager / Zyte API) | rebranded | Reseller | HTTP/HTTPS | No | mandatory | Yes |

¹ **Unlocker** = the provider also sells a server-side "web unlocker," "scraping browser," or "web data API" product that terminates your TLS on their infrastructure. When you use that product (not the raw proxy), the provider sees your decrypted content by design. The raw proxy from the same vendor does not decrypt. See the traffic-visibility section.

**Distribution across the 58:**
- Sourcing tags (providers can carry several): Reseller 27, SDK 20, Panel 16, Undisclosed 10, P2P 3, DC-mislabel 1.
- Crypto: Yes 44, No 8, Unclear 6.
- KYC: none 38, mandatory 10, conditional 8, unclear 2.
- Sells a TLS-terminating unlocker product: Yes 21, No 37.

---

## Dimension 1: how they get the residential proxies

The honest one-liner: a residential proxy is someone else's home or mobile connection rented out as an exit node so your traffic looks like a real consumer. The entire value is that the IP is not a datacenter and not obviously a proxy. That value is in direct tension with consent, because the most valuable IPs belong to people least aware they are being used.

The sourcing spectrum runs from transparent to criminal, and the two ends are technically identical at the device level.

**Paid bandwidth-sharing panels (proxyware).** Honeygain, Pawns.app (formerly IPRoyal Pawns), PacketStream, Peer2Profit, EarnApp, Repocket. People install software and get paid pennies per gigabyte (roughly $0.20/GB on Pawns, $0.10/GB on PacketStream) to resell idle bandwidth, which is aggregated and resold up the chain at a large markup. The most defensible model. Consent is still thin, because users rarely grasp that strangers will route arbitrary, possibly illegal, traffic out of their home IP.

**SDK bundling in free apps (the gray zone).** Operators ship SDKs (PacketSDK, CastarSDK, and others) that developers embed in free VPNs, games, and extensions. The developer is paid per install; the SDK quietly turns the device into an exit node, running even when the app is closed. Disclosure ranges from buried in a EULA to absent. This is the heart of the controversy, and it is where most "100% ethical" pools actually come from.

**Botnet and malware (criminal).** The same exit-node payload, installed by outright malware with zero consent. The landmark case is **911 S5**, dismantled by DOJ and FBI in May 2024 and described as likely the largest botnet ever: about 19 million unique IPs built by bundling backdoors into free VPNs (MaskVPN, DewVPN, PaladinVPN, ProxyGate, ShieldVPN, ShineVPN) and pirated software, leased to criminals, around $99M in revenue, $136.4M in crypto seized.

The skeptical point that matters: **SDK and botnet sourcing produce the same artifact.** Same bidirectional payload, same fake-VPN delivery vehicle. The only difference is whether a consent screen existed somewhere and how honest it was. Google's Threat Intelligence Group, disrupting the IPIDEA network in early 2026, put it plainly: many providers claim ethical sourcing and "these claims are often incorrect or overstated."

**The lineage that explains the whole industry.** Hola, a free VPN, quietly resold its free users as exit nodes through a sister company, Luminati, charging for bandwidth that came from people who thought they had installed a free VPN. It went public in May 2015 after 8chan was attacked through the network. Luminati rebranded to **Bright Data** in March 2021 and is today the largest, most compliance-forward player. The biggest "ethical" vendor in the market is the direct descendant of the company that pioneered non-consensual resale.

**What the marketing terms actually mean.** "100% consent" and "KYC of suppliers" are weak by construction. The supply chain is layered: aggregator, then mid-tier broker, then brand. A provider can truthfully say it KYCs its suppliers while sourcing from an aggregator who got the bandwidth from an SDK buried in a game whose users never meaningfully agreed. KYC of your counterparty is not consent from the person whose IP is used. Each hop launders the claim.

**Regulatory reality, stated precisely.** 911 S5 was a criminal and sanctions action (OFAC sanctioned three people and three front companies), not consumer protection. The FBI issued consumer PSAs in 2024 and 2026. The FTC has not, in this research, brought a residential-proxy-specific case; its X-Mode/Outlogic and Avast actions (2024) are adjacent SDK-consent precedents, not proxy cases. Anyone claiming "the FTC blessed or banned residential proxies" is overstating the record in both directions.

**Notable named histories surfaced by the verifiers:** Shifter is the former Microleaves, tied by KrebsOnSecurity to pay-per-install malware distribution. Infatica's operator was linked by Krebs to King Servers. Rayobyte's pool drew documented abuse findings from the Qurium Media Foundation. GeoSurf (now defunct) could not have its acquisition pipeline verified in an NDSS 2021 measurement study. None of these are allegations I am inventing; they are the verifiers' citations, and they cluster on exactly the cheap, undisclosed-sourcing end of the matrix.

---

## Dimension 2: how you route traffic through them

This is the most standardized dimension. The dominant pattern, used by nearly every provider in the matrix:

- **A backconnect gateway endpoint.** One hostname and port (for example `gate.provider.com:7000`). You point your client at it; the provider rotates the actual exit IP behind it.
- **Credentials and control in the username.** You authenticate with username and password (or IP allowlist), and you encode targeting and session control as flags inside the username string: country, region, city, ASN, a session ID to hold a sticky IP. Bright Data's `brd-customer-[id]-zone-[zone]-country-us` format is the canonical example.
- **Rotation modes.** Rotating gives a fresh IP per request. Sticky holds one IP for a bounded session (often up to ~30 minutes) for flows like carts and logins.
- **Protocols.** HTTP and HTTPS almost everywhere, SOCKS5 on most. A handful of scraping-platform players (Zyte, ScraperAPI, Thordata, Nimble, ScrapingBee-types) expose HTTP and HTTPS only, because you talk to their API rather than a raw socket.
- **Access surfaces.** Raw gateway is universal. Many add a REST API, a dashboard with manual IP switching, proxy-list export, and a browser extension. The scraping platforms add a fetch-on-behalf API where you hand them a URL and they return rendered HTML or JSON.

The real per-provider variation is **targeting granularity**, not mechanism. Country-only is the floor (Webshare, PacketStream). City plus ASN plus carrier is the ceiling (Bright Data, Oxylabs, SOAX, IPRoyal, Infatica). If geo precision matters to your use case, that is the axis to compare, and it lives in the per-provider detail rather than this matrix.

---

## Dimension 3: payments, and crypto in particular

The market splits cleanly. The compliance-first majors (Bright Data, Oxylabs) gate access behind KYC and treat anonymity as a liability to design out. The crypto-first mid-market sells email signup plus crypto checkout as a feature.

**Crypto acceptance: who, and on what rail.** 44 of 58 take crypto. The rail is almost always a **hosted processor redirect**, not wallets the provider runs. **CoinGate is the dominant, verifiable processor** (confirmed for IPRoyal and Decodo). NOWPayments and Coinbase Commerce appear constantly in market SEO copy but I could not tie them to a named provider from primary sources, so treat them as plausible but unverified per vendor.

Standouts:
- **IPRoyal** is the most aggressively crypto-positioned major: advertises 25+ coins (BTC, ETH, LTC, TRX, DOGE, BNB, MATIC, SOL, XRP, USDT, USDC and more) via CoinGate, and literally pitches "maintain your anonymity."
- **anyIP** (surfaced in the payments deep-dive though not in the 58-row sample) claims 60+ coins and, notably, **Monero**, the only widely accepted coin with real on-chain unlinkability. That combination, burner email plus Monero plus auto-activation, is the only end-to-end-anonymous purchase path in the market.
- **Decodo** takes crypto via CoinGate for everything except ISP and per-IP datacenter plans, while its fiat side runs through Paddle as merchant of record (a heavier compliance footprint).
- **SOAX** takes crypto via EukaPay (BTC, ETH, USDC, USDT on ETH and Tron, LTC, BCH, SOL, MATIC).
- **DataImpulse** narrows to USDT on TRC20, the cheap-stablecoin pattern common among small vendors.
- Many smaller vendors (Proxy-Cheap, Proxy-Seller, Froxy, NodeMaven, ProxyScrape, ProxyWing, Infatica, Geonode, Shifter, PacketStream) take BTC and usually USDT and ETH.

**Crypto is not always self-service.** Shifter and some others require contacting support to arrange a crypto or wire payment, while card and PayPal are instant.

**The compliance majors are the crypto holdouts.** Oxylabs (Stripe, PayPal, AliPay, wire) and Bright Data (card, PayPal, Payoneer, AliPay, wire, with crypto inconsistent and undocumented) do not foreground crypto, because their KYC-gated, invoice-billed model is structurally incompatible with anonymous payment.

**Fiat** is universal and richer at consumer vendors: cards everywhere, PayPal common, Google Pay and Apple Pay and AliPay at several, wire and invoicing as the enterprise default (and exactly where KYC lives). Card, PayPal, and wire are the identity-binding methods, which is why the privacy-conscious segment skews crypto.

---

## Dimension 4: account requirement and anonymity

**An account is always required.** Every provider authenticates each proxy request against your account or API key, so there is no account-less product. "No-KYC" still binds usage to an account; it just does not verify who owns it.

The verification spectrum:
- **Mandatory (10 of 58).** Oxylabs KYCs everyone (its own words: every customer answers a KYC questionnaire; it says it rejects about 25% of applicants). Bright Data requires use-case review, incorporation docs, government ID, and sometimes a live video call for full residential access. Rayobyte, Infatica (Veriff ID plus selfie), Nimble, Zyte, and a few others gate residential behind identity. This is the hardest gate, and anonymous signup is impossible here.
- **Conditional (8 of 58).** No KYC by default, triggered on the risky edges: IPRoyal verifies for sensitive targets (banking, government) and large buys; Decodo, Geonode, SOAX, ProxyEmpire, and Ping Proxies follow the same "KYC deferred until you look risky" pattern. Bright Data also runs a genuine no-KYC on-ramp to a 200-site allow-list, conditioned on installing its certificate.
- **None (38 of 58).** Email signup, no identity check for standard use. This is the bulk of the mid-market and the SOCKS5 and mobile resellers.

**Is truly anonymous signup plus payment possible?** Technically yes, narrowly. Burner email plus Monero plus an auto-activating vendor (anyIP comes closest) binds no legal identity at purchase and leaves no traceable payment trail. BTC or USDT get you email-only signup but a pseudonymous, traceable on-chain trail, and the CoinGate off-ramp can correlate the fiat conversion.

**But anonymity at the till is mostly theater for the threat that matters.** Even with a burner email and Monero, the provider's gateway sits in path for every request. It sees your real source IP, every destination, timing, and volume, and can unilaterally correlate all of it to your account. There is no cryptographic unlinkability, the same single-trusted-party weakness as a VPN. As the payments brief put it: no-KYC removes a name from the billing record; it does not remove the provider's god's-eye view of your traffic.

**How no-KYC vendors control abuse without identity.** Four mechanisms: default restricted-target lists applied to all customers (banking, government, streaming, crypto-finance, ticketing are commonly fenced off, and unblocking them often triggers KYC); certificate or controlled-gateway enforcement (Bright Data's no-KYC mode requires its cert); acceptable-use policy plus the self-interest that abuse burns their own IP pool; and reactive verification on chargebacks and large orders. No-KYC is really KYC-deferred-until-you-look-risky, paired with fencing off the highest-fraud destinations.

---

## Dimension 5: can a residential proxy decrypt or view your traffic

This is the security-critical question, and the answer is precise and mostly the same across providers. It depends entirely on which proxying mode you use and whether you have trusted the provider's certificate. The provider and the exit host **always** see who you talk to, when, and how much (destination IP, the TLS SNI hostname, timing, volume). They see your **decrypted content** only in two specific cases.

**Case 1, plain HTTP. Full exposure.** When you send a cleartext HTTP request, the proxy is the recipient of your request line and headers; it parses them to forward. The exit sees the full URL with query string, every header including Authorization and Cookie, the request body, and the full response. This is how an HTTP proxy works by definition, not a bug. Never send anything sensitive over plain HTTP through any proxy. Increasingly moot for real websites in 2026, but it still bites on internal APIs, legacy endpoints, and redirect chains that start on `http://`.

**Case 2, HTTPS over a CONNECT tunnel. Payload safe, metadata leaks.** This is the standard commercial mode and the one people get wrong in both directions. To reach an `https://` site, your client sends the proxy `CONNECT host:443`; the proxy opens a raw TCP connection and blindly relays bytes. Your TLS handshake terminates at the **origin server**, not the proxy, so the proxy never holds the session keys and cannot read or alter the encrypted body. What it does see: the destination (named in the CONNECT line and re-leaked by the cleartext TLS SNI unless ECH is in use), the destination IP, and timing, volume, and packet-size patterns, all bound to your authenticated billing identity. So content is protected, but who you talk to, when, and how much leaks regardless. A residential proxy gives you zero unlinkability here; it just relocates the observer from your ISP to the provider.

**Case 3, MITM with a provider certificate. Full decryption of HTTPS.** This is real and marketed, not hypothetical. The precondition is that your client trusts the interceptor's certificate, established two ways: you install the provider's root CA, or you use a provider-supplied browser, SDK, or managed-fetch endpoint that bakes the trust in (or simply disables certificate validation). The interceptor terminates your TLS, presents a leaf cert it mints for the hostname signed by its own CA, decrypts, reads or modifies, then opens a second TLS connection onward. Two sessions, provider as cleartext in the middle, full case-1 exposure for HTTPS. Where it shows up:
- **"Web unlocker," "scraping browser," and "SERP/web-data API" products.** These solve CAPTCHAs, render JS, and rotate fingerprints for you, which structurally requires them to terminate TLS and see your plaintext request and the decrypted response. **21 of the 58 sell such a product** (the `Unlocker` column): Bright Data, Oxylabs, SOAX, IPRoyal, Rayobyte, Decodo, Zyte, ScraperAPI, Apify, Infatica, NetNut, Geonode, Nimble, Thordata, ProxyScrape, NodeMaven, LunaProxy, DataImpulse, Massive, ProxyEmpire, Webshare. If you use the unlocker, assume case 3. The raw proxy from the same vendor stays case 2.
- **Proxies that ship a custom CA "to make HTTPS work."** Installing it is consenting to interception. Bright Data's own Proxy Manager has an "SSL Analyzing" feature that does exactly this when switched on.
- **SDKs and clients that disable cert verification** (`verify=False`, `rejectUnauthorized:false`, `--insecure`). This is the quiet, dangerous variant: no CA-install ceremony, just a flag that silently turns case 2 into case 3. IPRoyal's Web Unblocker documentation, for instance, instructs disabling SSL verification.

**The peer and its ISP.** The exit is a real stranger's device running proxyware (or, in the criminal case, compromised). That device sits at the TCP relay point and sees the same destination and metadata as the gateway (case 2), or plaintext under case 1 or 3. The peer's home router and ISP see the outbound connections leaving that home, which are actually your traffic, attributed to the peer. That attribution is the whole product, and the inverse is the ethical landmine: if you run a bandwidth-sharing app, strangers' traffic, including criminal traffic, exits via your IP and is attributed to you. That is how innocent people get subpoenas.

**Metadata leaks even under perfect TLS.** SNI sends the hostname in cleartext by default. ECH encrypts it but only with mutual support, partial 2026 adoption, and it gets you blocked rather than protected in censoring jurisdictions (China has dropped ESNI connections since 2020). DNS can leak hostnames before the connection opens. The destination IP is always visible. Packet sizes and timing routinely reveal which page or video within a known site. TLS protects content, not shape.

**The trust model is the frame.** With a residential proxy you have not removed an observer; you have moved the all-seeing one from your ISP and the destination to a company that authenticated you, and added a second, usually non-consenting party (the exit host and its ISP). Unlike Tor, mixnets, OHTTP, or Apple Private Relay, which split trust across independently operated parties so breaking them needs collusion, a residential proxy provides no split. The provider, linked to your billing identity, sees your identity, every destination, and all metadata unilaterally, and can decrypt content the moment you use its unlocker or trust its cert. No collusion needed; it is one party that already has everything except, in the good case, your payload bytes.

**Bottom line on this dimension.** Plain HTTP or an installed provider CA means full plaintext. A CONNECT tunnel with certificate validation left on means payload safe, metadata exposed. Certificate pinning is your one hard defense that makes silent interception break loudly. A residential proxy is an IP-reputation and geo-evasion tool, not a privacy or anonymity tool. A China-based residential exit is the strict worst case: single-trusted-party exposure plus an interception-friendly jurisdiction that also blocks the encrypted-handshake features you would want.

---

## Provider archetypes

The 58 cluster into recognizable types. The cluster predicts the answers on all five axes better than any single brand fact.

**The compliance majors.** Bright Data, Oxylabs, and the Oxylabs-owned Webshare. Largest pools, finest targeting, also sell unlockers. KYC mandatory or near it, crypto absent or unclear, sourcing relatively documented but descended from or adjacent to the worst practices. You buy scale and a legal indemnity, not anonymity.

**The crypto-first mid-market.** IPRoyal, Decodo, SOAX, NodeMaven, Proxy-Cheap, Proxy-Seller, DataImpulse, Froxy, ProxyScrape, ProxyEmpire, Geonode. Crypto checkout, no-KYC-by-default with conditional triggers, blended and partly undisclosed sourcing, prepaid and pay-as-you-go billing. This is the center of gravity for anyone who wants low friction.

**The scraping platforms.** Zyte, ScraperAPI, Apify, Nimble, Thordata, and the unlocker tiers of the majors. You talk to an API, not a socket; they fetch on your behalf and therefore terminate your TLS by design. Convenience in exchange for handing them your plaintext.

**The P2P supply side.** PacketStream, and the panels behind many others (Honeygain, Pawns, Repocket). Transparent two-sided marketplaces, the most defensible sourcing, but country-only targeting and smaller pools.

**The SOCKS5 and mobile resellers.** ASocks, NSocks, ProxySocks5, BestProxy, PYProxy, LunaProxy, PlainProxies, IPCola, Geonix, MobileHop, MobileProxyNow, PROXY.father, and the rest of the long tail. Cheap, crypto-friendly, no-KYC, undisclosed or reseller sourcing, frequent rebrands. The highest-risk-sourcing, lowest-accountability end. Several are thin rebrands of each other.

**The disrupted and defunct.** 922Proxy (domain seized in the early-2026 Google and Mandiant IPIDEA takedown), ABCProxy (named in the same IPIDEA action), GeoSurf (shut down December 2023). The IPIDEA disruption found 13 nominally independent proxy and VPN brands under common control, fed by 600+ Android apps and 3,000+ trojanized Windows binaries. Treat low-profile SDK-sourced brands as one enforcement action away from disappearing, with the underlying device pool resurfacing under a new name.

---

## A buyer's skeptical checklist

You cannot verify sourcing from the outside. You can only assess plausibility and shift risk.

- **Demand named, auditable supply, not adjectives.** "Ethically sourced" with no mechanism is marketing. Ask which SDKs, apps, or panels feed the pool, and whether you can see the actual opt-in flow an end user sees.
- **Run the supply-chain hop test.** Ask them to name the layer directly above the end user. "We buy from a trusted aggregator" is the laundering answer. More hops, less the consent claim is worth.
- **Read buyer-KYC for what it is.** Strong buyer KYC protects the provider and gates you; it says little about supplier consent.
- **Cross-check against threat intel.** Pool IPs that show up in GTIG/IPIDEA, HUMAN/PROXYLIB, or Spur datasets are a red flag regardless of the pitch.
- **Watch the fake-VPN tell and the price.** If the supply is free consumer VPNs or passive-income apps, consent is structurally thin. Suspiciously cheap, enormous pools signal supply that was not fairly obtained.
- **For confidentiality: keep TLS validation on, never send sensitive data over plain HTTP, and pin certificates if you can.** If a provider tells you to install a certificate or ships a client that skips validation, you are in the full-decryption regime.
- **For anonymity: understand you are not getting any from the provider.** Burner email plus Monero hides you from a future paper trail, not from the gateway watching every request. If you need unlinkability, this is the wrong tool category; look at OHTTP, PIR, and mixnets (see the rest of this repo).

---

## Scope and honesty notes

- **58 of 137 profiled.** The swarm found 137 unique providers and deep-profiled the 58 highest-priority. The remaining ~79 are mostly thin resellers, rebrands, and forum-advertised micro-vendors in the same SOCKS5-niche cluster, which the archetype already characterizes. They were not silently dropped; they are out of the detailed sample by priority cap.
- **A few cells are auto-derived.** The Sourcing, KYC, and Unlocker columns are bucketed from the verified prose by rule, so a handful of edge cases (a borderline conditional-versus-mandatory KYC call, an unlocker flag on a vendor whose scraper product is nascent) may be off by one bucket. The per-provider verified profiles, with their confidence ratings, are the authoritative source; the matrix is the index.
- **Marketing is not evidence.** Pool-size numbers are vendor claims (Bright Data's own pool measured far smaller than its marketed total in independent testing). "No logs," "ethical," and "anonymous" are self-attestation unless a verifier tied them to primary evidence.
- **The market churns.** Rebrands (Smartproxy to Decodo, Ping Proxies to Byteful, GoProxy to GloryCloud), takedowns (IPIDEA, 911 S5), and shutdowns (GeoSurf) all happened recently. Re-verify status before relying on any single row.

**Primary sources behind the analysis** (full citations live in the per-provider verified profiles): Google Cloud / GTIG IPIDEA disruption (2026); US DOJ and OFAC on 911 S5 (2024); HUMAN Security PROXYLIB and LumiApps; KrebsOnSecurity on Microleaves/Shifter and on Infatica/King Servers; Trend Micro "Illuminating HolaVPN"; Qurium Media Foundation on Rayobyte and Bright Data; NDSS 2021 residential-proxy measurement study; FBI/IC3 PSAs (2024, 2026); FTC actions on X-Mode/Outlogic and Avast; provider documentation (Bright Data SSL Analyzing, IPRoyal Web Unblocker, Oxylabs KYC policy, CoinGate integrations); and independent reviews (Proxyway and others). The traffic-visibility verdict extends the trust-model analysis in [`residential-proxies.md`](residential-proxies.md) in this repo.
