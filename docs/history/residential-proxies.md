# Anonymized scraping, residential proxies, and what they do to your privacy

> **History.** Kept as written for the record; it describes an earlier version and is not a current runbook. Current docs: [docs index](../README.md).

This report answers four questions raised in conversation:

1. A friend ran SearXNG with Tor enabled, but nearly every site and engine blocked him, so it effectively did not work. Why?
2. A friend doing industrial scraping buys thousands of residential IPs. What is that market?
3. A friend uses residential proxies based in China. What changes?
4. The key question: if you use a residential proxy service, does that kill the privacy and anonymity guarantees you were trying to get?

The short version of the answer to (4) is at the bottom, in bold. It is "yes," and the first three sections explain why someone ends up reaching for residential proxies in the first place and what they cost you when you do.

A note on sourcing: every numeric and factual claim below was adversarially verified against primary sources. Where verification found a claim overstated, mis-attributed, or false, this report uses the corrected version and flags it explicitly.

---

## Why SearXNG over Tor got blocked

The friend's experience was not a misconfiguration. It is structural, and it has three layers.

### Layer 1: Tor exit IPs are a public, auto-blockable list

Tor's exit relays are not secret. The canonical bulk exit list lives at [check.torproject.org/torbulkexitlist](https://check.torproject.org/torbulkexitlist) and contains roughly 2,000 IPs. Tor Metrics shows on the order of 1,500 to 2,000 exit relays out of roughly 8,000 to 10,000 total relays in 2026 ([Tor Metrics](https://metrics.torproject.org/)). That list is routinely ingested by off-the-shelf blocking tooling: iptables rules, Palo Alto external dynamic lists, and the [FireHOL tor_exits ipset](https://iplists.firehol.org/?ipset=tor_exits). So any site that wants to can drop all Tor exit traffic with a list it refreshes hourly.

### Layer 2: Cloudflare and other anti-bot layers give Tor exits terrible IP reputation

Cloudflare fronts a large share of the web, and it treats Tor exits as high-threat. In its 2016 post [The Trouble with Tor](https://blog.cloudflare.com/the-trouble-with-tor/), Cloudflare claimed "94% of requests that we see across the Tor network are per se malicious" and attributed roughly 18% of global email spam to bots harvesting addresses over Tor. Because Tor's anonymity prevents per-browser reputation, Cloudflare falls back to per-IP threat scoring and CAPTCHA challenges, which on a poor-reputation exit can feel like an infinite loop.

That 94% figure is real but contested, and it should be treated as a decade-old, self-reported vendor metric, not a neutral measurement. It counts requests, not users, and the Tor Project published a [substantive rebuttal](https://blog.torproject.org/trouble-cloudflare/): Cloudflare's reputation system labels any IP that has ever sent spam as malicious, so innocent users sharing an exit are tainted in perpetuity. The Tor Project countered that Cloudflare blocks at least 80% of Tor IPs, that it typically took about 30 days for an exit to acquire bad reputation that then stuck, and cited Akamai finding Tor conversion rates virtually equal to non-Tor.

Both blogs are partisan and from 2016. Independent peer-reviewed measurement gives a more grounded picture than either:

- NDSS 2016, [Do You See What I See? Differential Treatment of Anonymous Users](https://www.ndss-symposium.org/wp-content/uploads/2017/09/do-you-see-what-i-see-differential-treatment-anonymous-users.pdf) (Khattak et al.), found roughly 3.67% of Alexa top-1000 sites discriminate against Tor at the application layer.
- USENIX Security 2017, [Characterizing the Nature and Dynamics of Tor Exit Blocking](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/singh) (Singh et al.), found blocking is highly concentrated: 51% of discriminating websites block fewer than 5% of studied exits, while only 11% block more than 70%.

So Tor blocking is real and measurable, but it is neither "94% malicious" nor a blanket ban. It is concentrated among a minority of exits and a small fraction of top sites, and Cloudflare happens to sit in front of enough of those sites that it dominates the lived experience.

### Layer 3: SearXNG is itself classified as a bot, and Google in particular has gotten worse

SearXNG aggregates other engines by forwarding requests on your behalf. Its own [limiter documentation](https://docs.searxng.org/admin/searx.limiter.html) states plainly that "SearXNG passes through requests from bots and is thus classified as a bot itself," after which the engine "receives a CAPTCHA or is blocked." SearXNG encodes this reality in its defaults: the Cloudflare-CAPTCHA suspension timer `cf_SearxEngineCaptcha` is set to 1,296,000 seconds, which is 15 days ([settings.yml](https://github.com/searxng/searxng/blob/master/searx/settings.yml)). A single CAPTCHA event takes that upstream engine offline for your instance for two weeks.

The Google case is the sharpest. [Issue #2515](https://github.com/searxng/searxng/issues/2515) (opened 2023-06-24) documented that a fresh instance is blocked after about 5 searches, and that Google-working public instances dropped from 66 of 91 to 25 of 91 in June 2023, with TLS and HTTP/2 fingerprinting suspected. That was a 2023 snapshot, and the situation has worsened, not eased: as of early 2026 Google rejects SearXNG requests with HTTP 403 outright rather than just rate-limit CAPTCHAs, and the Google engine is widely reported broken across public instances ([#5286](https://github.com/searxng/searxng/issues/5286), [#5768](https://github.com/searxng/searxng/issues/5768), [#5867](https://github.com/searxng/searxng/issues/5867)).

### The fix space

Stacking these three layers explains the friend's result completely. He routed a bot-classified aggregator through the single worst-reputation IP pool on the internet, then asked it to query engines that fingerprint and block exactly that. Everything blocked because everything was designed to.

The fix space, in order of how much it costs you:

- **Reduce the engine set.** Drop Google and other heavily-protected engines; keep engines that do not aggressively challenge bots. This keeps your anonymity but shrinks coverage.
- **Move to a clean exit IP.** SearXNG's own [CAPTCHA documentation](https://docs.searxng.org/admin/answer-captcha.html) recommends running the instance behind an SSH or SOCKS5 tunnel to a clean IP. This trades Tor's anonymity for an IP nobody has flagged yet.
- **Buy IP reputation.** This is what industrial scrapers do, and it is the on-ramp to the rest of this report. Residential and mobile proxies pass the bot checks precisely because they look like real consumer users. The catch, developed in the final section, is that they pass the checks by surrendering the anonymity Tor was protecting. Passing the bot check and staying anonymous are in direct tension.

---

## The residential proxy market

Industrial scraping at the scale of "thousands of IPs" runs almost entirely on commercial proxy networks. The market sorts along a single gradient: price versus detectability. The cheaper the IP, the easier a site can tell it is not a real consumer and block it.

### The taxonomy

| Tier | What it is | Rough price | Detectability / trust | Notes |
|---|---|---|---|---|
| Datacenter | IPs from hosting and cloud ASNs | ~$0.10–0.50/GB | Easily flagged as non-residential; success can fall to 40–60% on protected sites | Fast (100–1000 Mbps, 10–50ms), often sold per-IP/subscription. Roughly 80x cheaper than residential. |
| ISP / static residential | IPs registered to residential addresses but hosted in datacenters | Mid | Combine datacenter speed with residential legitimacy; sticky and long-lived | Bought in bulk from ISPs. |
| Rotating residential | Traffic routed through real consumer devices (P2P peers) | ~$1.75–8.50/GB retail, ~$2–3.50/GB at TB scale | Hard to detect; 95–99% success rates | Slower (10–100 Mbps, 100–300ms). The workhorse for scraping. |
| Mobile (3G/4G/5G/LTE) | Carrier-assigned IPs behind Carrier-Grade NAT | Often per-port-per-day ($2–7/day) or ~$2–2.25/GB | Highest trust, because one IP genuinely fronts 500–5,000 real users, so blocking it risks collateral damage | Rotates via airplane-mode / reconnect cycling. |

Sources for the taxonomy and pricing: [Webshare](https://www.webshare.io/blog/datacenter-vs-residential-proxies), [Apify](https://use-apify.com/blog/datacenter-vs-residential-vs-isp-proxies), [Oxylabs datacenter-vs-residential](https://oxylabs.io/blog/the-difference-between-data-center-and-residential-proxies), [Infatica ISP-vs-residential](https://infatica.io/blog/isp-proxies-vs-residential-proxies/), [Oxylabs mobile](https://oxylabs.io/products/mobile-proxies), [Multilogin mobile](https://multilogin.com/blog/best-mobile-proxies/), [Apify IPRoyal pricing](https://use-apify.com/blog/iproyal-pricing-plans-2026), [AIMultiple proxy pricing](https://aimultiple.com/proxy-pricing), [Proxyway residential](https://proxyway.com/best/residential-proxies).

### Providers and their claimed pool sizes

The headline numbers providers advertise are marketing maxima and overstate concurrently-available IPs, because a residential IP only exists in the pool while the underlying consumer device is online. Treat all of these as upper bounds, not live inventory.

| Provider | Claimed pool | Notes |
|---|---|---|
| Bright Data | 150M+ (commonly advertised today) | Some sources cite 400M+, but 150M+ is the current standard claim; treat 400M+ as soft. City/ASN/carrier targeting across 195 countries. |
| Oxylabs | 175M+ | Across 195 countries. |
| Decodo / Smartproxy | 115–155M | |
| NetNut | 85M | |
| Webshare | 80M | |
| Rayobyte | 36–80M | |
| IPRoyal | 32M+ | Pool sourced from Pawns.app. |
| SOAX | 155M claimed / ~8.5M active | Aggregator estimates put daily reality far below the headline. |

Proxyway, which actually measures pools, [explicitly notes](https://proxyway.com/best/residential-proxies) that advertised figures "don't always reflect real-world availability, as residential IPs depend on active user devices," and its [pool-test work](https://proxyway.com/guides/proxy-pool-test) found older measurements of tens-of-millions-advertised vendors yielding only hundreds of thousands of unique IPs per run. SOAX's 155M claim is, by Proxyway's account, nowhere near daily reality. Pool freshness, rotation, and targeting granularity matter far more than the headline count. Vendor comparison context: [Bright Data vs Oxylabs](https://brightdata.com/blog/comparison/bright-data-vs-oxylabs), [IPRoyal provider list](https://iproyal.com/blog/best-residential-proxy-providers/), [Ace Proxies on active-vs-pool](https://www.aceproxies.com/proxy-blog/active-ips-vs-pool-size-the-proxy-metric-nobody-talks-about).

### Pricing model and market size

Residential is overwhelmingly priced per-GB of bandwidth; datacenter is usually per-IP or subscription; mobile is sometimes per-port-per-day. Spot prices in mid-2026: IPRoyal runs $7/GB at 1GB scaling to $1.75/GB in bulk with non-expiring traffic ([IPRoyal pricing](https://iproyal.com/pricing/residential-proxies/)); Webshare from $1.75/GB; Bright Data roughly $8.40/GB at 10GB down to about $3.30/GB at 10TB; Oxylabs $6/GB starter to $2.50/GB at 1TB ([Oxylabs pool pricing](https://oxylabs.io/pricing/residential-proxy-pool)); Rayobyte a flat $3.50/GB at low volume. Exact numbers are time-sensitive snapshots.

Market-size estimates vary by an order of magnitude depending on whether the analyst counts only vendor software revenue or bundles bandwidth resale and adjacent data-as-a-service spend. Do not present any single figure as authoritative:

- Narrow (software/subscription revenue only): [Mordor Intelligence](https://www.mordorintelligence.com/industry-reports/residential-proxy-server-market) puts the residential proxy server market at $122.03M in 2025 growing to $148.33M by 2030 at a 3.98% CAGR.
- Broader "residential proxy IP network" framings: ~$0.44B (2024) to $1.11B by 2033 at 10.5% ([Business Research Insights](https://www.businessresearchinsights.com/market-reports/residential-proxy-ip-network-market-113136)); ~$1.2B (2024) to $3.5B by 2031 at 15.8% ([Verified Market Reports](https://www.verifiedmarketreports.com/product/residential-proxy-ip-network-market/)).

These are paywalled analyst estimates with non-comparable scope definitions.

---

## Where those IPs come from

This is the heart of the matter. A "residential" IP is a real person's home or mobile connection. The supply chain that delivers those IPs to a scraper runs on a spectrum from thin consent to outright crime, and a buyer generally cannot verify where any individual IP came from.

### Tier 1: Bandwidth-sharing apps (thin consent)

Apps like Honeygain, Pawns.app (which feeds IPRoyal), Peer2Profit, PacketStream, and EarnApp pay users pennies per GB to relay strangers' traffic. Current payouts are roughly $0.30/GB on Honeygain and ~$0.20/GB on Pawns ([Honeygain payout](https://www.honeygain.com/honeygain-payout/)). (An earlier ~$0.10/GB figure is stale; the qualitative "pennies per GB" holds.) The contested part, flagged by Proxyway and security researchers, is that ordinary users rarely grasp that they become exit nodes whose IP can be attributed to whatever a paying customer does, including scraping, ad fraud, credential stuffing, or illegal content. Trend Micro frames even the consensual variant as exposing the host to [legal and security risk](https://www.trendmicro.com/en/research/23/b/hijacking-your-bandwidth-how-proxyware-apps-open-you-up-to-risk.html). See also [Proxyway on proxyware](https://proxyway.com/research/proxyware-passive-income-apps) and [IPRoyal's sourcing page](https://iproyal.com/residential-proxy-sourcing/).

### Tier 2: SDK monetization (disclosure buried or absent)

Proxy networks pay app developers to embed a resale SDK into otherwise benign free apps, enrolling the user's device with disclosure buried or missing. HUMAN Security's Satori team documented [PROXYLIB](https://www.humansecurity.com/learn/blog/satori-threat-intelligence-alert-proxylib-and-lumiapps-transform-mobile-devices-into-proxy-nodes/): 28 Android apps on Google Play, roughly 3M downloads, silently enrolling devices as proxy nodes; Google removed them, and a later version shipped publicly as the LumiApps SDK, with monetization tied to the proxy seller Asocks. This was corroborated across multiple outlets including [Help Net Security](https://www.helpnetsecurity.com/2024/03/26/smartphone-apps-proxy-network/) and [The Hacker News](https://thehackernews.com/2024/04/malicious-apps-caught-secretly-turning.html). Palo Alto Unit42 documented attackers going further, using a GeoServer CVE to silently install bandwidth-sharing apps on compromised servers with zero consent ([Unit42](https://unit42.paloaltonetworks.com/attackers-sell-your-bandwidth-using-sdks/)).

### Tier 3: Malware and botnets (no consent)

The clearest proof that "residential proxy" often means "botnet" is **911 S5**, dismantled by DOJ and FBI in May 2024 and described as likely the largest botnet ever. Verified figures from primary government sources:

- Operator YunHe Wang, a PRC national (and St. Kitts citizen-by-investment), arrested in Singapore on 2024-05-24.
- Malware spread from 2014 to July 2022 compromised millions of residential Windows machines tied to more than 19M unique IPs across nearly 200 countries, including 613,841 US IPs.
- Wang earned roughly $99M selling cybercriminals access. Seizures included 23 domains, 70+ servers, and $136.4M in crypto. He faces up to 65 years.
- The IPs were sourced without consent: malware was silently bundled into free VPN apps (MaskVPN, DewVPN, PaladinVPN, ProxyGate, ShieldVPN, ShineVPN) and pirated software.

Importantly, the often-cited ~$5.9B figure is the loss enabled *through* the botnet (about 560,000 fraudulent unemployment claims), not Wang's revenue. Do not conflate the two. Sources: [DOJ press release](https://www.justice.gov/archives/opa/pr/911-s5-botnet-dismantled-and-its-administrator-arrested-coordinated-international-operation), [FBI/IC3 PSA240529](https://www.ic3.gov/PSA/2024/PSA240529), [Treasury sanctions on Wang, Liu, and Zheng](https://home.treasury.gov/news/press-releases/jy2375), [Krebs on the mechanism](https://krebsonsecurity.com/2024/05/treasury-sanctions-creators-of-911-s5-proxy-botnet/). Note: only the arrest, charges, and sanctions are adjudicated facts; the dollar and forfeiture figures are allegations at indictment, and no guilty plea or sentence is documented as of mid-2026.

### The industry's origin is the same consent gap

The commercial industry traces to **Hola VPN / Luminati**. Luminati launched in 2014 as a division of Hola, selling access to Hola's free userbase as residential exit nodes at around $20/GB. In May 2015 an attacker used the Luminati/Hola network to DDoS 8chan, exposing that millions of free Hola users were silent, unpaid exit nodes with no real opt-out, so a paying customer's illegal traffic was attributable to a random user's home IP. Hola's founder claimed it had always disclosed this, but the explanation was added only after the backlash. Luminati was sold to EMK Capital for roughly $200M in 2017 and rebranded Bright Data. Sources: [The Register](https://www.theregister.com/2015/05/29/hola_vpn_used_8chan_takedown_botnet_or_not/), [Fortune](https://fortune.com/2015/05/29/hola-luminati-vpn/), [PCWorld](https://www.pcworld.com/article/427726/ultra-popular-hola-vpn-extension-sold-your-bandwidth-for-use-in-a-botnet-attack/), [Bright Data on Wikipedia](https://en.wikipedia.org/wiki/Bright_Data).

### The measurement and enforcement record

- **Resident Evil (IEEE S&P 2019).** Mi, Feng et al., [Resident Evil: Understanding Residential IP Proxy as a Dark Service](https://www-users.cse.umn.edu/~fengqian/paper/rpaas_sp19.pdf), detected roughly 6M residential proxy IPs across 230+ countries and 52,000+ ISPs (data spanning May 2017 to March 2018). Despite provider claims of willing participants, cross-matching against potentially-unwanted-program logs and behavioral analysis showed many proxies run on likely-compromised hosts, including IoT devices. Present 6M as a snapshot; 2024 follow-ups confirm substantial growth.
- **FBI/IC3 (March 2026).** [PSA260312](https://www.ic3.gov/PSA/2026/PSA260312) warns that residential proxy networks route traffic through compromised home and small-business networks and consumer IoT (TV streamers, picture frames, vehicle infotainment, routers), recruited via SDK "passive income" apps, free-VPN services that enroll devices without consent, malware in pirated content, and IoT compromise. It states the device's IP "can be used by threat actors to mask their online illegal activity, making the consumer appear responsible." [Companion FBI page](https://www.fbi.gov/investigate/cyber/alerts/2026/evading-residential-proxy-networks-protecting-your-devices-from-becoming-a-tool-for-criminals).
- **Vendor "ethical sourcing" claims are self-attested and unverifiable per-IP.** Bright Data documents a single-screen [opt-in consent flow](https://brightdata.com/trustcenter/sourcing) via Bright SDK; Honeygain documents a [consent-based SDK](https://sdk.honeygain.com/blog/transparent-and-ethical-ip-sourcing/). These are vendor trust-center attestations, not third-party audits. A buyer cannot verify how any individual residential IP was obtained.

One scraping-legality footnote that is often confused with the sourcing question: Bright Data won [Meta v. Bright Data](https://blog.ericgoldman.org/archives/2024/01/game-on-bright-data-scores-major-victory-in-web-scraping-dispute-with-meta-guest-blog-post.htm) (Jan 2024, Judge Chen, N.D. Cal.), holding that logged-off scraping of public data did not breach Meta's terms. That is a win about the legality of scraping public data, entirely separate from the ethics of how the IPs are sourced.

---

## The China angle

China is the single most damning case study for the privacy question, on two independent axes.

### Axis 1: The largest non-consensual networks are China-operated

Beyond 911 S5 (PRC national operator, covered above), **IPIDEA** was disrupted by Google in January 2026 and described as one of the largest residential proxy networks in the world. Verified against Google's primary [GTIG blog](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network): 600+ applications connecting to the Tier-One C2, 3,075 unique Windows binaries, roughly 7,400 Tier-Two servers, and 550+ distinct threat groups using it within a single seven-day window in January 2026, including actors from China, North Korea, Iran, and Russia. IPs were sourced via four monetization SDKs (Castar, Earn, Hex, Packet) embedded in third-party apps and via trojanized off-brand Android TV boxes linked to BADBOX 2.0; many users were enrolled with little or no real disclosure. Google sued 25 unnamed China-based entities in 2025 and obtained a January 2026 court order removing dozens of IPIDEA domains ([The Hacker News](https://thehackernews.com/2026/01/google-disrupts-ipidea-one-of-worlds.html), [Help Net Security](https://www.helpnetsecurity.com/2026/01/29/ipidea-proxy-network-disrupted/)).

One precision correction: the "Chinese company" label is defensible but imprecise relative to the primary source. Google's GTIG blog does not itself call IPIDEA a Chinese company; it lists the corporate signers as five Hong Kong-registered entities and separately attributes Chinese threat-actor usage. The "Chinese company" framing comes from secondary press. Accurate framing is **China/Hong Kong-based** (Hong Kong being a PRC SAR), not a documented clean mainland incorporation.

### Axis 2: A China exit node sits behind a national interception apparatus

A residential node physically inside China reaches the open internet through the Great Firewall, which is well-documented to perform deep packet inspection on international links, SNI/TLS fingerprinting, DNS poisoning, TCP-RST injection, and active probing of suspected circumvention services. Since July 2020 it has dropped TLS connections using the ESNI extension on all ports, with residual IP blocking lasting a few minutes ([GFW Report on ESNI blocking](https://gfw.report/blog/gfw_esni_blocking/en/), [Geneva/UMD](https://geneva.cs.umd.edu/posts/china-censors-esni/esni/), [Great Firewall on Wikipedia](https://en.wikipedia.org/wiki/Great_Firewall)). This means a China-located node inherits the same blocking that broke the friend's Tor setup, and degrades the exact encrypted-handshake privacy features you would otherwise rely on.

The exit relay's man-in-the-middle position lets it inspect non-TLS traffic and attempt SSL-stripping or rogue-certificate impersonation, and the operator inherently sees your destination, timing, and volume. Layering the GFW on top means a node inside China sits behind a state inspection apparatus in addition to the proxy operator ([arXiv 2404.10610](https://arxiv.org/pdf/2404.10610), [ACM Queue on GFW](https://queue.acm.org/detail.cfm?id=2405036)).

Two claims that need careful framing:

- **Real-time state interception of a specific commercial provider's customer traffic is a capability and a risk, not documented practice.** The GFW's DPI capability is well established, but there is no primary-source documentation of the state capturing a particular commercial residential-proxy customer's traffic in real time. Present it as risk, not proven practice.
- **Personal criminal jeopardy for a foreign buyer merely routing through a China IP is thin.** China's Cybersecurity Law, Data Security Law, and PIPL impose monitoring, retention, and data-localization obligations, but those fall on data handlers and operators inside China, not on a foreign user transiting an IP ([DLA Piper](https://www.dlapiperdataprotection.com/index.html?c=CN), [Skadden](https://www.skadden.com/insights/publications/2021/11/chinas-new-data-security-and-personal-information-protection-laws)). PIPL is extraterritorial and its Article 41 prohibits handlers from providing PRC-stored data to foreign law enforcement without PRC approval, effective Nov 1, 2021 ([PIPL Article 41](https://personalinformationprotectionlaw.com/PIPL/article-41/), [Gibson Dunn](https://www.gibsondunn.com/china-passes-the-personal-information-protection-law-to-take-effect-on-november-1/)). The 2017 MIIT notice bars enterprises from setting up unauthorized cross-border lines or VPNs, and enforcement targets providers and sellers; individual administrative fines are small and sporadic, reported around 100 to 1,000 yuan (roughly $15 to $150) ([UW JSIS](https://jsis.washington.edu/eacenter/2017/04/17/chinas-new-cybersecurity-regulations-analyzing-ban-vpn-services/), [Law.asia](https://law.asia/vpn-compliance-china/)).

The net for the friend using China-based proxies: it is strictly worse on the trust axis. The intermediary is in an adversarial, monitored jurisdiction designed for inspection, the exit node is very likely a compromised stranger device, and the confidentiality exposure for whatever data you move is real even if your personal criminal jeopardy is low. The legal exposure that does bite falls on providers and on the data, not on you as a routing customer.

---

## Does using a residential proxy kill your privacy guarantees?

Yes. A residential proxy is a trust-shift, not a privacy gain.

Here is the architecture. The provider's gateway sits in-path for every request: your client authenticates to the gateway, the gateway picks an exit and forwards, the response returns through the gateway. So the provider sees your real source identity (your authenticated account or API key), your destination, timing, and volume for all of your traffic, and can trivially correlate every session to your billing identity. You gain IP-hiding from the destination website. You lose anonymity to the provider. This is the same single-entity-sees-everything weakness as a VPN, and the OHTTP literature names it directly: in VPN or traditional HTTP proxy models, a single entity can see identifying information about the user and all of their activity ([Cloudflare OHTTP](https://blog.cloudflare.com/stronger-than-a-promise-proving-oblivious-http-privacy-properties/), [Oxylabs on residential proxies](https://oxylabs.io/blog/what-is-residential-proxy)).

There is no cryptographic unlinkability. The provider can de-anonymize you unilaterally, with no collusion and no global adversary required. That is the defining feature that Tor, OHTTP, and PIR provide and that a proxy categorically lacks.

A common rebuttal is "but it's HTTPS, so the provider can't see anything." That is half right and the half it gets wrong matters:

- With a plain HTTP CONNECT tunnel (the standard commercial mode), the provider reads the CONNECT destination, the cleartext TLS SNI in the ClientHello, and timing and volume metadata. It cannot read the encrypted body. So your content is protected, but who you talk to, when, and how much leaks regardless.
- Decryption of content is possible only if the gateway runs an active man-in-the-middle: it issues its own CA and you trust that cert (the [mitmproxy](https://docs.mitmproxy.org/stable/concepts/how-mitmproxy-works/) / [PolarProxy](https://blog.apnic.net/2021/08/03/decrypting-tls-traffic-with-polarproxy/) / [Cisco SSL-proxy](https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/security/ios-xe-17/security-book-xe/m-ssl-proxy.html) pattern). This is a real capability, but it is not the default commercial mode. Treat "the gateway can decrypt my content" as conditional, and treat "the gateway sees my metadata and destinations" as a given.

And the exit host is a real third party who, per Resident Evil, 911 S5, PROXYLIB, IPIDEA, and the FBI's March 2026 PSA, very likely never knowingly consented. Their home router and ISP can observe the destination and metadata of traffic leaving their connection, and your activity is attributed to their IP. So you gain plausible IP-attribution confusion at the cost of riding a coercive or criminal supply chain. The inverse risk is worth stating plainly: if you yourself run a "passive income" bandwidth-sharing app, strangers' traffic, including the criminal traffic the FBI describes, exits via your home IP and is attributed to you, which is how innocent people end up with subpoenas and law-enforcement visits.

### Trust-model comparison

This table shows which guarantee survives in each model. The column that matters most is "unlinkability," because that is the property the corpus is trying to preserve and the one a proxy destroys.

| Model | Who sees your source IP | Who sees your destination/content | Cryptographic unlinkability | What it takes to de-anonymize you |
|---|---|---|---|---|
| **Tor** | First relay sees IP, not destination | Exit sees destination (content if not E2E TLS), not your IP | Yes (no single relay sees both ends) | Global passive adversary or end-to-end timing correlation |
| **VPN** | The VPN provider | The VPN provider | No | The provider alone (single trusted party) |
| **OHTTP / Private Relay** | Relay sees IP, only ciphertext | Gateway sees plaintext, only the relay's IP | Yes (split across two parties) | Collusion of two independently-operated parties |
| **PIR** | N/A to query content | Server learns nothing about which record you fetch | Yes (query privacy by construction) | Holds even against a malicious server |
| **Residential proxy** | The provider (linked to your billing identity) + the exit host's ISP | The provider (metadata always; content if MITM CA) | No | The provider alone, unilaterally |

Sources for the comparison: [RFC 9458 (OHTTP)](https://www.ietf.org/rfc/rfc9458.html), [Cloudflare OHTTP proof](https://blog.cloudflare.com/stronger-than-a-promise-proving-oblivious-http-privacy-properties/), [Oblivious HTTP on Wikipedia](https://en.wikipedia.org/wiki/Oblivious_HTTP), [Private Information Retrieval on Wikipedia](https://en.wikipedia.org/wiki/Private_information_retrieval), [PIR in CACM](https://cacm.acm.org/research/private-information-retrieval/).

### Bottom line

**Using a residential proxy service kills the anonymity guarantees you were trying to get. It does not anonymize you; it relocates the party who can see everything from your ISP and the destination site to a commercial intermediary who links every request to your billing identity, who can log and (with a MITM cert) potentially decrypt your traffic, and who provides none of the cryptographic unlinkability that Tor, OHTTP, and PIR are built to provide. You trade IP-reputation evasion for a new, fully-trusted third party, and you very likely route through a stranger's non-consenting (often compromised) device whose owner inherits the legal blast radius. A China-based residential proxy is strictly the worst version of this trade: an adversarial, monitored jurisdiction on top of the same single-trusted-party exposure. Residential proxies optimize for evading server-side blocking. They are an anonymity anti-pattern.**

---

## Sources

- [check.torproject.org/torbulkexitlist](https://check.torproject.org/torbulkexitlist)
- [Tor Metrics](https://metrics.torproject.org/)
- [FireHOL tor_exits ipset](https://iplists.firehol.org/?ipset=tor_exits)
- [Cloudflare, The Trouble with Tor](https://blog.cloudflare.com/the-trouble-with-tor/)
- [Tor Project, The Trouble with CloudFlare](https://blog.torproject.org/trouble-cloudflare/)
- [NDSS 2016, Do You See What I See?](https://www.ndss-symposium.org/wp-content/uploads/2017/09/do-you-see-what-i-see-differential-treatment-anonymous-users.pdf)
- [USENIX Security 2017, Characterizing the Nature and Dynamics of Tor Exit Blocking](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/singh)
- [SearXNG limiter docs](https://docs.searxng.org/admin/searx.limiter.html)
- [SearXNG CAPTCHA docs](https://docs.searxng.org/admin/answer-captcha.html)
- [SearXNG settings.yml](https://github.com/searxng/searxng/blob/master/searx/settings.yml)
- [SearXNG issue #2515](https://github.com/searxng/searxng/issues/2515)
- [SearXNG issue #5286](https://github.com/searxng/searxng/issues/5286)
- [SearXNG issue #5768](https://github.com/searxng/searxng/issues/5768)
- [SearXNG issue #5867](https://github.com/searxng/searxng/issues/5867)
- [Webshare, datacenter vs residential](https://www.webshare.io/blog/datacenter-vs-residential-proxies)
- [Apify, datacenter vs residential vs ISP](https://use-apify.com/blog/datacenter-vs-residential-vs-isp-proxies)
- [Oxylabs, datacenter vs residential](https://oxylabs.io/blog/the-difference-between-data-center-and-residential-proxies)
- [Infatica, ISP proxies vs residential](https://infatica.io/blog/isp-proxies-vs-residential-proxies/)
- [Oxylabs mobile proxies](https://oxylabs.io/products/mobile-proxies)
- [Multilogin, best mobile proxies](https://multilogin.com/blog/best-mobile-proxies/)
- [Apify, IPRoyal pricing 2026](https://use-apify.com/blog/iproyal-pricing-plans-2026)
- [IPRoyal residential pricing](https://iproyal.com/pricing/residential-proxies/)
- [AIMultiple proxy pricing](https://aimultiple.com/proxy-pricing)
- [Oxylabs residential pool pricing](https://oxylabs.io/pricing/residential-proxy-pool)
- [Proxyway, best residential proxies](https://proxyway.com/best/residential-proxies)
- [Proxyway, proxy pool test](https://proxyway.com/guides/proxy-pool-test)
- [Bright Data vs Oxylabs](https://brightdata.com/blog/comparison/bright-data-vs-oxylabs)
- [IPRoyal, best residential proxy providers](https://iproyal.com/blog/best-residential-proxy-providers/)
- [Ace Proxies, active IPs vs pool size](https://www.aceproxies.com/proxy-blog/active-ips-vs-pool-size-the-proxy-metric-nobody-talks-about)
- [Mordor Intelligence, residential proxy server market](https://www.mordorintelligence.com/industry-reports/residential-proxy-server-market)
- [Business Research Insights, residential proxy IP network market](https://www.businessresearchinsights.com/market-reports/residential-proxy-ip-network-market-113136)
- [Verified Market Reports, residential proxy IP network market](https://www.verifiedmarketreports.com/product/residential-proxy-ip-network-market/)
- [Honeygain payout](https://www.honeygain.com/honeygain-payout/)
- [Trend Micro, hijacking your bandwidth](https://www.trendmicro.com/en/research/23/b/hijacking-your-bandwidth-how-proxyware-apps-open-you-up-to-risk.html)
- [Proxyway, proxyware passive income apps](https://proxyway.com/research/proxyware-passive-income-apps)
- [IPRoyal residential proxy sourcing](https://iproyal.com/residential-proxy-sourcing/)
- [HUMAN Security, PROXYLIB and LumiApps](https://www.humansecurity.com/learn/blog/satori-threat-intelligence-alert-proxylib-and-lumiapps-transform-mobile-devices-into-proxy-nodes/)
- [Help Net Security, smartphone apps proxy network](https://www.helpnetsecurity.com/2024/03/26/smartphone-apps-proxy-network/)
- [The Hacker News, malicious apps turning devices into proxies](https://thehackernews.com/2024/04/malicious-apps-caught-secretly-turning.html)
- [Palo Alto Unit42, attackers sell your bandwidth using SDKs](https://unit42.paloaltonetworks.com/attackers-sell-your-bandwidth-using-sdks/)
- [DOJ, 911 S5 botnet dismantled](https://www.justice.gov/archives/opa/pr/911-s5-botnet-dismantled-and-its-administrator-arrested-coordinated-international-operation)
- [FBI/IC3 PSA240529 (911 S5)](https://www.ic3.gov/PSA/2024/PSA240529)
- [Treasury sanctions on 911 S5 creators](https://home.treasury.gov/news/press-releases/jy2375)
- [Krebs on Security, 911 S5 sanctions](https://krebsonsecurity.com/2024/05/treasury-sanctions-creators-of-911-s5-proxy-botnet/)
- [The Hacker News, US dismantles 911 S5](https://thehackernews.com/2024/05/us-dismantles-worlds-largest-911-s5.html)
- [The Register, Hola VPN / 8chan](https://www.theregister.com/2015/05/29/hola_vpn_used_8chan_takedown_botnet_or_not/)
- [Fortune, Hola / Luminati](https://fortune.com/2015/05/29/hola-luminati-vpn/)
- [PCWorld, Hola VPN sold your bandwidth](https://www.pcworld.com/article/427726/ultra-popular-hola-vpn-extension-sold-your-bandwidth-for-use-in-a-botnet-attack/)
- [Bright Data on Wikipedia](https://en.wikipedia.org/wiki/Bright_Data)
- [Meta v. Bright Data analysis (Eric Goldman)](https://blog.ericgoldman.org/archives/2024/01/game-on-bright-data-scores-major-victory-in-web-scraping-dispute-with-meta-guest-blog-post.htm)
- [Resident Evil (IEEE S&P 2019)](https://www-users.cse.umn.edu/~fengqian/paper/rpaas_sp19.pdf)
- [FBI/IC3 PSA260312 (residential proxy networks)](https://www.ic3.gov/PSA/2026/PSA260312)
- [FBI, evading residential proxy networks](https://www.fbi.gov/investigate/cyber/alerts/2026/evading-residential-proxy-networks-protecting-your-devices-from-becoming-a-tool-for-criminals)
- [Bright Data trust center, sourcing](https://brightdata.com/trustcenter/sourcing)
- [Bright SDK ethical monetization](https://brightdata.com/trustcenter/bright-sdk-ethical-monetization-data-privacy)
- [Honeygain SDK, transparent and ethical IP sourcing](https://sdk.honeygain.com/blog/transparent-and-ethical-ip-sourcing/)
- [Google GTIG, disrupting largest residential proxy network (IPIDEA)](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [The Hacker News, Google disrupts IPIDEA](https://thehackernews.com/2026/01/google-disrupts-ipidea-one-of-worlds.html)
- [Help Net Security, IPIDEA proxy network disrupted](https://www.helpnetsecurity.com/2026/01/29/ipidea-proxy-network-disrupted/)
- [Great Firewall on Wikipedia](https://en.wikipedia.org/wiki/Great_Firewall)
- [GFW Report, ESNI blocking](https://gfw.report/blog/gfw_esni_blocking/en/)
- [Geneva/UMD, China censors ESNI](https://geneva.cs.umd.edu/posts/china-censors-esni/esni/)
- [GFW Report, USENIX Security 2025](https://gfw.report/publications/usenixsecurity25/en/)
- [arXiv 2404.10610](https://arxiv.org/pdf/2404.10610)
- [ACM Queue, the collateral damage of internet censorship](https://queue.acm.org/detail.cfm?id=2405036)
- [DLA Piper data protection, China](https://www.dlapiperdataprotection.com/index.html?c=CN)
- [Skadden, China data security and PIPL](https://www.skadden.com/insights/publications/2021/11/chinas-new-data-security-and-personal-information-protection-laws)
- [PIPL Article 41](https://personalinformationprotectionlaw.com/PIPL/article-41/)
- [Gibson Dunn, China passes PIPL](https://www.gibsondunn.com/china-passes-the-personal-information-protection-law-to-take-effect-on-november-1/)
- [UW JSIS, China cybersecurity regulations VPN ban](https://jsis.washington.edu/eacenter/2017/04/17/chinas-new-cybersecurity-regulations-analyzing-ban-vpn-services/)
- [Law.asia, VPN compliance in China](https://law.asia/vpn-compliance-china/)
- [RFC 9458, Oblivious HTTP](https://www.ietf.org/rfc/rfc9458.html)
- [Cloudflare, proving OHTTP privacy properties](https://blog.cloudflare.com/stronger-than-a-promise-proving-oblivious-http-privacy-properties/)
- [Oblivious HTTP on Wikipedia](https://en.wikipedia.org/wiki/Oblivious_HTTP)
- [Private Information Retrieval on Wikipedia](https://en.wikipedia.org/wiki/Private_information_retrieval)
- [PIR in CACM](https://cacm.acm.org/research/private-information-retrieval/)
- [Oxylabs, what is a residential proxy](https://oxylabs.io/blog/what-is-residential-proxy)
- [mitmproxy, how it works](https://docs.mitmproxy.org/stable/concepts/how-mitmproxy-works/)
- [PolarProxy, decrypting TLS traffic](https://blog.apnic.net/2021/08/03/decrypting-tls-traffic-with-polarproxy/)
- [Cisco SSL proxy](https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/security/ios-xe-17/security-book-xe/m-ssl-proxy.html)
