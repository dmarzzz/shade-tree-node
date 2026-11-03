# Sample run, 2026-11-03 05:14Z (5 sites, 2 passes, smoke test of this harness)

80 cells: 2 exit(s) x 4 client(s) x 5 site(s), 2 pass(es), 2026-11-03T05:14:40.792Z to 2026-11-03T05:25:28.407Z.
Cells are ok/n. chl = blocked-challenge, cap = captcha, 403 = blocked-403, 429 = blocked-429, to = timeout, err = error, unv = unverified; ':2' is a count.

## Summary: share of cells ok

| client | datacenter | shadenet |
|---|---|---|
| curl | 6/10 (60%) | 6/10 (60%) |
| node | 6/10 (60%) | 4/10 (40%) |
| headless | 7/10 (70%) | 4/10 (40%) |
| headed | 5/10 (50%) | 6/10 (60%) |

## By wall (anti-bot vendor in front of the site)

| wall | client | datacenter | shadenet |
|---|---|---|---|
| akamai | curl | 2/2 | 2/2 |
| akamai | node | 2/2 | 1/2 err |
| akamai | headless | 2/2 | 1/2 err |
| akamai | headed | 2/2 | 2/2 |
| aws-waf | curl | 0/2 chl:2 | 0/2 chl:2 |
| aws-waf | node | 0/2 chl:2 | 0/2 chl:2 |
| aws-waf | headless | 1/2 chl | 0/2 chl:2 |
| aws-waf | headed | 0/2 chl:2 | 1/2 unv |
| none | curl | 4/4 | 4/4 |
| none | node | 4/4 | 3/4 err |
| none | headless | 4/4 | 3/4 err |
| none | headed | 3/4 err | 3/4 err |
| own-asn | curl | 0/2 403:2 | 0/2 403,err |
| own-asn | node | 0/2 403:2 | 0/2 403,err |
| own-asn | headless | 0/2 403:2 | 0/2 403,err |
| own-asn | headed | 0/2 403:2 | 0/2 err:2 |

## Per site, client = curl

| tier | site | wall | datacenter | shadenet |
|---|---|---|---|---|
| web | amazon | aws-waf | 0/2 chl:2 | 0/2 chl:2 |
| web | hn | none | 2/2 | 2/2 |
| web | nike | akamai | 2/2 | 2/2 |
| web | reddit | own-asn | 0/2 403:2 | 0/2 403,err |
| web | wikipedia | none | 2/2 | 2/2 |

## Per site, client = node

| tier | site | wall | datacenter | shadenet |
|---|---|---|---|---|
| web | amazon | aws-waf | 0/2 chl:2 | 0/2 chl:2 |
| web | hn | none | 2/2 | 1/2 err |
| web | nike | akamai | 2/2 | 1/2 err |
| web | reddit | own-asn | 0/2 403:2 | 0/2 403,err |
| web | wikipedia | none | 2/2 | 2/2 |

## Per site, client = headless

| tier | site | wall | datacenter | shadenet |
|---|---|---|---|---|
| web | amazon | aws-waf | 1/2 chl | 0/2 chl:2 |
| web | hn | none | 2/2 | 1/2 err |
| web | nike | akamai | 2/2 | 1/2 err |
| web | reddit | own-asn | 0/2 403:2 | 0/2 403,err |
| web | wikipedia | none | 2/2 | 2/2 |

## Per site, client = headed

| tier | site | wall | datacenter | shadenet |
|---|---|---|---|---|
| web | amazon | aws-waf | 0/2 chl:2 | 1/2 unv |
| web | hn | none | 1/2 err | 1/2 err |
| web | nike | akamai | 2/2 | 2/2 |
| web | reddit | own-asn | 0/2 403:2 | 0/2 err:2 |
| web | wikipedia | none | 2/2 | 2/2 |

## Page time, seconds (p50 / p90, all cells that returned a status)

| client | datacenter | shadenet |
|---|---|---|
| curl | 0.1 / 0.6 | 3.2 / 17.2 |
| node | 0.1 / 0.5 | 3.2 / 17.9 |
| headless | 6.5 / 7.1 | 16.7 / 32.8 |
| headed | 6.4 / 7.2 | 12.6 / 36.6 |

## Dial time through the exit, seconds (tunnel open = CONNECT 200 or SOCKS ready, then TLS)

| exit | phase | n | failed | tunnel p50 | tunnel max | total p50 | total max |
|---|---|---|---|---|---|---|---|
| shadenet | cold | 1 | 0 | 1.2 | 1.2 | 2.4 | 2.4 |
| shadenet | warm | 4 | 0 | 0.4 | 4.3 | 0.9 | 4.8 |

## Provenance

- `datacenter-20261103T0514`: exit `datacenter` (datacenter, direct): AS24940 Hetzner Online GmbH, DE. clients curl,node,headless,headed, passes 2, started 2026-11-03T05:14:39.487Z. harness c8aea38db1fe+dirty, node v24.14.0, chromium 156.0.8078.4, curl 8.5.0 (x86_64-pc-linux-gnu) libcurl/8.5.0 OpenSSL/3.0.13 zlib/1.3 brotli/1.1.0 zstd/1.5.5 libidn2/2.3.7 libpsl/0.21.2 (+libidn2/2.3.7) libssh/0.10.6/openss. host 16 x AMD EPYC-Rome Processor, linux 6.8.0-100-generic.
- `shadenet-20261103T0514`: exit `shadenet` (shadenet, http://127.0.0.1:8888): AS14061 DigitalOcean, LLC, GB. clients curl,node,headless,headed, passes 2, started 2026-11-03T05:14:40.489Z. harness c8aea38db1fe+dirty, node v24.14.0, chromium 156.0.8078.4, curl 8.5.0 (x86_64-pc-linux-gnu) libcurl/8.5.0 OpenSSL/3.0.13 zlib/1.3 brotli/1.1.0 zstd/1.5.5 libidn2/2.3.7 libpsl/0.21.2 (+libidn2/2.3.7) libssh/0.10.6/openss. host 16 x AMD EPYC-Rome Processor, linux 6.8.0-100-generic.

