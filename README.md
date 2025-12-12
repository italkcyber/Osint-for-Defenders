# OSINT Web-Based Tools Catalog

A curated list of web-based tools, browser extensions, and services to support defenders and investigators with discovery, enrichment, and analysis.

## Table of Contents

- [Browser Extensions](#browser-extensions)
- [VPN](#vpn)
- [Encoding / Decoding](#encoding--decoding)
- [Investigations](#investigations)
- [Browser Isolation](#browser-isolation)
- [Acquisitions](#acquisitions)
- [Autonomous System Numbers (ASN)](#autonomous-system-numbers-asn)
- [Apex Domains](#apex-domains)
- [Subdomains](#subdomains)
- [Service Discovery](#service-discovery)
- [Data Exposure](#data-exposure)
- [Third-Party & Brand Misuse](#third-party--brand-misuse)

---

## Browser Extensions

| Tool | Type | Purpose |
|:-----|:-----|:--------|
| [Instant Data Scraper](https://chromewebstore.google.com/detail/instant-data-scraper/ofaokhiedipichpaobibbnahnkdoiiah?hl=en&pli=1) | Free | Scrape tabular data from web pages to CSV/Excel. |
| [Open Multiple URLs](https://chromewebstore.google.com/detail/open-multiple-urls/oifijhaokejakekmnjmphonojcfkpbbh) | Free | Open a list of URLs in new tabs. |
| [User Agent Switcher](https://chromewebstore.google.com/detail/user-agent-switcher-and-m/bhchdcejhohfmigjafbampogmaanbfkg) | Free | Spoof/change browser user-agent. |
| [Link Gopher](https://chromewebstore.google.com/detail/link-gopher/bpjdkodgnbfalgghnbeggfbfjpcfamkf) | Free | Extract and deduplicate all links on a page. |
| [TruffleHog](https://chromewebstore.google.com/detail/trufflehog/bafhdnhjnlcdbjcdcnafhdcphhnfnhjc) | Free | Detect exposed credentials on pages you visit. |
| [Clear Cache](https://chromewebstore.google.com/detail/clear-cache/cppjkneekbjaeellbfkmgnhonkkjfpdn?hl) | Free | One-click browser cache clearing. |
| [Wappalyzer](https://www.wappalyzer.com/apps/) | Free | Detect site technologies from the browser. |

---

## VPN

| Tool | Type | Purpose |
|:-----|:-----|:--------|
| [NordVPN](https://refer-nordvpn.com/onoJadKqUxW) | Free (referral) | General-purpose VPN provider. |
| [Surfshark](https://surfshark.club/friend/9mGyGfuL) | Free (referral) | General-purpose VPN provider. |

---

## Encoding / Decoding

| Tool | Type | Purpose |
|:-----|:-----|:--------|
| [CyberChef](https://cyberchef.org/) | Free | Encoding, decoding, data transformation and analysis. |

---

## Investigations

| Tool | Type | Purpose |
|:-----|:-----|:--------|
| [OSINT Tracker](https://www.osintracker.com) | Free | Track OSINT cases, tasks and artefacts. |

---

## Browser Isolation

| Tool | Type | Purpose |
|:-----|:-----|:--------|
| [Kasm](https://kasm.com/) | Paid | Browser/container isolation platform. |
| [Browserling](https://browserling.com) | Free / Paid | Online browser sandbox and testing. |

---

## Acquisitions

| Tool | Type | Inputs (Seeds) | Outputs (Identifiers) |
|:-----|:-----|:----------------|:-----------------------|
| [Crunchbase](https://www.crunchbase.com) | Free | Company | Website, domain, parent company, acquisitions. |
| [OCCRP Aleph](https://aleph.occrp.org) | Free | Company, domain | Acquisitions, trademarks. |
| [GitHub MA001](https://github.com/italkcyber/Osint-for-Defenders/blob/main/AI/Prompt/MA001) | Free | Company, website, date range | Company, website, acquisition status. |

---

## Autonomous System Numbers (ASN)

| Tool | Type | Inputs (Seeds) | Outputs (Identifiers) |
|:-----|:-----|:----------------|:-----------------------|
| [BGP](https://bgp.he.net) | Free (Global) | ASN, IP, company, keyword | ASN, ASN name, CIDR, WHOIS org and technical contact details. |
| [RIPE DB](https://apps.db.ripe.net/db-web-ui/fulltextsearch) | Free (EU) | Company, ASN, IP, email, keyword | ASN, CIDR, company, WHOIS, email, person, address. |
| [ARIN](https://whois.arin.net/ui/query.do) | Free (US) | Company, ASN, IP, email, keyword | ASN, CIDR, company, WHOIS, email, person, address. |

---

## Apex Domains

### Whois

| Tool | Type | Inputs (Seeds) | Outputs (Identifiers) |
|:-----|:-----|:----------------|:-----------------------|
| [OnlineDnsLookup – Bulk Whois](https://www.onlinednslookup.com/bulk-domain-whois/) | Free | Domain list | Register/expiry dates, registrar, registrant, name servers. |
| [ViewDNS – Whois](https://viewdns.info/whois/?domain) | Free | Domain | Register/expiry dates, registrar, registrant, name servers. |

### Whois History & Reverse Whois

| Tool | Type | Inputs (Seeds) | Outputs (Identifiers) |
|:-----|:-----|:----------------|:-----------------------|
| [Bigdomaindata – Whois History](https://www.bigdomaindata.com/whois-history/) | Free | Domain | Historic WHOIS, registrant, email, similar/fuzzy domains, typosquatting. |
| [Whoxy – Reverse Whois](https://www.whoxy.com/reverse-whois/) | Free | Registrant name, email, company | Domains, registrar, created/expiry dates. |
| [WhoisXMLAPI – Reverse Whois](https://tools.whoisxmlapi.com/reverse-whois-search) | Free Credits / Paid | Domain, organisation, registrant/admin email | Domains linked to seed. |
| [Bigdomaindata – Reverse Whois](https://www.bigdomaindata.com/reverse-whois/) | Free | Domain, keyword, registrant, email, company, address, name server | Domains plus WHOIS timeline and registrant data. |
| [Host.io](https://host.io/) | Free | Domain | Analytics IDs, DNS records, co-hosted domains, backlinks, redirects. |

### Reverse IP / NS / MX

| Tool | Type | Inputs (Seeds) | Outputs (Identifiers) |
|:-----|:-----|:----------------|:-----------------------|
| [DNSLytics](https://search.dnslytics.com/) | Free | Domain, keyword, IP, CIDR, MX, tags | ASN, IP, domain, reverse MX/NS, analytics tags. |

---

## Subdomains

| Tool | Type | Inputs (Seeds) | Outputs (Identifiers) |
|:-----|:-----|:----------------|:-----------------------|
| [crt.sh](https://crt.sh) | Free | Domain, company, SSL org | Domains, subdomains, cert CN, identity, issuer. |
| [C99 Subdomain Finder](https://subdomainfinder.c99.nl) | Free | Domain | Subdomains, IPs. |
| [ViewDNS – Subdomains](https://viewdns.info/subdomains/?domain=) | Free | Domain | Subdomains, IPs. |
| [HackerTarget – DNS Host Records](https://hackertarget.com/find-dns-host-records/) | Free | Domain | Host records, subdomains, IPs. |
| [VirusTotal](https://www.virustotal.com/gui/home/search) | Free | Domain, subdomain, IP, hash | Related domains, subdomains, IPs, historical IPs. |
| [VirusTotal Domain API]<br>https://www.virustotal.com/vtapi/v2/domain/report?apikey=Enter_APIKEY&domain=EXAMPLE.COM | Domain| Domain, API key | Domains, subdomains, IPs, historical IPs, hashes, URLs. |
| [VirusTotal IP API]<br>https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=Enter_APIKey&ip=Enter_IP | Domain| IP, API key | Domains, subdomains, IPs, historical IPs, hashes, URLs. |
| [SecurityTrails – Subdomains](https://securitytrails.com/list/keyword) | Free | Domain, keyword | Subdomains for given keyword/domain. |

---

## Service Discovery

### Search Engines & Banners

| Tool | Type | Inputs (Seeds) | Outputs (Identifiers) |
|:-----|:-----|:----------------|:-----------------------|
| [Shodan – Advanced Search](https://www.shodan.io/search/advanced) | Free | ASN, IP, CIDR, port, domain, subdomain, SSL, favicon, OS, website title, product, country | ASN, IP, original IP, port, domain, subdomain, technology, SSL, fraudulent websites, country, favicon |
| [Shodan – Facet Search](https://www.shodan.io/search/facet) | Free | ASN, IP, CIDR, port, domain, subdomain, SSL, favicon, OS, website title, product, country | ASN, IP, original IP, port, domain, subdomain, technology, SSL, fraudulent websites, country, favicon|
| [FOFA](https://en.fofa.info/) | Free | ASN, IP, CIDR, port, domain, headers, body, favicon, SSL | Hosts, technologies, suspected fraudulent sites. |
| [Zoomeye](https://www.zoomeye.ai) | Free | ASN, IP, CIDR, port, domain, headers, body, favicon, SSL | Hosts, technologies, suspected fraudulent sites. |

### Reverse IP & Historical IP

| Tool | Type | Inputs (Seeds) | Outputs (Identifiers) |
|:-----|:-----|:----------------|:-----------------------|
| [ViewDNS – Reverse IP](https://viewdns.info/reverseip/?host=&t=1) | Free | IP | Domains and subdomains on IP. |
| [SecurityTrails – Reverse IP](https://securitytrails.com/list/keyword) | Free | IP | Domains and subdomains on IP. |
| [WhoisXMLAPI – Reverse IP](https://reverse-ip.whoisxmlapi.com/lookup) | Free | IP | Domains on IP with first/last seen dates. |
| [SecurityTrails – Historical IP](https://securitytrails.com/list/keyword) | Free | Domain, subdomain | Historical IPs, org, first/last seen. |

### Technology Profiling

| Tool | Type | Inputs (Seeds) | Outputs (Identifiers) |
|:-----|:-----|:----------------|:-----------------------|
| [Wappalyzer](https://www.wappalyzer.com/apps/) | Free | URL | Server stack, frameworks, CMS, analytics. |
| [WebTechSurvey](https://webtechsurvey.com/) | Free | URL | Technologies, redirects, IP, reverse IP, ASN, linked domains, tech changes. |

### DNS / SPF / Tenant Intelligence

| Tool | Type | Inputs (Seeds) | Outputs (Identifiers) |
|:-----|:-----|:----------------|:-----------------------|
| [ThreatYeti](https://threatyeti.com/) | Free | Domain, URL, IP | IPs, shared IPs, subdomains, redirects, inbound/outbound links. |
| [TenantIDLookup](https://tenantidlookup.com) | Free | Domain, tenant ID, UPN, URL | Azure AD tenant ID, default domain, org name, region, MX. |
| [SPF-Record](https://www.spf-record.com/spf-lookup) | Free | Domain, subdomain | SPF IPs, third-party senders, domains. |
| [OnlineDnsLookup – Bulk DNS](https://www.onlinednslookup.com/bulk-dns-lookup/) | Free | Domains, subdomains | ASN, ASN org, IPs, CNAMEs. |

### Ports / Online Checks

| Tool | Type | Inputs (Seeds) | Outputs (Identifiers) |
|:-----|:-----|:----------------|:-----------------------|
| [DNSChecker – Port Scanner](https://dnschecker.org/port-scanner.php) | Free | Domain, hostname, IP | Port open/closed state. |

---

## Data Exposure

### Archive.org

| Tool | Type | Inputs (Seeds) | Outputs (Identifiers) |
|:-----|:-----|:----------------|:-----------------------|
| [Wayback Machine](https://web.archive.org/web/*/example.com*) | Free | Domain, subdomain | Historic site content, files, configs, secrets, emails. |
| [Wayback CDX API]<br>https://web.archive.org/cdx/search/cdx?url=*.EXAMPLE.COM/*&collapse=urlkey&output=text&fl=original | Free | Domain, date, keyword | Historic URLs for further inspection. |
| [Wayback CDX Filtered]<br>https://web.archive.org/cdx/search/cdx?url=*.EXAMPLE.COM/*&collapse=urlkey&output=text&from=2024&to=2025&filter=statuscode:(200)&fl=original&filter=original:.*\.(xls|sql|doc|ppt|zip|tar|gz|tgz|bak|7z|rar|log|cache|secret|db|backup|git|config|csv|bat|env|crt|pem|DS_Store|token|auth|password|login|admin|@|%40|apikey|api_key|dashboard|console|asc) | Free | Domain, date, keyword (with file/extension filters) | Filtered historic URLs likely containing sensitive files/secrets. |

### Google Dorking & Code Repos

| Tool | Type | Inputs (Seeds) | Outputs (Identifiers) |
|:-----|:-----|:----------------|:-----------------------|
| [Google](https://www.google.com/) | Free | Dork, keyword | Domains, URLs, documents, files. |
| [Ultimate Google Dork Generator](https://tools.fluxxset.com/Ultimate-Google-Dork-Generator/) | Free | Dork, keyword | Generated dorks to use in Google. |
| [Exploit-DB GHDB](https://www.exploit-db.com/google-hacking-database) | Free | Dork, keyword | Curated dorks for sensitive content. |
| [Pentest-Tools Google Hacking](https://pentest-tools.com/information-gathering/google-hacking) | Free | Dork, keyword | Automated Google dorking for targets. |
| [Postman via Google](https://www.google.com/) | Free | `site:documenter.getpostman.com <keyword>` | Public Postman docs, APIs, potential secrets/code. |
| [GitHub](https://github.com/search) | Free | Dork, keywords | API keys, tokens, secrets, code, files. |
| [Sourcegraph](https://sourcegraph.com/search) | Free | Dork, keywords | API keys, tokens, secrets, code, files. |

### Cloud Buckets & Shorteners

| Tool | Type | Inputs (Seeds) | Outputs (Identifiers) |
|:-----|:-----|:----------------|:-----------------------|
| [GrayHatWarfare – Buckets](https://buckets.grayhatwarfare.com) | Free | Domain, company, keywords | Exposed buckets, file listings, URLs, secrets. |
| [GrayHatWarfare – Shorteners](https://shorteners.grayhatwarfare.com) | Free | Domain, company, keywords | Shortened URLs and resolved targets. |

---

## Third-Party & Brand Misuse

| Tool | Type | Inputs (Seeds) | Outputs (Identifiers) |
|:-----|:-----|:----------------|:-----------------------|
| [URLScan](https://urlscan.io/search) | Free | Domain, URL, IP, hash, title, keyword | Subdomains, IPs, third-party use, clones, typosquats. |
| [KMSec – Favicon Hash](https://favicon-hash.kmsec.uk/) | Free | URL, filename, hash | Sites sharing favicon hash (similar/clone sites). |
| [BuiltWith](https://builtwith.com) | Free | Domain, subdomain, keyword | Tech stack, GTM/GA IDs, clones, historical IPs. |
| [Google – Trademark/Copyright](https://www.google.com) | Free | Dork, trademark, copyright (e.g. `"Example © 2025" -www`) | URLs, domains/subdomains using specified mark. |
| [Bigdomaindata – Similar Domains](https://www.bigdomaindata.com/similar-domains) | Free | Domain, keyword | Similar domains, typosquats. |
| [Bigdomaindata – Fuzzy Domains](https://www.bigdomaindata.com/fuzzy-domains/) | Free | Domain | Fuzzy/typo variants (typosquats). |
| [Copyscape](https://www.copyscape.com/) | Free | URL, text | Plagiarised or cloned websites. |

