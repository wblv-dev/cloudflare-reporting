"""
remediation.py — Remediation guidance for audit findings.

Maps check labels/grades to actionable fix instructions. Used by the
reporter to generate the Remediations tab in the HTML dashboard.
"""

from typing import Dict, List


# ── Tooltips for technical terms ─────────────────────────────────────────────

TOOLTIPS = {
    "SSL mode": "Controls how Cloudflare connects to your origin server. 'Full (strict)' validates the origin's SSL certificate.",
    "Minimum TLS version": "The oldest TLS protocol version allowed. TLS 1.0 and 1.1 have known vulnerabilities and are deprecated.",
    "TLS 1.3": "The latest TLS protocol version, offering faster handshakes and improved forward secrecy.",
    "Automatic HTTPS rewrites": "Automatically changes HTTP URLs to HTTPS in your HTML, preventing mixed content warnings.",
    "Opportunistic encryption": "Advertises HTTPS support via the Alt-Svc header, allowing browsers to upgrade HTTP/2 connections.",
    "Always use HTTPS": "Redirects all HTTP requests to HTTPS using a 301 redirect.",
    "Security level": "Controls how aggressively Cloudflare challenges suspicious visitors. Higher levels show more CAPTCHAs.",
    "Browser Integrity Check": "Evaluates HTTP headers from visitors and blocks requests with suspicious or missing headers.",
    "Email obfuscation": "Hides email addresses on your pages from bots and email harvesters by encoding them in JavaScript.",
    "Hotlink protection": "Prevents other websites from embedding your images, saving bandwidth.",
    "HSTS": "HTTP Strict Transport Security — tells browsers to only connect via HTTPS for a set period. Preload adds your domain to browser built-in lists.",
    "SPF": "Sender Policy Framework — a DNS TXT record that lists which mail servers can send email for your domain.",
    "DMARC": "Domain-based Message Authentication, Reporting, and Conformance — tells receiving servers what to do with emails that fail SPF/DKIM checks.",
    "DKIM": "DomainKeys Identified Mail — cryptographically signs outgoing emails so recipients can verify they haven't been tampered with.",
    "DNSSEC": "DNS Security Extensions — cryptographically signs DNS records to prevent spoofing and cache poisoning.",
    "CAA": "Certificate Authority Authorization — DNS records that specify which certificate authorities can issue SSL certificates for your domain.",
    "Dangling CNAMEs": "CNAME records pointing to services that no longer exist. Attackers can register the target and take over the subdomain.",
    "MTA-STS": "Mail Transfer Agent Strict Transport Security — forces receiving mail servers to use TLS encryption for inbound email.",
    "TLSRPT": "SMTP TLS Reporting — tells mail servers where to send reports about TLS negotiation failures.",
    "BIMI": "Brand Indicators for Message Identification — displays your brand logo next to emails in supporting clients (requires DMARC p=quarantine or p=reject).",
    "Transfer lock": "Prevents your domain from being transferred to another registrar without explicit authorisation.",
    "Domain expiry": "When your domain registration expires. An expired domain can be registered by anyone.",
    "Blacklist (DNSBL)": "DNS-based blacklists that track IP addresses known to send spam. Being listed can cause email delivery failures.",
    "Reverse DNS": "PTR records that map IP addresses back to hostnames. Mail servers often reject email from IPs without valid reverse DNS.",
    "FCrDNS": "Forward-Confirmed reverse DNS — the PTR record's hostname must resolve back to the original IP address.",
    "security.txt": "A /.well-known/security.txt file that tells security researchers how to report vulnerabilities in your site.",
    "X-Frame-Options": "HTTP header that controls whether your site can be embedded in iframes, preventing click-jacking attacks.",
    "Content-Security-Policy": "HTTP header that restricts which resources (scripts, styles, images) browsers can load, mitigating XSS and data injection attacks.",
    "X-Content-Type-Options": "HTTP header (set to 'nosniff') that stops browsers from MIME-type sniffing, preventing content-type confusion attacks.",
    "Referrer-Policy": "HTTP header that controls how much referrer information is sent with outgoing requests, protecting user privacy.",
    "Permissions-Policy": "HTTP header that controls which browser features (camera, microphone, geolocation) your site can use.",
}


# ── Regulatory standards references ──────────────────────────────────────────

STANDARDS = {
    "SSL mode": {
        "references": [
            {
                "body": "Cloudflare",
                "document": "SSL/TLS encryption modes",
                "requirement": "Use Full (strict) mode to validate origin certificates",
                "url": "https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/",
                "mandatory": False,
                "jurisdiction": "N/A",
            },
            {
                "body": "NIST",
                "document": "SP 800-52 Rev. 2",
                "requirement": "Servers SHALL be configured with a valid certificate to enable authenticated TLS connections to the origin",
                "url": "https://csrc.nist.gov/pubs/sp/800/52/r2/final",
                "mandatory": True,
                "jurisdiction": "US",
            },
            {
                "body": "NCSC",
                "document": "Using TLS to protect data",
                "requirement": "Use authenticated TLS connections; validate server certificates",
                "url": "https://www.ncsc.gov.uk/guidance/using-tls-to-protect-data",
                "mandatory": False,
                "jurisdiction": "UK",
            },
        ],
    },
    "Minimum TLS version": {
        "references": [
            {
                "body": "NIST",
                "document": "SP 800-52 Rev. 2",
                "requirement": "TLS 1.2 SHALL be supported; TLS 1.0 and 1.1 SHALL NOT be used",
                "url": "https://csrc.nist.gov/pubs/sp/800/52/r2/final",
                "mandatory": True,
                "jurisdiction": "US",
            },
            {
                "body": "PCI SSC",
                "document": "PCI DSS v4.0 Req 4.2.1",
                "requirement": "Only trusted keys and certificates are accepted; TLS 1.2 or higher is required",
                "url": "https://www.pcisecuritystandards.org",
                "mandatory": True,
                "jurisdiction": "US",
            },
            {
                "body": "NCSC",
                "document": "Using TLS to protect data",
                "requirement": "Use TLS 1.2 or above; disable TLS 1.0 and 1.1",
                "url": "https://www.ncsc.gov.uk/guidance/using-tls-to-protect-data",
                "mandatory": False,
                "jurisdiction": "UK",
            },
            {
                "body": "NCSC",
                "document": "Cyber Essentials v3.3",
                "requirement": "Encrypt data in transit with TLS 1.2 or higher",
                "url": "https://www.ncsc.gov.uk/files/cyber-essentials-requirements-for-it-infrastructure-v3-3.pdf",
                "mandatory": True,
                "jurisdiction": "UK",
            },
            {
                "body": "ICO",
                "document": "Encryption guidance (UK GDPR)",
                "requirement": "Use current versions of TLS; older versions have known vulnerabilities",
                "url": "https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/security/encryption/",
                "mandatory": True,
                "jurisdiction": "UK",
            },
            {
                "body": "BSI",
                "document": "TR-02102-2",
                "requirement": "TLS 1.2 with recommended cipher suites or TLS 1.3 SHALL be used",
                "url": "https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-2.html",
                "mandatory": True,
                "jurisdiction": "EU",
            },
            {
                "body": "ANSSI",
                "document": "TLS security recommendations",
                "requirement": "TLS 1.2 or 1.3 is mandatory; TLS 1.0 and 1.1 are forbidden",
                "url": "https://cyber.gouv.fr/en/publications/security-recommendations-tls",
                "mandatory": True,
                "jurisdiction": "EU",
            },
            {
                "body": "European Parliament",
                "document": "GDPR Article 32",
                "requirement": "Implement appropriate technical measures including encryption of personal data in transit",
                "url": "https://gdpr-info.eu/art-32-gdpr/",
                "mandatory": True,
                "jurisdiction": "EU",
            },
            {
                "body": "European Parliament",
                "document": "NIS2 Directive Article 21",
                "requirement": "Implement policies on the use of cryptography and encryption",
                "url": "https://www.nis-2-directive.com/NIS_2_Directive_Article_21.html",
                "mandatory": True,
                "jurisdiction": "EU",
            },
            {
                "body": "ENISA",
                "document": "Recommended cryptographic measures",
                "requirement": "Use TLS 1.2+ with recommended cipher suites for securing personal data",
                "url": "https://www.enisa.europa.eu/publications/recommended-cryptographic-measures-securing-personal-data",
                "mandatory": False,
                "jurisdiction": "EU",
            },
        ],
    },
    "TLS 1.3": {
        "references": [
            {
                "body": "NIST",
                "document": "SP 800-52 Rev. 2",
                "requirement": "Servers SHOULD be configured to support TLS 1.3",
                "url": "https://csrc.nist.gov/pubs/sp/800/52/r2/final",
                "mandatory": False,
                "jurisdiction": "US",
            },
            {
                "body": "NCSC",
                "document": "Using TLS to protect data",
                "requirement": "Use TLS 1.3 where possible for improved security and performance",
                "url": "https://www.ncsc.gov.uk/guidance/using-tls-to-protect-data",
                "mandatory": False,
                "jurisdiction": "UK",
            },
            {
                "body": "BSI",
                "document": "TR-02102-2",
                "requirement": "TLS 1.3 is recommended; provides improved forward secrecy",
                "url": "https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-2.html",
                "mandatory": False,
                "jurisdiction": "EU",
            },
        ],
    },
    "Always use HTTPS": {
        "references": [
            {
                "body": "CISA",
                "document": "BOD 18-01",
                "requirement": "All web traffic must be served over HTTPS",
                "url": "https://www.cisa.gov/news-events/directives/bod-18-01-enhance-email-and-web-security",
                "mandatory": True,
                "jurisdiction": "US",
            },
            {
                "body": "UK GDS",
                "document": "Using HTTPS",
                "requirement": "Use HTTPS for all government services; redirect HTTP to HTTPS",
                "url": "https://www.gov.uk/service-manual/technology/using-https",
                "mandatory": True,
                "jurisdiction": "UK",
            },
            {
                "body": "ICO",
                "document": "Encryption guidance (UK GDPR)",
                "requirement": "Encrypt personal data in transit using HTTPS",
                "url": "https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/security/encryption/",
                "mandatory": True,
                "jurisdiction": "UK",
            },
            {
                "body": "NCSC",
                "document": "Using TLS to protect data",
                "requirement": "Redirect all HTTP requests to HTTPS",
                "url": "https://www.ncsc.gov.uk/guidance/using-tls-to-protect-data",
                "mandatory": False,
                "jurisdiction": "UK",
            },
        ],
    },
    "HSTS": {
        "references": [
            {
                "body": "IETF",
                "document": "RFC 6797",
                "requirement": "HTTP Strict Transport Security (HSTS) specification",
                "url": "https://datatracker.ietf.org/doc/html/rfc6797",
                "mandatory": False,
                "jurisdiction": "International",
            },
            {
                "body": "CISA",
                "document": "BOD 18-01",
                "requirement": "Enable HSTS with a max-age of at least one year; preload where possible",
                "url": "https://www.cisa.gov/news-events/directives/bod-18-01-enhance-email-and-web-security",
                "mandatory": True,
                "jurisdiction": "US",
            },
            {
                "body": "OWASP",
                "document": "HTTP Headers Cheat Sheet",
                "requirement": "Set Strict-Transport-Security with max-age, includeSubDomains, and preload",
                "url": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
                "mandatory": False,
                "jurisdiction": "International",
            },
            {
                "body": "UK GDS",
                "document": "Using HTTPS",
                "requirement": "Use HSTS to instruct browsers to always use HTTPS",
                "url": "https://www.gov.uk/service-manual/technology/using-https",
                "mandatory": True,
                "jurisdiction": "UK",
            },
            {
                "body": "NCSC",
                "document": "Using TLS to protect data",
                "requirement": "Implement HSTS to prevent downgrade attacks",
                "url": "https://www.ncsc.gov.uk/guidance/using-tls-to-protect-data",
                "mandatory": False,
                "jurisdiction": "UK",
            },
        ],
    },
    "Security level": {
        "references": [
            {
                "body": "Cloudflare",
                "document": "Security Level setting",
                "requirement": "Set an appropriate security level to challenge suspicious visitors",
                "url": "https://developers.cloudflare.com/waf/tools/security-level/",
                "mandatory": False,
                "jurisdiction": "N/A",
            },
        ],
    },
    "Browser Integrity Check": {
        "references": [
            {
                "body": "Cloudflare",
                "document": "Browser Integrity Check",
                "requirement": "Enable to block requests with suspicious HTTP headers",
                "url": "https://developers.cloudflare.com/waf/tools/browser-integrity-check/",
                "mandatory": False,
                "jurisdiction": "N/A",
            },
        ],
    },
    "Email obfuscation": {
        "references": [
            {
                "body": "Cloudflare",
                "document": "Email Address Obfuscation",
                "requirement": "Enable to hide email addresses from scrapers",
                "url": "https://developers.cloudflare.com/waf/tools/scrape-shield/email-address-obfuscation/",
                "mandatory": False,
                "jurisdiction": "N/A",
            },
        ],
    },
    "Hotlink protection": {
        "references": [
            {
                "body": "Cloudflare",
                "document": "Hotlink Protection",
                "requirement": "Enable to prevent other sites from embedding your images",
                "url": "https://developers.cloudflare.com/waf/tools/scrape-shield/hotlink-protection/",
                "mandatory": False,
                "jurisdiction": "N/A",
            },
        ],
    },
    "SPF": {
        "references": [
            {
                "body": "IETF",
                "document": "RFC 7208",
                "requirement": "Sender Policy Framework (SPF) specification",
                "url": "https://datatracker.ietf.org/doc/html/rfc7208",
                "mandatory": False,
                "jurisdiction": "International",
            },
            {
                "body": "CISA",
                "document": "BOD 18-01",
                "requirement": "All internet-facing mail servers must offer STARTTLS; SPF records must be published for all domains",
                "url": "https://www.cisa.gov/news-events/directives/bod-18-01-enhance-email-and-web-security",
                "mandatory": True,
                "jurisdiction": "US",
            },
            {
                "body": "NIST",
                "document": "SP 800-177 Rev. 1",
                "requirement": "Domain owners SHOULD publish SPF records specifying authorised senders",
                "url": "https://csrc.nist.gov/pubs/sp/800/177/r1/final",
                "mandatory": False,
                "jurisdiction": "US",
            },
            {
                "body": "NCSC",
                "document": "Email security and anti-spoofing",
                "requirement": "Publish an SPF record to declare which servers may send mail for your domain",
                "url": "https://www.ncsc.gov.uk/collection/email-security-and-anti-spoofing",
                "mandatory": False,
                "jurisdiction": "UK",
            },
            {
                "body": "BSI",
                "document": "TR-03182",
                "requirement": "SPF records SHALL be published for all domains used for email",
                "url": "https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03182/tr-03182.html",
                "mandatory": True,
                "jurisdiction": "EU",
            },
        ],
    },
    "DMARC": {
        "references": [
            {
                "body": "IETF",
                "document": "RFC 7489",
                "requirement": "Domain-based Message Authentication, Reporting, and Conformance (DMARC) specification",
                "url": "https://datatracker.ietf.org/doc/html/rfc7489",
                "mandatory": False,
                "jurisdiction": "International",
            },
            {
                "body": "CISA",
                "document": "BOD 18-01",
                "requirement": "DMARC policy of reject must be set for all second-level domains",
                "url": "https://www.cisa.gov/news-events/directives/bod-18-01-enhance-email-and-web-security",
                "mandatory": True,
                "jurisdiction": "US",
            },
            {
                "body": "NIST",
                "document": "SP 800-177 Rev. 1",
                "requirement": "Domain owners SHOULD publish DMARC records with a policy of quarantine or reject",
                "url": "https://csrc.nist.gov/pubs/sp/800/177/r1/final",
                "mandatory": False,
                "jurisdiction": "US",
            },
            {
                "body": "NCSC",
                "document": "Email security and anti-spoofing",
                "requirement": "Set a DMARC policy to protect your domain from spoofing",
                "url": "https://www.ncsc.gov.uk/collection/email-security-and-anti-spoofing",
                "mandatory": False,
                "jurisdiction": "UK",
            },
            {
                "body": "BSI",
                "document": "TR-03182",
                "requirement": "DMARC records SHALL be published with an enforcement policy",
                "url": "https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03182/tr-03182.html",
                "mandatory": True,
                "jurisdiction": "EU",
            },
        ],
    },
    "DKIM": {
        "references": [
            {
                "body": "IETF",
                "document": "RFC 6376",
                "requirement": "DomainKeys Identified Mail (DKIM) Signatures specification",
                "url": "https://datatracker.ietf.org/doc/html/rfc6376",
                "mandatory": False,
                "jurisdiction": "International",
            },
            {
                "body": "NIST",
                "document": "SP 800-177 Rev. 1",
                "requirement": "Sending domains SHOULD sign messages with DKIM",
                "url": "https://csrc.nist.gov/pubs/sp/800/177/r1/final",
                "mandatory": False,
                "jurisdiction": "US",
            },
            {
                "body": "NCSC",
                "document": "Email security and anti-spoofing",
                "requirement": "Sign outbound email with DKIM to prove message authenticity",
                "url": "https://www.ncsc.gov.uk/collection/email-security-and-anti-spoofing",
                "mandatory": False,
                "jurisdiction": "UK",
            },
        ],
    },
    "DNSSEC": {
        "references": [
            {
                "body": "IETF",
                "document": "RFC 4033",
                "requirement": "DNS Security Introduction and Requirements",
                "url": "https://datatracker.ietf.org/doc/html/rfc4033",
                "mandatory": False,
                "jurisdiction": "International",
            },
            {
                "body": "NIST",
                "document": "SP 800-81 Rev. 3",
                "requirement": "DNS zones SHOULD be signed with DNSSEC",
                "url": "https://csrc.nist.gov/pubs/sp/800/81/r3/final",
                "mandatory": False,
                "jurisdiction": "US",
            },
            {
                "body": "NCSC",
                "document": "Managing public domain names",
                "requirement": "Enable DNSSEC to protect against DNS spoofing",
                "url": "https://www.ncsc.gov.uk/guidance/managing-public-domain-names",
                "mandatory": False,
                "jurisdiction": "UK",
            },
            {
                "body": "European Parliament",
                "document": "NIS2 Directive Article 21",
                "requirement": "Implement policies on the use of cryptography; secure DNS resolution",
                "url": "https://www.nis-2-directive.com/NIS_2_Directive_Article_21.html",
                "mandatory": True,
                "jurisdiction": "EU",
            },
        ],
    },
    "CAA": {
        "references": [
            {
                "body": "IETF",
                "document": "RFC 8659",
                "requirement": "DNS Certification Authority Authorization (CAA) Resource Record",
                "url": "https://datatracker.ietf.org/doc/html/rfc8659",
                "mandatory": False,
                "jurisdiction": "International",
            },
            {
                "body": "NCSC",
                "document": "Provisioning and managing certificates in the Web PKI",
                "requirement": "Use CAA records to restrict which CAs can issue certificates for your domain",
                "url": "https://www.ncsc.gov.uk/guidance/provisioning-and-managing-certificates-in-the-web-pki",
                "mandatory": False,
                "jurisdiction": "UK",
            },
            {
                "body": "CA/Browser Forum",
                "document": "Baseline Requirements",
                "requirement": "CAs must check CAA records before issuing certificates",
                "url": "https://cabforum.org/baseline-requirements/",
                "mandatory": True,
                "jurisdiction": "International",
            },
        ],
    },
    "MTA-STS": {
        "references": [
            {
                "body": "IETF",
                "document": "RFC 8461",
                "requirement": "SMTP MTA Strict Transport Security (MTA-STS) specification",
                "url": "https://datatracker.ietf.org/doc/html/rfc8461",
                "mandatory": False,
                "jurisdiction": "International",
            },
            {
                "body": "NCSC",
                "document": "Email security and anti-spoofing",
                "requirement": "Use MTA-STS to enforce TLS for inbound email",
                "url": "https://www.ncsc.gov.uk/collection/email-security-and-anti-spoofing",
                "mandatory": False,
                "jurisdiction": "UK",
            },
        ],
    },
    "TLSRPT": {
        "references": [
            {
                "body": "IETF",
                "document": "RFC 8460",
                "requirement": "SMTP TLS Reporting specification",
                "url": "https://datatracker.ietf.org/doc/html/rfc8460",
                "mandatory": False,
                "jurisdiction": "International",
            },
            {
                "body": "BSI",
                "document": "TR-03182",
                "requirement": "TLS reporting SHOULD be configured to receive failure notifications",
                "url": "https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03182/tr-03182.html",
                "mandatory": False,
                "jurisdiction": "EU",
            },
        ],
    },
    "BIMI": {
        "references": [
            {
                "body": "BIMI Group",
                "document": "BIMI specification",
                "requirement": "Industry best practice for displaying brand logos in email clients; requires DMARC enforcement",
                "url": "https://bimigroup.org/",
                "mandatory": False,
                "jurisdiction": "International",
            },
        ],
    },
    "Transfer lock": {
        "references": [
            {
                "body": "NCSC",
                "document": "Managing public domain names",
                "requirement": "Enable transfer lock to prevent unauthorised domain transfers",
                "url": "https://www.ncsc.gov.uk/guidance/managing-public-domain-names",
                "mandatory": False,
                "jurisdiction": "UK",
            },
        ],
    },
    "Domain expiry": {
        "references": [
            {
                "body": "NCSC",
                "document": "Managing public domain names",
                "requirement": "Monitor domain expiry dates and enable auto-renewal",
                "url": "https://www.ncsc.gov.uk/guidance/managing-public-domain-names",
                "mandatory": False,
                "jurisdiction": "UK",
            },
        ],
    },
    "security.txt": {
        "references": [
            {
                "body": "IETF",
                "document": "RFC 9116",
                "requirement": "A machine-readable file for security vulnerability disclosure",
                "url": "https://datatracker.ietf.org/doc/html/rfc9116",
                "mandatory": False,
                "jurisdiction": "International",
            },
            {
                "body": "NCSC",
                "document": "Vulnerability Disclosure Toolkit",
                "requirement": "Publish a security.txt file to help security researchers report vulnerabilities",
                "url": "https://www.ncsc.gov.uk/information/vulnerability-disclosure-toolkit",
                "mandatory": False,
                "jurisdiction": "UK",
            },
            {
                "body": "CISA",
                "document": "BOD 20-01",
                "requirement": "Federal agencies must publish a vulnerability disclosure policy",
                "url": "https://www.cisa.gov/news-events/directives/bod-20-01-develop-and-publish-vulnerability-disclosure-policy",
                "mandatory": True,
                "jurisdiction": "US",
            },
            {
                "body": "European Parliament",
                "document": "NIS2 Directive Article 21",
                "requirement": "Establish policies for handling vulnerability disclosure",
                "url": "https://www.nis-2-directive.com/NIS_2_Directive_Article_21.html",
                "mandatory": True,
                "jurisdiction": "EU",
            },
        ],
    },
    "X-Frame-Options": {
        "references": [
            {
                "body": "OWASP",
                "document": "Secure Headers Project",
                "requirement": "Set X-Frame-Options to DENY or SAMEORIGIN to prevent click-jacking",
                "url": "https://owasp.org/www-project-secure-headers/",
                "mandatory": False,
                "jurisdiction": "International",
            },
            {
                "body": "OWASP",
                "document": "HTTP Headers Cheat Sheet",
                "requirement": "Use X-Frame-Options or Content-Security-Policy frame-ancestors directive",
                "url": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
                "mandatory": False,
                "jurisdiction": "International",
            },
        ],
    },
    "Content-Security-Policy": {
        "references": [
            {
                "body": "OWASP",
                "document": "Secure Headers Project",
                "requirement": "Implement a Content-Security-Policy to mitigate XSS and data injection attacks",
                "url": "https://owasp.org/www-project-secure-headers/",
                "mandatory": False,
                "jurisdiction": "International",
            },
            {
                "body": "OWASP",
                "document": "HTTP Headers Cheat Sheet",
                "requirement": "Deploy CSP with a restrictive default-src directive",
                "url": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
                "mandatory": False,
                "jurisdiction": "International",
            },
        ],
    },
    "X-Content-Type-Options": {
        "references": [
            {
                "body": "OWASP",
                "document": "Secure Headers Project",
                "requirement": "Set X-Content-Type-Options: nosniff to prevent MIME-type sniffing",
                "url": "https://owasp.org/www-project-secure-headers/",
                "mandatory": False,
                "jurisdiction": "International",
            },
            {
                "body": "OWASP",
                "document": "HTTP Headers Cheat Sheet",
                "requirement": "Always set X-Content-Type-Options: nosniff",
                "url": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
                "mandatory": False,
                "jurisdiction": "International",
            },
        ],
    },
    "Referrer-Policy": {
        "references": [
            {
                "body": "OWASP",
                "document": "Secure Headers Project",
                "requirement": "Set Referrer-Policy to limit referrer information leakage",
                "url": "https://owasp.org/www-project-secure-headers/",
                "mandatory": False,
                "jurisdiction": "International",
            },
            {
                "body": "OWASP",
                "document": "HTTP Headers Cheat Sheet",
                "requirement": "Use strict-origin-when-cross-origin or no-referrer",
                "url": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
                "mandatory": False,
                "jurisdiction": "International",
            },
        ],
    },
    "Permissions-Policy": {
        "references": [
            {
                "body": "OWASP",
                "document": "Secure Headers Project",
                "requirement": "Set Permissions-Policy to restrict browser feature access",
                "url": "https://owasp.org/www-project-secure-headers/",
                "mandatory": False,
                "jurisdiction": "International",
            },
            {
                "body": "OWASP",
                "document": "HTTP Headers Cheat Sheet",
                "requirement": "Restrict unnecessary browser features with Permissions-Policy",
                "url": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
                "mandatory": False,
                "jurisdiction": "International",
            },
        ],
    },
    "Reverse DNS": {
        "references": [
            {
                "body": "Industry",
                "document": "Email deliverability best practice",
                "requirement": "Mail server IPs should have valid PTR records matching the sending hostname",
                "url": "https://support.google.com/mail/answer/81126",
                "mandatory": False,
                "jurisdiction": "International",
            },
        ],
    },
    "Blacklist (DNSBL)": {
        "references": [
            {
                "body": "Industry",
                "document": "Email deliverability best practice",
                "requirement": "Monitor DNSBL listings and remediate promptly to maintain email deliverability",
                "url": "https://www.spamhaus.org/",
                "mandatory": False,
                "jurisdiction": "International",
            },
        ],
    },
}


def get_standards(label: str) -> list:
    """Return the list of regulatory standard references for a check label, or empty list."""
    entry = STANDARDS.get(label, {})
    return entry.get("references", [])


# ── Remediation instructions ─────────────────────────────────────────────────

REMEDIATIONS = {
    # Zone security
    "SSL mode": {
        "WARN": {
            "priority": "High",
            "risk": "Traffic between Cloudflare and your origin server is unencrypted. Attackers on the same network can intercept data.",
            "steps": [
                "Install a valid SSL certificate on your origin server (Cloudflare offers free origin certificates)",
                "In the Cloudflare dashboard, go to SSL/TLS → Overview",
                "Change the encryption mode to 'Full (strict)'",
                "Test your site still loads correctly",
            ],
        },
        "FAIL": {
            "priority": "Critical",
            "risk": "SSL is disabled. All traffic is sent in plain text — passwords, cookies, and personal data are exposed.",
            "steps": [
                "In the Cloudflare dashboard, go to SSL/TLS → Overview",
                "Set encryption mode to at least 'Flexible' immediately, then work towards 'Full (strict)'",
                "Install a valid SSL certificate on your origin server",
            ],
        },
    },
    "Minimum TLS version": {
        "FAIL": {
            "priority": "High",
            "risk": "TLS 1.0 has known vulnerabilities (BEAST, POODLE). It is deprecated by all major browsers and fails PCI DSS compliance.",
            "steps": [
                "In the Cloudflare dashboard, go to SSL/TLS → Edge Certificates",
                "Set 'Minimum TLS Version' to 1.2",
                "This may break very old clients (IE 10, Android 4.x) — check your analytics first",
            ],
        },
        "WARN": {
            "priority": "Medium",
            "risk": "TLS 1.1 is deprecated and has known weaknesses. Most modern browsers no longer support it.",
            "steps": [
                "In the Cloudflare dashboard, go to SSL/TLS → Edge Certificates",
                "Set 'Minimum TLS Version' to 1.2",
            ],
        },
    },
    "TLS 1.3": {
        "FAIL": {
            "priority": "Medium",
            "risk": "TLS 1.3 provides better performance and security than older versions. Disabling it means visitors miss out on faster connections.",
            "steps": [
                "In the Cloudflare dashboard, go to SSL/TLS → Edge Certificates",
                "Enable TLS 1.3",
            ],
        },
    },
    "Always use HTTPS": {
        "FAIL": {
            "priority": "High",
            "risk": "Visitors can access your site over plain HTTP, exposing them to man-in-the-middle attacks and data interception.",
            "steps": [
                "In the Cloudflare dashboard, go to SSL/TLS → Edge Certificates",
                "Enable 'Always Use HTTPS'",
                "This creates an automatic 301 redirect from HTTP to HTTPS",
            ],
        },
    },
    "Automatic HTTPS rewrites": {
        "FAIL": {
            "priority": "Medium",
            "risk": "Mixed content (HTTP resources on HTTPS pages) causes browser warnings and can break page functionality.",
            "steps": [
                "In the Cloudflare dashboard, go to SSL/TLS → Edge Certificates",
                "Enable 'Automatic HTTPS Rewrites'",
            ],
        },
    },
    "HSTS": {
        "WARN": {
            "priority": "Medium",
            "risk": "Without HSTS, browsers may still attempt HTTP connections before being redirected, leaving a window for interception.",
            "steps": [
                "In the Cloudflare dashboard, go to SSL/TLS → Edge Certificates",
                "Enable HSTS with max-age of at least 31536000 (1 year)",
                "Enable 'Include subdomains' if all subdomains support HTTPS",
                "Enable 'Preload' to be included in browser preload lists",
                "Warning: Once enabled with preload, it's difficult to revert — ensure all subdomains support HTTPS first",
            ],
        },
    },
    "Security level": {
        "FAIL": {
            "priority": "Medium",
            "risk": "Security level is effectively off. Cloudflare won't challenge suspicious visitors, increasing exposure to automated attacks.",
            "steps": [
                "In the Cloudflare dashboard, go to Security → Settings",
                "Set Security Level to at least 'Medium'",
            ],
        },
    },
    "Browser Integrity Check": {
        "FAIL": {
            "priority": "Low",
            "risk": "Requests with suspicious HTTP headers (common in bots and automated tools) are not being blocked.",
            "steps": [
                "In the Cloudflare dashboard, go to Security → Settings",
                "Enable 'Browser Integrity Check'",
            ],
        },
    },
    "Email obfuscation": {
        "FAIL": {
            "priority": "Low",
            "risk": "Email addresses on your pages are visible to scraping bots, which may lead to increased spam.",
            "steps": [
                "In the Cloudflare dashboard, go to Scrape Shield",
                "Enable 'Email Address Obfuscation'",
            ],
        },
    },
    "Hotlink protection": {
        "FAIL": {
            "priority": "Low",
            "risk": "Other websites can embed your images, consuming your bandwidth.",
            "steps": [
                "In the Cloudflare dashboard, go to Scrape Shield",
                "Enable 'Hotlink Protection'",
            ],
        },
    },

    # Email
    "SPF": {
        "FAIL": {
            "priority": "Critical",
            "risk": "Without an SPF record, anyone can send email pretending to be your domain. This is the most common email spoofing vector.",
            "steps": [
                "Identify your email provider (Microsoft 365, Google Workspace, etc.)",
                "Add a TXT record to your DNS: v=spf1 include:<provider_spf> -all",
                "For Microsoft 365: v=spf1 include:spf.protection.outlook.com -all",
                "For Google Workspace: v=spf1 include:_spf.google.com -all",
                "Use -all (hard fail) not ~all (soft fail) for maximum protection",
            ],
        },
        "WARN": {
            "priority": "Medium",
            "risk": "Your SPF record uses ~all (soft fail) which marks suspicious emails but doesn't reject them. Spoofed emails may still reach inboxes.",
            "steps": [
                "Change ~all to -all in your SPF TXT record",
                "Monitor for any legitimate email sources you may have missed before making this change",
            ],
        },
    },
    "DMARC": {
        "FAIL": {
            "priority": "Critical",
            "risk": "Without DMARC, receiving servers have no policy for handling emails that fail SPF/DKIM checks. Your domain can be freely spoofed.",
            "steps": [
                "Add a TXT record at _dmarc.yourdomain.com",
                "Start with monitoring: v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com",
                "Review DMARC reports for 2-4 weeks to identify all legitimate email sources",
                "Move to quarantine: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com",
                "Finally enforce: v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com",
            ],
        },
        "WARN": {
            "priority": "Medium",
            "risk": "DMARC is set to quarantine, which sends failing emails to spam. Moving to p=reject would block them entirely.",
            "steps": [
                "Review DMARC reports to ensure all legitimate sources pass",
                "Change p=quarantine to p=reject in your _dmarc TXT record",
            ],
        },
    },

    # DNS security
    "DNSSEC": {
        "WARN": {
            "priority": "Medium",
            "risk": "Without DNSSEC, DNS responses can be spoofed. An attacker could redirect your visitors to a malicious server.",
            "steps": [
                "In the Cloudflare dashboard, go to DNS → Settings",
                "Click 'Enable DNSSEC'",
                "Cloudflare will provide a DS record",
                "Add the DS record at your domain registrar (this is a separate step from Cloudflare)",
                "DNSSEC is not fully active until the DS record is published at the registrar",
            ],
        },
    },
    "CAA": {
        "WARN": {
            "priority": "Low",
            "risk": "Without CAA records, any certificate authority can issue SSL certificates for your domain. A rogue CA could issue a certificate to an attacker.",
            "steps": [
                "Add CAA DNS records specifying which CAs can issue certificates",
                "For Cloudflare: Add CAA records for letsencrypt.org, digicert.com, and pki.goog",
                'Example: 0 issue "letsencrypt.org"',
                'Example: 0 issue "digicert.com"',
                "Optionally add an iodef record for violation reports",
            ],
        },
        "FAIL": {
            "priority": "High",
            "risk": "CAA records exist but don't include Cloudflare's certificate authorities. This will prevent Cloudflare from issuing or renewing SSL certificates for your domain.",
            "steps": [
                "Add CAA issue records for Cloudflare's CAs: letsencrypt.org, digicert.com, pki.goog",
                "Keep any existing CAA records for other services you use",
                "Test by checking certificate issuance in the Cloudflare dashboard",
            ],
        },
    },
    "Dangling CNAMEs": {
        "FAIL": {
            "priority": "Critical",
            "risk": "Dangling CNAME records point to services that no longer exist. An attacker can register the target and serve malicious content on your subdomain.",
            "steps": [
                "Review each dangling CNAME record listed above",
                "If the service is no longer needed, delete the CNAME record from your DNS",
                "If the service should exist, re-provision it at the target",
                "This is a subdomain takeover vulnerability — treat with urgency",
            ],
        },
    },

    # Registrar
    "Transfer lock": {
        "WARN": {
            "priority": "Medium",
            "risk": "Without a transfer lock, your domain could be transferred to another registrar without your knowledge (domain hijacking).",
            "steps": [
                "Log in to your domain registrar",
                "Find the domain lock or transfer lock setting",
                "Enable 'clientTransferProhibited' or equivalent",
                "This is usually a single toggle in your registrar's dashboard",
            ],
        },
    },
    "Domain expiry": {
        "FAIL": {
            "priority": "Critical",
            "risk": "Your domain is expired or about to expire. An expired domain can be registered by anyone, resulting in complete loss of your web presence and email.",
            "steps": [
                "Renew your domain immediately at your registrar",
                "Enable auto-renewal to prevent future expiry",
                "Consider registering for multiple years",
            ],
        },
        "WARN": {
            "priority": "High",
            "risk": "Your domain expires within 90 days. If renewal fails (e.g. expired payment card), you could lose the domain.",
            "steps": [
                "Verify auto-renewal is enabled at your registrar",
                "Check the payment method on file is current",
                "Consider renewing early for peace of mind",
            ],
        },
    },
}


def get_tooltip(label: str) -> str:
    """Return tooltip text for a check label, or empty string."""
    return TOOLTIPS.get(label, "")


def get_remediation(label: str, grade: str) -> dict:
    """Return remediation guidance for a check/grade, or None."""
    check_remediations = REMEDIATIONS.get(label, {})
    return check_remediations.get(grade)


def collect_remediations(
    domains: list,
    security_results: dict,
    email_results: dict,
    dns_sec_results: dict,
    registrar_results: dict,
    blacklist_results: dict,
    rdns_results: dict,
) -> List[Dict]:
    """Collect all findings that need remediation across all domains.

    Returns a list of dicts sorted by priority (Critical > High > Medium > Low).
    """
    PRIORITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings = []

    for domain in domains:
        # Zone security
        sec = security_results.get(domain, {})
        for r in sec.get("results", []):
            grade = r.get("grade")
            if grade in ("FAIL", "WARN"):
                rem = get_remediation(r.get("label", ""), grade)
                if rem:
                    findings.append({
                        "domain": domain,
                        "category": "Zone Security",
                        "check": r.get("label", ""),
                        "grade": grade,
                        "actual": r.get("actual", ""),
                        "recommended": r.get("recommended", ""),
                        **rem,
                    })

        # Email
        email = email_results.get(domain, {})
        for check_key, check_label in [("spf", "SPF"), ("dmarc", "DMARC")]:
            grade = email.get(check_key, {}).get("grade")
            if grade in ("FAIL", "WARN"):
                rem = get_remediation(check_label, grade)
                if rem:
                    findings.append({
                        "domain": domain,
                        "category": "Email Security",
                        "check": check_label,
                        "grade": grade,
                        "actual": email.get(check_key, {}).get("reason", ""),
                        "recommended": "",
                        **rem,
                    })

        # DNS security
        ds = dns_sec_results.get(domain, {})
        for check_key, check_label in [("dnssec", "DNSSEC"), ("caa", "CAA"), ("dangling", "Dangling CNAMEs")]:
            grade = ds.get(check_key, {}).get("grade")
            if grade in ("FAIL", "WARN"):
                rem = get_remediation(check_label, grade)
                if rem:
                    findings.append({
                        "domain": domain,
                        "category": "DNS Security",
                        "check": check_label,
                        "grade": grade,
                        "actual": ds.get(check_key, {}).get("reason", ""),
                        "recommended": "",
                        **rem,
                    })

        # Registrar
        reg = registrar_results.get(domain, {})
        for check_key, check_label in [("expiry", "Domain expiry"), ("lock", "Transfer lock")]:
            grade = reg.get(check_key, {}).get("grade")
            if grade in ("FAIL", "WARN"):
                rem = get_remediation(check_label, grade)
                if rem:
                    findings.append({
                        "domain": domain,
                        "category": "Registrar",
                        "check": check_label,
                        "grade": grade,
                        "actual": reg.get(check_key, {}).get("reason", ""),
                        "recommended": "",
                        **rem,
                    })

    findings.sort(key=lambda f: PRIORITY_ORDER.get(f.get("priority", "Low"), 99))
    return findings
