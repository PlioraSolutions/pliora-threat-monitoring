import { RemediationGuidance } from './types';

export const REMEDIATION_LIBRARY: Record<string, RemediationGuidance> = {
  TLS_WEAK_PROTOCOL: {
    code: 'TLS_WEAK_PROTOCOL',
    title: 'Disable Insecure TLS 1.0/1.1 Protocols',
    category: 'TRANSPORT_SECURITY',
    version: '1.1.0',
    approvedSteps: [
      'Disable legacy TLS 1.0 and TLS 1.1 in your web server or load balancer configuration.',
      'Enforce TLS 1.2 as the minimum supported protocol version, and enable TLS 1.3 for optimal forward secrecy and PCI DSS 4.0 Requirement 8.2 compliance.',
      'Configure modern AEAD cipher suites such as ECDHE-ECDSA-AES128-GCM-SHA256 and ECDHE-RSA-AES128-GCM-SHA256 to align with NIST 800-52r2 payment processing standards.',
      'Verify the configuration using an external SSL scanning utility to ensure deprecated protocol handshakes fail cleanly.',
    ],
  },
  'TLS-OBSOLETE-PROTOCOL': {
    code: 'TLS-OBSOLETE-PROTOCOL',
    title: 'Decommission Deprecated TLS 1.0/1.1 Protocols (PCI DSS Compliance)',
    category: 'TRANSPORT_SECURITY',
    version: '1.1.0',
    approvedSteps: [
      'Disable deprecated TLS 1.0 and TLS 1.1 across all load balancers, CDN distributions, and web server profiles.',
      'Enforce TLS 1.2 or TLS 1.3 exclusively to maintain alignment with PCI DSS 4.0 (Requirement 8.2) and NIST 800-52r2 encryption mandates.',
      'Audit client user agents to ensure legacy browsers without TLS 1.2 support are redirected to an upgrade advisory.',
    ],
  },
  TLS_CERT_EXPIRED: {
    code: 'TLS_CERT_EXPIRED',
    title: 'Renew Expired SSL/TLS Certificate',
    category: 'TRANSPORT_SECURITY',
    version: '1.0.0',
    approvedSteps: [
      'Renew the expired TLS certificate immediately through your Certificate Authority (CA) or automated ACME provider.',
      'Deploy the newly issued certificate and intermediate bundle to your web server or CDN distribution.',
      'Restart or reload the web service to load the valid certificate without interrupting active sessions.',
      'Audit automated renewal jobs (such as Certbot or Cloudflare Universal SSL) to prevent future expiration lapses.',
    ],
  },
  TLS_CERT_EXPIRING_SOON: {
    code: 'TLS_CERT_EXPIRING_SOON',
    title: 'Schedule Imminent TLS Certificate Renewal',
    category: 'TRANSPORT_SECURITY',
    version: '1.0.0',
    approvedSteps: [
      'Initiate renewal of the expiring certificate with your certificate authority before the stated expiration window.',
      'Verify automated ACME renewal triggers and monitor deployment logs for renewal failures.',
      'Test intermediate certificate chain integrity on staging environments before deploying to production.',
    ],
  },
  TLS_SELF_SIGNED: {
    code: 'TLS_SELF_SIGNED',
    title: 'Replace Untrusted Self-Signed Certificate',
    category: 'TRANSPORT_SECURITY',
    version: '1.0.0',
    approvedSteps: [
      'Replace the self-signed certificate with an SSL/TLS certificate issued by a trusted public Certificate Authority.',
      'Ensure all necessary Subject Alternative Names (SANs) covering your domain and subdomains are included.',
      'Configure automated certificate issuance using Let\'s Encrypt or your cloud provider\'s managed certificate manager.',
    ],
  },
  TLS_HOST_MISMATCH: {
    code: 'TLS_HOST_MISMATCH',
    title: 'Correct TLS Certificate Hostname Mismatch',
    category: 'TRANSPORT_SECURITY',
    version: '1.0.0',
    approvedSteps: [
      'Re-issue the certificate with Subject Alternative Names (SANs) that explicitly include this queried domain.',
      'Update reverse proxy or CDN routing rules to ensure the client request reaches the intended vhost and certificate binding.',
      'Verify SNI (Server Name Indication) handling on the origin load balancer.',
    ],
  },
  MISSING_HSTS_HEADER: {
    code: 'MISSING_HSTS_HEADER',
    title: 'Implement HTTP Strict Transport Security (HSTS)',
    category: 'HTTP_SECURITY_HEADERS',
    version: '1.0.0',
    approvedSteps: [
      'Add the Strict-Transport-Security response header across all production HTTPS endpoints.',
      'Set the max-age directive to at least 31536000 seconds (1 year) to enforce HTTPS persistence.',
      'Include the includeSubDomains directive once all subdomains are verified to support HTTPS.',
      'Consider adding the preload directive and submitting the root domain to the Chrome HSTS preload list.',
    ],
  },
  MISSING_CSP_HEADER: {
    code: 'MISSING_CSP_HEADER',
    title: 'Deploy Content Security Policy (CSP)',
    category: 'HTTP_SECURITY_HEADERS',
    version: '1.0.0',
    approvedSteps: [
      'Define a Content-Security-Policy HTTP header restricting script-src, object-src, and default-src directives.',
      'Begin deployment using Content-Security-Policy-Report-Only to detect legitimate resource violations without breaking the UI.',
      'Refactor inline JavaScript execution to use cryptographic nonces or SHA-256 hashes instead of unsafe-inline.',
      'Transition to an enforced Content-Security-Policy once violation reports are clear of false positives.',
    ],
  },
  MISSING_X_FRAME_OPTIONS: {
    code: 'MISSING_X_FRAME_OPTIONS',
    title: 'Prevent Clickjacking with Frame Protection',
    category: 'HTTP_SECURITY_HEADERS',
    version: '1.0.0',
    approvedSteps: [
      'Add the X-Frame-Options response header with a value of DENY or SAMEORIGIN.',
      'Alternatively, configure the Content-Security-Policy frame-ancestors directive for modern browser clickjacking protection.',
      'Verify that application pages cannot be framed inside unauthorized third-party iframes.',
    ],
  },
  MISSING_REFERRER_POLICY: {
    code: 'MISSING_REFERRER_POLICY',
    title: 'Configure Referrer-Policy Header',
    category: 'HTTP_SECURITY_HEADERS',
    version: '1.0.0',
    approvedSteps: [
      'Add the Referrer-Policy header set to strict-origin-when-cross-origin.',
      'Ensure sensitive tokens, user IDs, or session parameters are never passed in URL query strings.',
      'Verify external outbound links do not leak internal path structures in HTTP Referer headers.',
    ],
  },
  MISSING_CONTENT_TYPE_OPTIONS: {
    code: 'MISSING_CONTENT_TYPE_OPTIONS',
    title: 'Enforce Strict MIME-Type Sniffing Protection',
    category: 'HTTP_SECURITY_HEADERS',
    version: '1.0.0',
    approvedSteps: [
      'Add the X-Content-Type-Options header with a value of nosniff to all HTTP responses.',
      'Ensure correct Content-Type headers are explicitly set for JavaScript, CSS, images, and JSON payloads.',
    ],
  },
  SERVER_BANNER_DISCLOSURE: {
    code: 'SERVER_BANNER_DISCLOSURE',
    title: 'Suppress Server Banner Version Disclosure',
    category: 'TECH_VERSION',
    version: '1.0.0',
    approvedSteps: [
      'Configure the web server to suppress granular software and OS versions in the Server HTTP header.',
      'In Apache, set ServerTokens Prod and ServerSignature Off in the server configuration.',
      'In Nginx, set server_tokens off inside the http block.',
    ],
  },
  X_POWERED_BY_DISCLOSURE: {
    code: 'X_POWERED_BY_DISCLOSURE',
    title: 'Remove Technology Disclosure Headers',
    category: 'TECH_VERSION',
    version: '1.0.0',
    approvedSteps: [
      'Disable framework banner headers such as X-Powered-By, X-AspNet-Version, or X-Runtime in backend code.',
      'In Express.js / Node.js, add app.disable("x-powered-by") before defining routes.',
      'In PHP, set expose_php = Off in php.ini.',
    ],
  },
  INCONCLUSIVE_WAF: {
    code: 'INCONCLUSIVE_WAF',
    title: 'Review WAF Blocking Rules for Scan Probes',
    category: 'TECH_VERSION',
    version: '1.0.0',
    approvedSteps: [
      'Verify whether automated security scans should be allowlisted in your Web Application Firewall (WAF) or CDN rules.',
      'Review WAF challenge logs to determine if security probes were challenged by CAPTCHAs or JavaScript challenges.',
    ],
  },
  TYPOSQUAT_DOMAIN_DETECTED: {
    code: 'TYPOSQUAT_DOMAIN_DETECTED',
    title: 'Monitor & Mitigate Look-Alike Brand Domain',
    category: 'BRAND_THREAT',
    version: '1.0.0',
    approvedSteps: [
      'Monitor the suspicious look-alike domain continuously for infrastructure changes (DNS records, MX records, SSL certs).',
      'Evaluate defensive registration or dispute proceedings (e.g. UDRP or registrar abuse complaint) if brand infringement is evident.',
      'Warn customer service and IT support staff of potential executive or customer impersonation campaigns.',
    ],
  },
  TYPOSQUAT_ACTIVE_MX: {
    code: 'TYPOSQUAT_ACTIVE_MX',
    title: 'Defend Against Active Look-Alike Mail Infrastructure',
    category: 'BRAND_THREAT',
    version: '1.0.0',
    approvedSteps: [
      'Block the look-alike domain on your corporate email gateway and spam filters to prevent inbound phishing lures.',
      'Ensure strict DMARC enforcement (p=reject) with SPF and DKIM configured on your legitimate brand domain.',
      'Submit an abuse notification to the mail provider hosting the suspicious MX server.',
    ],
  },
  TYPOSQUAT_SUSPICIOUS_ASN: {
    code: 'TYPOSQUAT_SUSPICIOUS_ASN',
    title: 'Mitigate High-Abuse Hosting Infrastructure',
    category: 'BRAND_THREAT',
    version: '1.0.0',
    approvedSteps: [
      'Submit a domain suspension request to the registrar and abuse contact for the bulletproof or high-abuse hosting provider.',
      'Add the hosting IP address and autonomous system number (ASN) to network egress and firewall monitoring rules.',
    ],
  },
  TYPOSQUAT_FRESH_REGISTRATION: {
    code: 'TYPOSQUAT_FRESH_REGISTRATION',
    title: 'Alert on Recently Registered Typosquat Domain',
    category: 'BRAND_THREAT',
    version: '1.0.0',
    approvedSteps: [
      'Flag the recently registered domain in internal security alerts as high risk for imminent phishing campaigns.',
      'Search public Certificate Transparency logs for newly issued SSL certificates associated with the look-alike hostname.',
      'Consider immediate preemptive domain takedown request if trademark infringement is clearly established.',
    ],
  },
  'EMAIL-SPF-MISSING': {
    code: 'EMAIL-SPF-MISSING',
    title: 'Publish SPF Authorization Record',
    category: 'EMAIL_SECURITY',
    version: '1.0.0',
    approvedSteps: [
      'Publish a TXT record for your apex domain defining authorized sending servers (e.g. "v=spf1 include:_spf.google.com ~all").',
      'Audit third-party SaaS vendors sending emails on your behalf (SendGrid, Mailchimp, Zendesk) and include their SPF mechanisms.',
      'Ensure the SPF record terminates with ~all (SoftFail) or -all (HardFail) to instruct receiving mail servers on handling unauthorized IP origins.',
    ],
  },
  'EMAIL-DMARC-MISSING': {
    code: 'EMAIL-DMARC-MISSING',
    title: 'Publish DMARC Domain Authentication Policy',
    category: 'EMAIL_SECURITY',
    version: '1.0.0',
    approvedSteps: [
      'Create a DNS TXT record at _dmarc.yourdomain.com with initial monitoring policy "v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com".',
      'Analyze incoming aggregate DMARC reports to identify legitimate email sources failing alignment.',
      'Transition policy to quarantine (p=quarantine) and ultimately strict rejection (p=reject) once all authorized sending services are aligned.',
    ],
  },
  'DNS-CAA-MISSING': {
    code: 'DNS-CAA-MISSING',
    title: 'Configure Certificate Authority Authorization (CAA)',
    category: 'DNS_HEALTH',
    version: '1.0.0',
    approvedSteps: [
      'Add CAA DNS records specifying explicitly authorized Certificate Authorities (e.g. 0 issue "letsencrypt.org").',
      'Include an iodef directive to receive notification alerts if unauthorized certificate issuance attempts occur.',
      'Test CAA policy propagation across global DNS resolvers before enforcing wildcards.',
    ],
  },
  'DNS-DANGLING-NS-DELEGATION': {
    code: 'DNS-DANGLING-NS-DELEGATION',
    title: 'Decommission Dangling Nameserver Delegation',
    category: 'DNS_HEALTH',
    version: '1.0.0',
    approvedSteps: [
      'Remove dangling, non-resolving nameservers from your domain registrar and authoritative NS records.',
      'Verify that all remaining nameservers respond authoritatively with identical zone serial numbers.',
      'Audit historical DNS records for abandoned delegations to third-party hosted DNS providers.',
    ],
  },
  'EXPOSURE-GIT-FOLDER': {
    code: 'EXPOSURE-GIT-FOLDER',
    title: 'Block Public Web Access to .git Directory',
    category: 'SENSITIVE_EXPOSURE',
    version: '1.0.0',
    approvedSteps: [
      'Configure your reverse proxy, CDN, or web server (Nginx, Apache, Caddy, Cloudflare) to deny all requests to "/.git".',
      'Ensure CI/CD build scripts do not copy the .git repository metadata folder into the public web root.',
      'Rotate all API keys, database credentials, and secrets that ever existed in git commit history.',
    ],
  },
  'EXPOSURE-ENV-FILE': {
    code: 'EXPOSURE-ENV-FILE',
    title: 'Restrict Access to .env File & Rotate Leaked Secrets',
    category: 'SENSITIVE_EXPOSURE',
    version: '1.0.0',
    approvedSteps: [
      'Block public web server access to .env and dotfiles immediately via web server configuration.',
      'Rotate all database credentials, master encryption keys, and third-party API tokens exposed in the file.',
      'Audit application server access logs to identify any unauthorized IP addresses that downloaded the environment file.',
    ],
  },
  'TAKEOVER-DANGLING-CNAME': {
    code: 'TAKEOVER-DANGLING-CNAME',
    title: 'Remediate Dangling CNAME Subdomain Takeover',
    category: 'SUBDOMAIN_TAKEOVER',
    version: '1.0.0',
    approvedSteps: [
      'Delete the dangling CNAME DNS record immediately from your DNS control panel.',
      'Alternatively, re-claim the abandoned cloud resource name in your cloud provider account (AWS S3, GitHub, Heroku, Netlify, Vercel).',
      'Audit public certificate logs to check if an unauthorized actor previously generated certificates for the hijacked hostname.',
    ],
  },
  'CLOUD-BUCKET-PUBLIC-LISTING-S3': {
    code: 'CLOUD-BUCKET-PUBLIC-LISTING-S3',
    title: 'Block Public Read Access to AWS S3 Bucket',
    category: 'CLOUD_STORAGE',
    version: '1.1.0',
    approvedSteps: [
      'Enable "Block Public Access" at both the bucket and AWS account level in the Amazon S3 console.',
      'Audit bucket ACLs and Bucket Policies to remove anonymous or wildcard ("Principal": "*") read permissions.',
      'Rotate any confidential files, database dumps, or credentials stored inside the public bucket.',
      'Enable AWS CloudTrail S3 Data Events to audit access logs for unauthorized object downloads.',
    ],
  },
  'CLOUD-BUCKET-PUBLIC-LISTING-GCS': {
    code: 'CLOUD-BUCKET-PUBLIC-LISTING-GCS',
    title: 'Secure Public Google Cloud Storage (GCS) Bucket',
    category: 'CLOUD_STORAGE',
    version: '1.1.0',
    approvedSteps: [
      'Enable uniform bucket-level access in the Google Cloud Console.',
      'Remove allUsers and allAuthenticatedUsers members from bucket IAM permissions and ACLs.',
      'Enforce Organization Policy "constraints/storage.publicAccessPrevention" across the GCP project.',
      'Audit Cloud Audit Logs to review all unauthenticated object download requests.',
    ],
  },
  'CLOUD-BUCKET-PUBLIC-LISTING-AZURE': {
    code: 'CLOUD-BUCKET-PUBLIC-LISTING-AZURE',
    title: 'Disable Public Anonymous Access to Azure Blob Storage',
    category: 'CLOUD_STORAGE',
    version: '1.1.0',
    approvedSteps: [
      'Set "Allow Blob anonymous access" to Disabled at the Azure Storage Account level.',
      'Change the container public access level from "Blob" or "Container" to "Private (no anonymous access)".',
      'Use Shared Access Signatures (SAS) with minimal expiration times and granular permissions for external file sharing.',
      'Enable Azure Storage logging to inspect historical anonymous read transactions.',
    ],
  },
  'CLOUD-BUCKET-EXISTS-PRIVATE': {
    code: 'CLOUD-BUCKET-EXISTS-PRIVATE',
    title: 'Maintain Private Cloud Bucket Security Hygiene',
    category: 'CLOUD_STORAGE',
    version: '1.1.0',
    approvedSteps: [
      'Maintain existing private access controls and verify bucket policies disallow anonymous reads.',
      'Audit bucket access logs periodically for enumeration attempts.',
      'Apply bucket versioning and object lock where appropriate for immutable data protection.',
    ],
  },
  'CORS-MISCONFIG-CREDENTIALS-REFLECTED': {
    code: 'CORS-MISCONFIG-CREDENTIALS-REFLECTED',
    title: 'Remediate Insecure CORS Origin Reflection with Credentials',
    category: 'WEB_HYGIENE',
    version: '1.1.0',
    approvedSteps: [
      'Never reflect the incoming request Origin header blindly into Access-Control-Allow-Origin when Access-Control-Allow-Credentials is true.',
      'Implement an explicit server-side whitelist of trusted origin domains (e.g., https://app.example.com).',
      'Validate request Origin against the whitelist using strict equality rather than regular expression prefix/suffix matching.',
      'Return a 403 Forbidden or omit CORS headers entirely when an unrecognized third-party origin sends credentials.',
    ],
  },
  'CORS-WILDCARD-ORIGIN': {
    code: 'CORS-WILDCARD-ORIGIN',
    title: 'Review Permissive Wildcard CORS Header',
    category: 'WEB_HYGIENE',
    version: '1.1.0',
    approvedSteps: [
      'Ensure "Access-Control-Allow-Origin: *" is restricted solely to public API endpoints containing non-confidential data.',
      'Ensure authenticated user endpoints restrict origins to authorized application domains.',
    ],
  },
  'MIXED-CONTENT-ACTIVE-SCRIPT': {
    code: 'MIXED-CONTENT-ACTIVE-SCRIPT',
    title: 'Eliminate Active Mixed Content (Insecure Scripts over HTTPS)',
    category: 'WEB_HYGIENE',
    version: '1.1.0',
    approvedSteps: [
      'Update all script source URLs from http:// to https:// in HTML templates and frontend source code.',
      'Add the "upgrade-insecure-requests" directive to your Content-Security-Policy (CSP) header.',
      'Configure automated CI/CD linting rules to prevent unencrypted asset URLs in production builds.',
    ],
  },
  'MIXED-CONTENT-PASSIVE-RESOURCE': {
    code: 'MIXED-CONTENT-PASSIVE-RESOURCE',
    title: 'Upgrade Passive Mixed Content Media and Stylesheets to HTTPS',
    category: 'WEB_HYGIENE',
    version: '1.1.0',
    approvedSteps: [
      'Migrate image, audio, video, and stylesheet links from http:// to https://.',
      'Enforce Content-Security-Policy with block-all-mixed-content or upgrade-insecure-requests.',
    ],
  },
  'SRI-MISSING-EXTERNAL-RESOURCE': {
    code: 'SRI-MISSING-EXTERNAL-RESOURCE',
    title: 'Implement Subresource Integrity (SRI) on Third-Party Scripts',
    category: 'WEB_HYGIENE',
    version: '1.1.0',
    approvedSteps: [
      'Generate cryptographic integrity hashes (sha384 or sha512) for all external CDN scripts.',
      'Add the "integrity" attribute and "crossorigin=anonymous" to every third-party script tag.',
      'Host business-critical JavaScript dependencies on your first-party origin or managed CDN distribution.',
    ],
  },
  'COOKIE-FLAG-SESSION-INSECURE': {
    code: 'COOKIE-FLAG-SESSION-INSECURE',
    title: 'Enforce HttpOnly, Secure, and SameSite Flags on Session Cookies',
    category: 'WEB_HYGIENE',
    version: '1.1.0',
    approvedSteps: [
      'Configure application session management to set the HttpOnly flag on session cookies to block XSS credential theft.',
      'Set the Secure flag on all session cookies to ensure transmission occurs exclusively over TLS/HTTPS.',
      'Set SameSite=Lax (or SameSite=Strict) on session cookies to protect against Cross-Site Request Forgery (CSRF).',
    ],
  },
  'COOKIE-FLAG-GENERAL-INSECURE': {
    code: 'COOKIE-FLAG-GENERAL-INSECURE',
    title: 'Configure Secure and SameSite Attributes on Cookies',
    category: 'WEB_HYGIENE',
    version: '1.1.0',
    approvedSteps: [
      'Add the Secure attribute to all cookies issued on HTTPS endpoints.',
      'Specify SameSite=Lax or SameSite=None; Secure for cross-origin tracking cookies.',
    ],
  },
  'JS-LIB-VULN-OUTDATED': {
    code: 'JS-LIB-VULN-OUTDATED',
    title: 'Upgrade Outdated and Vulnerable Client-Side JavaScript Libraries',
    category: 'WEB_HYGIENE',
    version: '1.1.0',
    approvedSteps: [
      'Upgrade vulnerable frontend libraries (e.g. jQuery >= 3.5.1, Lodash >= 4.17.21, Bootstrap >= 4.3.1) to patched versions.',
      'Integrate automated dependency auditing tools (such as npm audit, Dependabot, or Snyk) into the CI/CD pipeline.',
      'Remove unneeded legacy libraries and migrate modern code to native browser APIs.',
    ],
  },
  'WP-CORE-OUTDATED': {
    code: 'WP-CORE-OUTDATED',
    title: 'Upgrade Outdated WordPress Core CMS Installation',
    category: 'CMS_VULNERABILITY',
    version: '1.1.0',
    approvedSteps: [
      'Update WordPress core to the latest release through the administrative dashboard or WP-CLI (wp core update).',
      'Enable automatic background minor updates in wp-config.php (define("WP_AUTO_UPDATE_CORE", true)).',
      'Backup the WordPress database and wp-content directory before performing major version upgrades.',
    ],
  },
  'WP-OUTDATED-PLUGIN-DETECTED': {
    code: 'WP-OUTDATED-PLUGIN-DETECTED',
    title: 'Update Vulnerable WordPress Plugin',
    category: 'CMS_VULNERABILITY',
    version: '1.1.0',
    approvedSteps: [
      'Update the identified WordPress plugin to the latest version immediately through the admin dashboard or WP-CLI.',
      'Deactivate and completely delete the plugin if it has been abandoned by its developer or is no longer required.',
      'Monitor WordPress security advisories and security plugins (e.g. Wordfence) for zero-day notices.',
    ],
  },
  'WP-LOGIN-EXPOSED': {
    code: 'WP-LOGIN-EXPOSED',
    title: 'Harden WordPress Administrative Login Interface (wp-login.php)',
    category: 'CMS_VULNERABILITY',
    version: '1.1.0',
    approvedSteps: [
      'Enable Multi-Factor Authentication (MFA) for all WordPress administrator and editor accounts.',
      'Deploy rate limiting and CAPTCHA challenge rules at your Cloudflare / CDN WAF layer on /wp-login.php.',
      'Restrict access to wp-admin and wp-login.php to corporate IP ranges or VPN gateways where possible.',
    ],
  },
  'WP-XMLRPC-EXPOSED': {
    code: 'WP-XMLRPC-EXPOSED',
    title: 'Disable or Restrict WordPress XML-RPC API',
    category: 'CMS_VULNERABILITY',
    version: '1.1.0',
    approvedSteps: [
      'Disable XML-RPC in web server configuration by blocking access to /xmlrpc.php in Nginx or Apache (.htaccess).',
      'Alternatively, add "add_filter(\'xmlrpc_enabled\', \'__return_false\');" to your theme functions.php or site-specific plugin.',
      'Block unauthenticated XML-RPC requests at your CDN/WAF layer if the WordPress mobile app or legacy Jetpack features are not needed.',
    ],
  },
  'TRUST-SECURITY-TXT-PRESENT': {
    code: 'TRUST-SECURITY-TXT-PRESENT',
    title: 'Maintain RFC 9116 security.txt Vulnerability Disclosure Policy',
    category: 'SENSITIVE_EXPOSURE',
    version: '1.1.0',
    approvedSteps: [
      'Ensure contact email addresses, PGP keys, and canonical links in /.well-known/security.txt are active.',
      'Update the Expires: field prior to expiration to maintain valid RFC 9116 compliance.',
    ],
  },
  'TRUST-COOKIE-CONSENT-DETECTED': {
    code: 'TRUST-COOKIE-CONSENT-DETECTED',
    title: 'Maintain Consent Management Platform (CMP) Compliance',
    category: 'WEB_HYGIENE',
    version: '1.1.0',
    approvedSteps: [
      'Ensure cookie consent choices correctly prevent third-party analytics and marketing trackers from firing before user consent.',
      'Keep CMP vendor libraries and privacy policies synchronized with GDPR, ePrivacy, and CCPA regulatory requirements.',
    ],
  },
  'DB-REDIS-UNAUTHENTICATED': {
    code: 'DB-REDIS-UNAUTHENTICATED',
    title: 'Secure Publicly Exposed Unauthenticated Redis Instance',
    category: 'EXPOSED_SERVICES',
    version: '1.2.0',
    approvedSteps: [
      'Enable authentication in redis.conf by setting a strong password with requirepass.',
      'Bind Redis strictly to localhost (127.0.0.1) or an internal VPC network interface (bind 127.0.0.1 ::1).',
      'Ensure protected-mode is enabled (protected-mode yes) to reject non-local connections when no password is set.',
      'Block external inbound traffic to port 6379 at the perimeter firewall and cloud security group level.',
    ],
  },
  'DB-ELASTICSEARCH-UNAUTHENTICATED': {
    code: 'DB-ELASTICSEARCH-UNAUTHENTICATED',
    title: 'Enable Authentication and Access Control for Elasticsearch Cluster',
    category: 'EXPOSED_SERVICES',
    version: '1.2.0',
    approvedSteps: [
      'Enable Elastic Stack Security by setting xpack.security.enabled: true in elasticsearch.yml.',
      'Set strong passwords for the built-in superuser (elastic) and system accounts using elasticsearch-setup-passwords.',
      'Configure TLS/HTTPS for node-to-node transport and HTTP REST client interfaces.',
      'Place Elasticsearch behind an authenticated API gateway or private reverse proxy, blocking port 9200 from public internet access.',
    ],
  },
  'DB-MONGODB-UNAUTHENTICATED': {
    code: 'DB-MONGODB-UNAUTHENTICATED',
    title: 'Enable Authorization and Bind MongoDB to Private Interfaces',
    category: 'EXPOSED_SERVICES',
    version: '1.2.0',
    approvedSteps: [
      'Enable role-based access control in mongod.conf by configuring security.authorization: enabled.',
      'Create a root user in the admin database with appropriate administrative roles before exposing the daemon.',
      'Bind mongod exclusively to private internal network interfaces (bindIp: 127.0.0.1,10.x.x.x) rather than 0.0.0.0.',
      'Block inbound TCP port 27017 at the perimeter firewall and cloud security group level.',
    ],
  },
  'SMTP-OPEN-RELAY-SUSPECTED': {
    code: 'SMTP-OPEN-RELAY-SUSPECTED',
    title: 'Remediate Open Mail Relay Configuration on SMTP Server',
    category: 'EMAIL_SECURITY',
    version: '1.2.0',
    approvedSteps: [
      'Configure your Mail Transfer Agent (MTA) to reject unauthenticated mail destined for external domains.',
      'In Postfix, ensure smtpd_recipient_restrictions includes reject_unauth_destination and permit_sasl_authenticated.',
      'Require mandatory TLS encryption and SASL authentication for all outbound relay submissions on port 587.',
      'Audit trusted network blocks in mynetworks to prevent unauthorized internal or cloud IP ranges from relaying freely.',
    ],
  },
  'SECRET-LEAK-GITHUB-CREDENTIAL': {
    code: 'SECRET-LEAK-GITHUB-CREDENTIAL',
    title: 'Revoke Publicly Leaked GitHub Credential and Purge Git History',
    category: 'SENSITIVE_EXPOSURE',
    version: '1.3.0',
    approvedSteps: [
      'Immediately revoke the leaked API key, AWS token, or database password in your cloud or database provider console.',
      'Review access logs for the exposed service to identify unauthorized API requests or abnormal IP activity.',
      'Purge the compromised credentials from the git commit history using git-filter-repo or BFG Repo-Cleaner.',
      'Implement automated pre-commit secret scanning hooks and enable GitHub Secret Scanning in the target repository.',
    ],
  },
  'SECRET-LEAK-GITHUB-MENTION': {
    code: 'SECRET-LEAK-GITHUB-MENTION',
    title: 'Review Public GitHub Code Mention for Unintended Data Exposure',
    category: 'SENSITIVE_EXPOSURE',
    version: '1.3.0',
    approvedSteps: [
      'Inspect the public GitHub repository and referenced file to assess context and exposure risks.',
      'Confirm that internal domain names, test endpoints, or private architecture details are not inadvertently disclosed.',
      'Request repository owners or employees to remove sensitive corporate domain names from public open-source repos.',
    ],
  },
  'SECRET-LEAK-PASTE-MATCH': {
    code: 'SECRET-LEAK-PASTE-MATCH',
    title: 'Remediate Exposure in Public Paste Archive',
    category: 'SENSITIVE_EXPOSURE',
    version: '1.3.0',
    approvedSteps: [
      'Inspect the content of the referenced public paste to determine whether credentials, configuration dumps, or logs were exposed.',
      'Revoke and rotate any secrets, session tokens, or passwords identified within the paste payload.',
      'Submit an abuse/takedown request to the paste host to remove the exposed confidential information.',
      'Audit user authentication logs and monitor for credential-stuffing or password-spraying attempts.',
    ],
  },
  'BREACH-EXPOSURE-EMAIL-FOUND': {
    code: 'BREACH-EXPOSURE-EMAIL-FOUND',
    title: 'Reset Passwords and Enforce Multi-Factor Authentication for Breached Accounts',
    category: 'SENSITIVE_EXPOSURE',
    version: '1.3.0',
    approvedSteps: [
      'Force an immediate password reset for the affected corporate email address across all internal systems and SSO providers.',
      'Enforce phishing-resistant Multi-Factor Authentication (MFA) using FIDO2/WebAuthn or hardware security keys.',
      'Audit active user sessions and terminate existing tokens to prevent unauthorized session hijacking.',
      'Educate users against password re-use between external third-party services and corporate network accounts.',
    ],
  },
};

/**
 * Validates whether candidate remediation steps match approved guidance in the library.
 * Rejects steps that have zero resemblance or are completely outside the library.
 */
export function validateRemediationSteps(
  code: string,
  candidateSteps: string[]
): { valid: boolean; rejectedSteps: string[]; approvedSteps: string[] } {
  const guidance = REMEDIATION_LIBRARY[code];
  if (!guidance || !guidance.approvedSteps || guidance.approvedSteps.length === 0) {
    // If no specific guidance for this code, allow general transport/header steps
    return { valid: true, rejectedSteps: [], approvedSteps: candidateSteps };
  }

  const approved = guidance.approvedSteps;
  const rejectedSteps: string[] = [];

  for (const step of candidateSteps) {
    const stepLower = step.toLowerCase().trim();
    // Check if step contains significant semantic overlap with any approved step
    const matchesAny = approved.some((app) => {
      const appLower = app.toLowerCase();
      // Exact substring or major keyword overlap
      if (appLower.includes(stepLower) || stepLower.includes(appLower)) return true;

      // Token overlap: count matching words (> 3 chars)
      const stepTokens = stepLower.split(/\W+/).filter((t) => t.length > 3);
      const appTokens = new Set(appLower.split(/\W+/).filter((t) => t.length > 3));
      if (stepTokens.length === 0) return false;
      const matchCount = stepTokens.filter((t) => appTokens.has(t)).length;
      return matchCount / stepTokens.length >= 0.4; // 40% keyword overlap
    });

    if (!matchesAny) {
      rejectedSteps.push(step);
    }
  }

  return {
    valid: rejectedSteps.length === 0,
    rejectedSteps,
    approvedSteps: guidance.approvedSteps,
  };
}
