import { NextRequest, NextResponse } from 'next/server';
import dns from 'dns';
import net from 'net';
import tls from 'tls';
import http from 'http';
import https from 'https';
import { isSafeExternalIp } from '@/lib/security';

const dnsPromises = dns.promises;
// Ensure robust public DNS resolution across environments
try {
  dns.setServers(['8.8.8.8', '1.1.1.1']);
} catch (e) {}

interface AssessmentFinding {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  confidence: 'CONFIRMED' | 'HIGH' | 'MEDIUM';
  asset: string;
  plainSummary: string;
  businessImpact: string;
  remediation: string;
  checkType: string;
  evidence: string;
}

// Helper to normalize user input domain
function normalizeDomain(input: string): string {
  return input
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/:\d+$/, '');
}

// Validate domain format
function isValidDomain(domain: string): boolean {
  if (!domain || domain.length > 253) return false;
  // Standard hostname regex (must have at least one dot, no spaces or special chars)
  const domainRegex = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;
  return domainRegex.test(domain);
}

// Perform real TLS handshake and certificate extraction
function checkTlsHandshake(domain: string, port = 443, timeoutMs = 6000): Promise<{
  success: boolean;
  protocol?: string;
  cipher?: any;
  peerCert?: any;
  authorized?: boolean;
  authorizationError?: string;
  daysRemaining?: number;
  isExpired?: boolean;
  error?: string;
}> {
  return new Promise((resolve) => {
    let resolved = false;

    const socket = tls.connect(
      {
        host: domain,
        port,
        servername: domain,
        timeout: timeoutMs,
        rejectUnauthorized: false, // We inspect authorization manually
      },
      () => {
        if (resolved) return;
        resolved = true;
        try {
          const peerCert = socket.getPeerCertificate(true);
          const protocol = socket.getProtocol() || undefined;
          const cipher = socket.getCipher();
          const authorized = socket.authorized;
          const authorizationError = socket.authorizationError ? String(socket.authorizationError) : undefined;

          let daysRemaining: number | undefined;
          let isExpired = false;

          if (peerCert && peerCert.valid_to) {
            const expiryTime = new Date(peerCert.valid_to).getTime();
            daysRemaining = Math.floor((expiryTime - Date.now()) / (1000 * 60 * 60 * 24));
            isExpired = daysRemaining < 0;
          }

          socket.end();
          resolve({
            success: true,
            protocol,
            cipher,
            peerCert,
            authorized,
            authorizationError,
            daysRemaining,
            isExpired,
          });
        } catch (err: any) {
          socket.destroy();
          resolve({ success: false, error: err.message });
        }
      }
    );

    socket.on('error', (err) => {
      if (!resolved) {
        resolved = true;
        resolve({ success: false, error: err.message });
      }
    });

    socket.on('timeout', () => {
      if (!resolved) {
        resolved = true;
        socket.destroy();
        resolve({ success: false, error: 'TLS connection timed out' });
      }
    });
  });
}

// Perform real HTTP request, follow redirect if present, and extract headers & status
function checkHttpEndpoint(
  domain: string,
  protocol: 'http' | 'https' = 'https',
  timeoutMs = 6000,
  maxRedirects = 1
): Promise<{
  success: boolean;
  statusCode?: number;
  headers?: Record<string, string>;
  redirectLocation?: string;
  rawHead?: string;
  error?: string;
}> {
  return new Promise((resolve) => {
    const client = protocol === 'https' ? https : http;
    const port = protocol === 'https' ? 443 : 80;
    let resolved = false;

    const req = client.request(
      {
        host: domain,
        port,
        path: '/',
        method: 'GET',
        timeout: timeoutMs,
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; PlioraThreatMonitor/1.0; +https://pliora.io)',
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
        rejectUnauthorized: false,
      },
      (res) => {
        if (resolved) return;
        resolved = true;

        const headers: Record<string, string> = {};
        for (const [key, val] of Object.entries(res.headers)) {
          if (val) {
            headers[key.toLowerCase()] = Array.isArray(val) ? val.join(', ') : val;
          }
        }

        // Build raw response head string
        const lines: string[] = [`HTTP/${res.httpVersion} ${res.statusCode} ${res.statusMessage || 'OK'}`];
        for (const [k, v] of Object.entries(headers)) {
          lines.push(`${k}: ${v}`);
        }

        const redirectLocation = res.headers.location;
        res.resume(); // Discard body quickly

        // If redirect and we have budget, inspect landing page headers
        if (
          maxRedirects > 0 &&
          res.statusCode &&
          [301, 302, 307, 308].includes(res.statusCode) &&
          redirectLocation
        ) {
          try {
            const nextUrl = redirectLocation.startsWith('http')
              ? new URL(redirectLocation)
              : new URL(redirectLocation, `${protocol}://${domain}`);

            const nextProtocol = (nextUrl.protocol.replace(':', '') || 'https') as 'http' | 'https';
            const nextDomain = nextUrl.hostname;
            const nextPort = nextUrl.port ? parseInt(nextUrl.port, 10) : nextProtocol === 'https' ? 443 : 80;

            const targetClient = nextProtocol === 'https' ? https : http;
            const redirectReq = targetClient.request(
              {
                host: nextDomain,
                port: nextPort,
                path: `${nextUrl.pathname || '/'}${nextUrl.search || ''}`,
                method: 'GET',
                timeout: timeoutMs,
                headers: {
                  'User-Agent': 'Mozilla/5.0 (compatible; PlioraThreatMonitor/1.0; +https://pliora.io)',
                  Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                },
                rejectUnauthorized: false,
              },
              (targetRes) => {
                const targetHeaders: Record<string, string> = {};
                for (const [key, val] of Object.entries(targetRes.headers)) {
                  if (val) {
                    targetHeaders[key.toLowerCase()] = Array.isArray(val) ? val.join(', ') : val;
                  }
                }
                targetRes.resume();

                // Merge headers (target landing headers take priority)
                const mergedHeaders = { ...headers, ...targetHeaders };
                const mergedLines = [
                  ...lines,
                  `\n--- [FOLLOWED REDIRECT ${res.statusCode} -> ${redirectLocation}] ---`,
                  `HTTP/${targetRes.httpVersion} ${targetRes.statusCode} ${targetRes.statusMessage || 'OK'}`,
                ];
                for (const [k, v] of Object.entries(targetHeaders)) {
                  mergedLines.push(`${k}: ${v}`);
                }

                resolve({
                  success: true,
                  statusCode: targetRes.statusCode,
                  headers: mergedHeaders,
                  redirectLocation,
                  rawHead: mergedLines.join('\n'),
                });
              }
            );

            redirectReq.on('error', () => {
              resolve({
                success: true,
                statusCode: res.statusCode,
                headers,
                redirectLocation,
                rawHead: lines.join('\n'),
              });
            });

            redirectReq.on('timeout', () => {
              redirectReq.destroy();
              resolve({
                success: true,
                statusCode: res.statusCode,
                headers,
                redirectLocation,
                rawHead: lines.join('\n'),
              });
            });

            redirectReq.end();
            return;
          } catch (e) {
            // parse error fallback
          }
        }

        resolve({
          success: true,
          statusCode: res.statusCode,
          headers,
          redirectLocation,
          rawHead: lines.join('\n'),
        });
      }
    );

    req.on('error', (err) => {
      if (!resolved) {
        resolved = true;
        resolve({ success: false, error: err.message });
      }
    });

    req.on('timeout', () => {
      if (!resolved) {
        resolved = true;
        req.destroy();
        resolve({ success: false, error: 'HTTP request timed out' });
      }
    });

    req.end();
  });
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const rawDomain = body?.domain;

    if (!rawDomain || typeof rawDomain !== 'string') {
      return NextResponse.json(
        { success: false, error: 'A domain name is required.' },
        { status: 400 }
      );
    }

    const domain = normalizeDomain(rawDomain);

    if (!isValidDomain(domain)) {
      return NextResponse.json(
        { success: false, error: `"${rawDomain}" is not a valid public domain format.` },
        { status: 400 }
      );
    }

    // SSRF Guard: prevent loopback or private scanning
    if (
      domain === 'localhost' ||
      domain.endsWith('.local') ||
      domain.endsWith('.internal') ||
      domain.endsWith('.test') ||
      domain === '127.0.0.1' ||
      domain === '::1'
    ) {
      return NextResponse.json(
        { success: false, error: 'Scanning internal, localhost, or reserved domains is not permitted.' },
        { status: 400 }
      );
    }

    // 1. Resolve DNS A/AAAA records
    let aRecords: string[] = [];
    let aaaaRecords: string[] = [];
    try {
      aRecords = await dnsPromises.resolve4(domain);
    } catch (e) {
      try {
        const lookup = await dnsPromises.lookup(domain, { all: true });
        aRecords = lookup.filter((r) => r.family === 4).map((r) => r.address);
        aaaaRecords = lookup.filter((r) => r.family === 6).map((r) => r.address);
      } catch (err: any) {
        return NextResponse.json(
          {
            success: false,
            error: `Unable to resolve DNS for "${domain}". Please verify the domain has active DNS records.`,
          },
          { status: 404 }
        );
      }
    }

    if (aRecords.length === 0 && aaaaRecords.length === 0) {
      return NextResponse.json(
        {
          success: false,
          error: `No A or AAAA records found for "${domain}". The domain does not appear to be active.`,
        },
        { status: 404 }
      );
    }

    // SSRF IP verification
    const primaryIp = aRecords[0] || aaaaRecords[0];
    if (primaryIp && !isSafeExternalIp(primaryIp)) {
      return NextResponse.json(
        { success: false, error: 'Target resolves to a private or internal network address.' },
        { status: 403 }
      );
    }

    // 2. Discover related subdomains via DNS queries
    const discoveredAssets = [domain];
    const commonSubdomains = ['www', 'api', 'mail'];
    await Promise.all(
      commonSubdomains.map(async (sub) => {
        try {
          const subDomain = `${sub}.${domain}`;
          const res = await dnsPromises.resolve4(subDomain);
          if (res && res.length > 0) {
            discoveredAssets.push(subDomain);
          }
        } catch (e) {}
      })
    );

    // 3. Concurrently execute live TLS check, www TLS check, HTTP inspection, and Email DNS records
    const [tlsResult, wwwTlsResult, httpsResult, httpPlainResult, txtRecords, dmarcRecords] = await Promise.all([
      checkTlsHandshake(domain, 443, 6000),
      checkTlsHandshake(`www.${domain}`, 443, 4000).catch(() => ({ success: false } as any)),
      checkHttpEndpoint(domain, 'https', 6000),
      checkHttpEndpoint(domain, 'http', 5000),
      dnsPromises.resolveTxt(domain).catch(() => [] as string[][]),
      dnsPromises.resolveTxt(`_dmarc.${domain}`).catch(() => [] as string[][]),
    ]);

    const findings: AssessmentFinding[] = [];
    let findingCounter = 1;
    const nextId = () => `FIND-${String(findingCounter++).padStart(2, '0')}`;

    // ----------------------------------------------------
    // Audit: TLS / SSL Security
    // ----------------------------------------------------
    let tlsSummary = {
      verified: false,
      issuer: 'None detected',
      validTo: 'N/A',
      protocol: 'N/A',
      cipher: 'N/A',
      daysRemaining: 0,
    };

    if (tlsResult.success && tlsResult.peerCert) {
      const cert = tlsResult.peerCert;
      const issuerName = cert.issuer?.O || cert.issuer?.CN || 'Unknown Certificate Authority';
      tlsSummary = {
        verified: Boolean(tlsResult.authorized),
        issuer: issuerName,
        validTo: cert.valid_to || 'N/A',
        protocol: tlsResult.protocol || 'TLS',
        cipher: tlsResult.cipher?.name || 'Standard',
        daysRemaining: tlsResult.daysRemaining || 0,
      };

      // Add SANs to discovered assets if matching apex
      if (cert.subjectaltname) {
        const sans = cert.subjectaltname
          .split(',')
          .map((s: string) => s.trim().replace(/^DNS:/, ''))
          .filter((s: string) => s.endsWith(`.${domain}`) && !s.includes('*'));
        for (const s of sans.slice(0, 5)) {
          if (!discoveredAssets.includes(s)) {
            discoveredAssets.push(s);
          }
        }
      }

      // Check for expired cert
      if (tlsResult.isExpired) {
        const wwwHasValidCert = wwwTlsResult?.success && !wwwTlsResult.isExpired;
        const wwwCertValidTo = wwwTlsResult?.peerCert?.valid_to;

        const plainSummary = wwwHasValidCert
          ? `The SSL/TLS certificate for root domain ${domain} expired on ${cert.valid_to}. While www.${domain} holds a valid certificate (valid until ${wwwCertValidTo}), browsers establish the TLS handshake before processing HTTP 301/302 redirects. As a result, anyone typing "${domain}" in a browser is immediately blocked by a full-screen security warning.`
          : `The cryptographic certificate for ${domain} expired on ${cert.valid_to}. Modern web browsers show full-screen security warnings (NET::ERR_CERT_DATE_INVALID) to all visitors.`;

        const remediation = wwwHasValidCert
          ? `Renew the certificate on ${domain} or point your apex DNS record to the same host/CDN providing the valid certificate for www.${domain}.`
          : `Renew and replace the SSL certificate for ${domain} immediately with your Certificate Authority (${issuerName}).`;

        findings.push({
          id: nextId(),
          title: 'SSL/TLS certificate has expired',
          severity: 'CRITICAL',
          confidence: 'CONFIRMED',
          asset: domain,
          plainSummary,
          businessImpact: 'Total customer abandonment, degraded brand trust, loss of web traffic, and failure of all API/webhook integrations.',
          remediation,
          checkType: 'TRANSPORT_SECURITY',
          evidence: `Certificate Expiry: ${cert.valid_to}\nIssuer: ${issuerName}\nSubject: ${cert.subject?.CN || domain}\nSerial: ${cert.serialNumber || 'N/A'}${wwwHasValidCert ? `\n\n[DIAGNOSTIC]: www.${domain} certificate is valid until ${wwwCertValidTo}. Apex domain is missing renewal.` : ''}`,
        });
      } else if (tlsResult.daysRemaining !== undefined && tlsResult.daysRemaining < 14) {
        findings.push({
          id: nextId(),
          title: `SSL/TLS certificate expiring soon (${tlsResult.daysRemaining} days remaining)`,
          severity: 'HIGH',
          confidence: 'CONFIRMED',
          asset: domain,
          plainSummary: `The SSL certificate expires in ${tlsResult.daysRemaining} days (${cert.valid_to}). Failure to renew will lead to browser interstitial blocking.`,
          businessImpact: 'Imminent outage of all customer-facing transactions and SSL handshake failures across all integrated clients.',
          remediation: `Trigger automated certificate renewal via ACME / Let's Encrypt or your SSL vendor before ${cert.valid_to}.`,
          checkType: 'TRANSPORT_SECURITY',
          evidence: `Certificate Valid To: ${cert.valid_to}\nDays Remaining: ${tlsResult.daysRemaining}\nIssuer: ${issuerName}`,
        });
      }

      // Check for self-signed or untrusted CA (deduplicated: ignore if failure was solely due to CERT_HAS_EXPIRED)
      if (
        !tlsResult.authorized &&
        tlsResult.authorizationError &&
        tlsResult.authorizationError !== 'CERT_HAS_EXPIRED' &&
        !tlsResult.isExpired
      ) {
        findings.push({
          id: nextId(),
          title: `Untrusted or Self-Signed SSL Certificate (${tlsResult.authorizationError})`,
          severity: 'HIGH',
          confidence: 'CONFIRMED',
          asset: domain,
          plainSummary: `The TLS certificate presented by ${domain} failed validation: ${tlsResult.authorizationError}.`,
          businessImpact: 'Browsers reject connection with SEC_ERROR_UNKNOWN_ISSUER or similar security warnings.',
          remediation: `Install a valid certificate issued by a trusted public Certificate Authority recognized by operating system trust stores.`,
          checkType: 'TRANSPORT_SECURITY',
          evidence: `Verification Error: ${tlsResult.authorizationError}\nIssuer: ${issuerName}\nSubject: ${cert.subject?.CN || domain}`,
        });
      }
    } else if (!tlsResult.success) {
      findings.push({
        id: nextId(),
        title: 'HTTPS port 443 closed or TLS handshake failed',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        asset: domain,
        plainSummary: `Unable to complete a TLS cryptographic handshake on port 443: ${tlsResult.error || 'Connection refused'}.`,
        businessImpact: 'Users cannot access the site over secure HTTPS encryption.',
        remediation: 'Configure an SSL certificate and bind an HTTPS listener on port 443.',
        checkType: 'TRANSPORT_SECURITY',
        evidence: `TLS Connection Error: ${tlsResult.error || 'Handshake failed'} on ${domain}:443`,
      });
    }

    // ----------------------------------------------------
    // Audit: HTTP Security Headers
    // ----------------------------------------------------
    const headers = httpsResult.headers || httpPlainResult.headers || {};
    const serverHeader = headers['server'];
    const xPoweredBy = headers['x-powered-by'];
    const rawHead = httpsResult.rawHead || httpPlainResult.rawHead || '';

    // 1. Check Content-Security-Policy (CSP)
    if (headers['content-security-policy']) {
      // Active enforcing Content-Security-Policy header is present
    } else if (headers['content-security-policy-report-only']) {
      findings.push({
        id: nextId(),
        title: 'Content-Security-Policy (CSP) active in Report-Only mode',
        severity: 'INFORMATIONAL',
        confidence: 'CONFIRMED',
        asset: domain,
        plainSummary: `The web server transmits a Content-Security-Policy in Report-Only mode. Violation reports are logged to telemetry endpoints, but script execution is not actively blocked.`,
        businessImpact: 'Provides real-time visibility and reporting for potential script violations without breaking dynamic third-party integrations or analytics tags.',
        remediation: 'Review collected violation reports at your report-uri endpoint and prepare to transition verified directives into an active Content-Security-Policy header.',
        checkType: 'HTTP_SECURITY_HEADERS',
        evidence: `Detected Header:\nContent-Security-Policy-Report-Only: ${headers['content-security-policy-report-only'].slice(0, 350)}...`,
      });
    } else {
      findings.push({
        id: nextId(),
        title: 'Missing Content-Security-Policy (CSP) header',
        severity: 'LOW',
        confidence: 'CONFIRMED',
        asset: domain,
        plainSummary: `The web server does not enforce an active Content-Security-Policy header to restrict sources of executable scripts, stylesheets, and frames.`,
        businessImpact: 'Defense-in-depth weakness. If an application injection vulnerability is introduced, malicious scripts can execute in client browsers.',
        remediation: 'Implement a Content-Security-Policy header in your reverse proxy or CDN restricting script execution to authorized domains and cryptographic nonces.',
        checkType: 'HTTP_SECURITY_HEADERS',
        evidence: `${rawHead.slice(0, 450)}\n\n[AUDIT: content-security-policy header is absent]`,
      });
    }

    // 2. Check HTTP Strict Transport Security (HSTS)
    const KNOWN_PRELOADED_DOMAINS = new Set([
      'google.com',
      'youtube.com',
      'gmail.com',
      'apple.com',
      'github.com',
      'microsoft.com',
      'facebook.com',
      'instagram.com',
      'whatsapp.com',
      'twitter.com',
      'x.com',
      'netflix.com',
      'amazon.com',
      'cloudflare.com',
    ]);
    const isPreloaded = KNOWN_PRELOADED_DOMAINS.has(domain);

    if (!headers['strict-transport-security'] && !isPreloaded) {
      findings.push({
        id: nextId(),
        title: 'Missing HTTP Strict-Transport-Security (HSTS) header',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        asset: domain,
        plainSummary: `The server does not transmit a Strict-Transport-Security header, allowing user connections to be initiated over unencrypted plain HTTP.`,
        businessImpact: 'Vulnerable to SSL stripping and Man-in-the-Middle (MitM) attacks on untrusted Wi-Fi networks.',
        remediation: 'Add Strict-Transport-Security: max-age=63072000; includeSubDomains; preload to all HTTPS responses.',
        checkType: 'HTTP_SECURITY_HEADERS',
        evidence: `${rawHead.slice(0, 450)}\n\n[AUDIT: strict-transport-security header is absent]`,
      });
    }

    // 3. Check X-Frame-Options (Clickjacking)
    if (!headers['x-frame-options'] && !headers['content-security-policy']?.includes('frame-ancestors')) {
      findings.push({
        id: nextId(),
        title: 'Missing X-Frame-Options clickjacking protection',
        severity: 'MEDIUM',
        confidence: 'CONFIRMED',
        asset: domain,
        plainSummary: `The response lacks an X-Frame-Options header or CSP frame-ancestors directive, allowing external websites to embed ${domain} in transparent iframe overlays.`,
        businessImpact: 'Attacker can trick users into clicking buttons or submitting credentials via deceptive overlay framing (Clickjacking).',
        remediation: 'Send X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN on all HTML responses.',
        checkType: 'HTTP_SECURITY_HEADERS',
        evidence: `${rawHead.slice(0, 450)}\n\n[AUDIT: x-frame-options header is absent]`,
      });
    }

    // 4. Check X-Content-Type-Options
    if (!headers['x-content-type-options'] || !headers['x-content-type-options'].includes('nosniff')) {
      findings.push({
        id: nextId(),
        title: 'Missing X-Content-Type-Options nosniff header',
        severity: 'LOW',
        confidence: 'CONFIRMED',
        asset: domain,
        plainSummary: `The server does not specify X-Content-Type-Options: nosniff, permitting browsers to MIME-sniff responses away from the declared content-type.`,
        businessImpact: 'Allows user-uploaded non-executable files (e.g. images) to be executed as HTML/JavaScript in older user agents.',
        remediation: 'Configure your web server or CDN to send X-Content-Type-Options: nosniff.',
        checkType: 'HTTP_SECURITY_HEADERS',
        evidence: `${rawHead.slice(0, 450)}\n\n[AUDIT: x-content-type-options header is absent or does not contain 'nosniff']`,
      });
    }

    // 5. Check Server Version Disclosure
    if (serverHeader || xPoweredBy) {
      const banner = [serverHeader && `Server: ${serverHeader}`, xPoweredBy && `X-Powered-By: ${xPoweredBy}`]
        .filter(Boolean)
        .join('; ');

      findings.push({
        id: nextId(),
        title: 'Server and technology banner disclosure',
        severity: 'LOW',
        confidence: 'CONFIRMED',
        asset: domain,
        plainSummary: `The web server broadcasts its underlying infrastructure stack in HTTP response headers (${banner}).`,
        businessImpact: 'Provides reconnaissance intelligence to threat actors searching for specific version vulnerabilities and zero-day exploits.',
        remediation: 'Strip or genericize the Server and X-Powered-By response headers at the reverse proxy or CDN layer.',
        checkType: 'SERVER_FINGERPRINT',
        evidence: `Disclosed Header(s):\n${serverHeader ? `Server: ${serverHeader}\n` : ''}${xPoweredBy ? `X-Powered-By: ${xPoweredBy}\n` : ''}`,
      });
    }

    // ----------------------------------------------------
    // Audit: Email Spoofing Defenses (SPF & DMARC)
    // ----------------------------------------------------
    // Flatten TXT records
    const allTxt = txtRecords.map((r) => r.join(''));
    const spfRecord = allTxt.find((t) => t.toLowerCase().startsWith('v=spf1'));
    const dmarcFlat = dmarcRecords.map((r) => r.join(''));
    const dmarcRecord = dmarcFlat.find((t) => t.toLowerCase().startsWith('v=dmarc1'));

    // Check SPF
    if (!spfRecord) {
      findings.push({
        id: nextId(),
        title: 'Missing SPF (Sender Policy Framework) record',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        asset: domain,
        plainSummary: `No SPF TXT record was found on ${domain}. Mail servers worldwide cannot verify whether outgoing emails claiming to be from your domain are authentic.`,
        businessImpact: 'Criminals can forge emails from @' + domain + ' to execute CEO fraud, invoice scamming, and customer phishing.',
        remediation: `Publish an SPF TXT record on ${domain} specifying authorized mail relays (e.g. "v=spf1 include:_spf.google.com -all").`,
        checkType: 'EMAIL_SECURITY',
        evidence: `Queried TXT records for ${domain}:\n${allTxt.length > 0 ? allTxt.map((t) => `  - ${t}`).join('\n') : '  (No TXT records found)'}\n[AUDIT: v=spf1 definition is missing]`,
      });
    } else if (spfRecord.includes('+all')) {
      findings.push({
        id: nextId(),
        title: 'Permissive SPF record permits all hosts (+all)',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        asset: domain,
        plainSummary: `The SPF record uses "+all", explicitly authorizing any server on the internet to send email on behalf of ${domain}.`,
        businessImpact: 'Completely invalidates SPF protections, enabling spoofed phishing emails to pass SPF authentication.',
        remediation: 'Change "+all" to "-all" (hard fail) or "~all" (soft fail) in your SPF TXT record.',
        checkType: 'EMAIL_SECURITY',
        evidence: `Found SPF Record: "${spfRecord}"\n[AUDIT: Dangerous "+all" directive allows universal spoofing]`,
      });
    }

    // Check DMARC
    if (!dmarcRecord) {
      findings.push({
        id: nextId(),
        title: 'Missing DMARC policy allows brand impersonation and phishing',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        asset: domain,
        plainSummary: `No DMARC record exists at _dmarc.${domain}. Receiving mail providers will not reject forged messages sent under your brand name.`,
        businessImpact: 'Direct customer phishing, reputation damage, and increased risk of corporate email compromise.',
        remediation: `Create a TXT record at _dmarc.${domain} with a policy such as "v=DMARC1; p=reject; rua=mailto:dmarc@${domain}".`,
        checkType: 'EMAIL_SECURITY',
        evidence: `Queried TXT records for _dmarc.${domain}:\n  (No DMARC records found)`,
      });
    } else {
      const pMatch = dmarcRecord.match(/p\s*=\s*(none|quarantine|reject)/i);
      const policy = pMatch ? pMatch[1].toLowerCase() : 'none';

      if (policy === 'none') {
        findings.push({
          id: nextId(),
          title: 'DMARC policy set to none (monitoring only, spoofed emails delivered)',
          severity: 'MEDIUM',
          confidence: 'CONFIRMED',
          asset: domain,
          plainSummary: `The DMARC policy on ${domain} is set to "p=none". While reports are collected, fraudulent spoofed emails are not blocked by recipient mailboxes.`,
          businessImpact: 'Phishing emails spoofing your domain continue to be delivered to recipient inboxes without enforcement.',
          remediation: 'Upgrade your DMARC policy from "p=none" to "p=quarantine" or "p=reject".',
          checkType: 'EMAIL_SECURITY',
          evidence: `Found DMARC Record: "${dmarcRecord}"\n[AUDIT: Policy is p=none — spoofed mail will not be blocked]`,
        });
      }

      const spMatch = dmarcRecord.match(/sp\s*=\s*(none|quarantine|reject)/i);
      if (spMatch && spMatch[1].toLowerCase() === 'none' && policy !== 'none') {
        findings.push({
          id: nextId(),
          title: 'DMARC subdomain policy explicitly set to none (sp=none)',
          severity: 'MEDIUM',
          confidence: 'CONFIRMED',
          asset: domain,
          plainSummary: `The apex domain has enforcement, but subdomains are explicitly exempted with "sp=none". Threat actors can spoof subdomains (e.g. support.${domain}).`,
          businessImpact: 'Allows targeted spear-phishing using legitimate-looking subdomains of your company.',
          remediation: 'Remove "sp=none" or set it to match apex policy ("sp=quarantine" or "sp=reject").',
          checkType: 'EMAIL_SECURITY',
          evidence: `Found DMARC Record: "${dmarcRecord}"\n[AUDIT: Subdomain policy is sp=none]`,
        });
      }
    }

    // ----------------------------------------------------
    // Compute Security Posture & Grade
    // ----------------------------------------------------
    const counts = {
      critical: findings.filter((f) => f.severity === 'CRITICAL').length,
      high: findings.filter((f) => f.severity === 'HIGH').length,
      medium: findings.filter((f) => f.severity === 'MEDIUM').length,
      low: findings.filter((f) => f.severity === 'LOW' || f.severity === 'INFORMATIONAL').length,
    };

    let posture = 100;
    posture -= counts.critical * 25;
    posture -= counts.high * 15;
    posture -= counts.medium * 8;
    posture -= counts.low * 3;
    posture = Math.max(10, Math.min(100, posture));

    let grade: 'A' | 'B' | 'C' | 'D' | 'F' = 'A';
    if (posture < 60) grade = 'F';
    else if (posture < 70) grade = 'D';
    else if (posture < 80) grade = 'C';
    else if (posture < 90) grade = 'B';

    return NextResponse.json({
      success: true,
      domain,
      ip: primaryIp,
      allIps: [...aRecords, ...aaaaRecords],
      assetsEnumerated: discoveredAssets.length,
      discoveredAssets,
      server: serverHeader || 'Generic Cloud Gateway',
      tls: tlsSummary,
      securityPosture: posture,
      grade,
      findings,
      counts,
      scannedAt: new Date().toISOString(),
    });
  } catch (err: any) {
    console.error('[FreeAssessment API Error]:', err);
    return NextResponse.json(
      { success: false, error: err.message || 'An unexpected error occurred during perimeter assessment.' },
      { status: 500 }
    );
  }
}
