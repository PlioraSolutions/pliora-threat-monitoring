import { CheckPlugin, PluginContext, PluginResult, FindingSpec, PluginEvidenceSpec } from './types';

// Curated vulnerable JavaScript library database for client-side dependency audit
interface KnownVulnerableLib {
  name: string;
  pattern: RegExp;
  extractVersion: (urlOrContent: string) => string | null;
  isVulnerable: (version: string) => { vulnerable: boolean; cve?: string; advisory?: string };
}

function parseSemver(ver: string): [number, number, number] {
  const parts = ver.split('.').map((p) => parseInt(p.replace(/\D/g, ''), 10) || 0);
  return [parts[0] || 0, parts[1] || 0, parts[2] || 0];
}

function isOlderThan(actual: string, target: [number, number, number]): boolean {
  const [maj, min, pat] = parseSemver(actual);
  if (maj !== target[0]) return maj < target[0];
  if (min !== target[1]) return min < target[1];
  return pat < target[2];
}

const VULNERABLE_LIBRARIES: KnownVulnerableLib[] = [
  {
    name: 'jQuery',
    pattern: /jquery[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)|jquery\/([0-9]+\.[0-9]+(?:\.[0-9]+)?)|jQuery\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i,
    extractVersion: (str: string) => {
      const match = str.match(/jquery[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)|jquery\/([0-9]+\.[0-9]+(?:\.[0-9]+)?)|jQuery\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i);
      return match ? match[1] || match[2] || match[3] || null : null;
    },
    isVulnerable: (ver: string) => {
      if (isOlderThan(ver, [3, 5, 0])) {
        return {
          vulnerable: true,
          cve: 'CVE-2020-11022 / CVE-2020-11023',
          advisory: 'Cross-Site Scripting (XSS) vulnerability in jQuery.htmlPrefilter regex',
        };
      }
      return { vulnerable: false };
    },
  },
  {
    name: 'Lodash',
    pattern: /lodash[@/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)|lodash\.min\.js\?v=([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i,
    extractVersion: (str: string) => {
      const match = str.match(/lodash[@/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)|lodash\.min\.js\?v=([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i);
      return match ? match[1] || match[2] || null : null;
    },
    isVulnerable: (ver: string) => {
      if (isOlderThan(ver, [4, 17, 21])) {
        return {
          vulnerable: true,
          cve: 'CVE-2021-23337 / CVE-2019-10744',
          advisory: 'Prototype Pollution & Remote Command Injection vulnerability in Lodash template/set/defaultsDeep',
        };
      }
      return { vulnerable: false };
    },
  },
  {
    name: 'Bootstrap',
    pattern: /bootstrap[@/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i,
    extractVersion: (str: string) => {
      const match = str.match(/bootstrap[@/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i);
      return match ? match[1] || null : null;
    },
    isVulnerable: (ver: string) => {
      if (isOlderThan(ver, [4, 3, 1])) {
        return {
          vulnerable: true,
          cve: 'CVE-2019-8331',
          advisory: 'XSS vulnerability in Bootstrap tooltip and popover plugins',
        };
      }
      return { vulnerable: false };
    },
  },
  {
    name: 'AngularJS',
    pattern: /angular(?:js)?[@/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i,
    extractVersion: (str: string) => {
      const match = str.match(/angular(?:js)?[@/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i);
      return match ? match[1] || null : null;
    },
    isVulnerable: (ver: string) => {
      const [maj] = parseSemver(ver);
      if (maj === 1) {
        return {
          vulnerable: true,
          cve: 'CVE-2020-35764',
          advisory: 'End-of-Life AngularJS 1.x carries unpatched universal XSS and sandbox bypass vulnerabilities',
        };
      }
      return { vulnerable: false };
    },
  },
];

// Common Consent Management Platform (CMP) indicators
const CMP_SIGNATURES = [
  { name: 'OneTrust', pattern: /onetrust|optanon|cookielaw|otsdk/i },
  { name: 'Cookiebot', pattern: /cookiebot/i },
  { name: 'Didomi', pattern: /didomi/i },
  { name: 'Klaro', pattern: /klaro/i },
  { name: 'Termly', pattern: /termly/i },
  { name: 'Usercentrics', pattern: /usercentrics/i },
  { name: 'Axeptio', pattern: /axeptio/i },
  { name: 'Complianz', pattern: /cmplz|complianz/i },
];

export const webHygieneCheckPlugin: CheckPlugin = {
  id: 'web-hygiene-check',
  name: 'Web Application Hygiene & Client Security Analyzer',
  category: 'WEB_HYGIENE',
  defaultConfidence: 'CONFIRMED',

  appliesTo(asset: { fqdn: string; type: string }) {
    return Boolean(asset.fqdn && asset.fqdn.includes('.'));
  },

  async run(asset, ctx: PluginContext): Promise<PluginResult> {
    const startTime = Date.now();
    const findings: FindingSpec[] = [];
    const evidence: PluginEvidenceSpec[] = [];
    const host = asset.fqdn.toLowerCase().trim();

    let baseUrl = `https://${host}`;
    let baseResponse: Response | null = null;
    let baseHtml = '';

    // 1. Initial Web Fetch (HTTPS first, HTTP fallback)
    try {
      baseResponse = await ctx.safeFetch(baseUrl, {
        method: 'GET',
        timeoutMs: ctx.timeoutMs,
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; PlioraThreatMonitor/1.0; +https://pliora.io)',
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
      });
      baseHtml = await baseResponse.text();
    } catch {
      try {
        baseUrl = `http://${host}`;
        baseResponse = await ctx.safeFetch(baseUrl, {
          method: 'GET',
          timeoutMs: ctx.timeoutMs,
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; PlioraThreatMonitor/1.0; +https://pliora.io)',
            Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          },
        });
        baseHtml = await baseResponse.text();
      } catch {
        // Unreachable host
      }
    }

    if (!baseResponse) {
      return {
        status: 'FAILED',
        evidence: [],
        findings: [],
        error: `Unable to establish HTTP/HTTPS connection to ${host}`,
        durationMs: Date.now() - startTime,
      };
    }

    const rawHeaders: Record<string, string> = {};
    baseResponse.headers.forEach((val, key) => {
      rawHeaders[key.toLowerCase()] = val;
    });

    // ==========================================
    // 2. CORS Misconfiguration Check
    // ==========================================
    try {
      const testOrigin = 'https://evil-attacker.com';
      const corsResponse = await ctx.safeFetch(baseUrl, {
        method: 'OPTIONS',
        timeoutMs: Math.min(ctx.timeoutMs || 4000, 3000),
        headers: {
          Origin: testOrigin,
          'Access-Control-Request-Method': 'POST',
        },
      });

      const allowOrigin = corsResponse.headers.get('access-control-allow-origin');
      const allowCredentials = corsResponse.headers.get('access-control-allow-credentials');

      if (allowOrigin && allowCredentials && allowCredentials.toLowerCase() === 'true') {
        if (allowOrigin === '*' || allowOrigin === testOrigin) {
          findings.push({
            category: 'WEB_HYGIENE',
            findingCode: 'CORS-MISCONFIG-CREDENTIALS-REFLECTED',
            title: 'Critical CORS Misconfiguration: Origin Reflected with Credentials Enabled',
            description: `The application reflects arbitrary origins ("${allowOrigin}") combined with "Access-Control-Allow-Credentials: true". Any malicious website can forge cross-origin authenticated requests and read sensitive authenticated data from ${host}.`,
            severity: 'HIGH',
            confidence: 'CONFIRMED',
            remediationGuidance: 'Never combine wildcard origin reflection with Access-Control-Allow-Credentials: true. Maintain an explicit whitelist of approved partner origins.',
          });
        }
      } else if (allowOrigin === '*') {
        findings.push({
          category: 'WEB_HYGIENE',
          findingCode: 'CORS-WILDCARD-ORIGIN',
          title: 'Permissive CORS Policy: Wildcard (*) Origin Configured',
          description: `The application returned "Access-Control-Allow-Origin: *". While permissible on public APIs, this exposes internal data endpoints if sensitive resources are returned.`,
          severity: 'INFORMATIONAL',
          confidence: 'CONFIRMED',
          remediationGuidance: 'Ensure wildcards are restricted only to purely public endpoints without sensitive responses.',
        });
      }
    } catch {
      // CORS probe failed
    }

    // ==========================================
    // 3. Mixed Content Detection (on HTTPS)
    // ==========================================
    const isHttps = baseUrl.startsWith('https://');
    if (isHttps && baseHtml) {
      // Active Mixed Content: <script src="http://...">
      const activeScriptMatches = Array.from(baseHtml.matchAll(/<script[^>]+src=["'](http:\/\/[^"']+)["']/gi));
      if (activeScriptMatches.length > 0) {
        const sampleUrls = activeScriptMatches.slice(0, 3).map((m) => m[1]);
        findings.push({
          category: 'WEB_HYGIENE',
          findingCode: 'MIXED-CONTENT-ACTIVE-SCRIPT',
          title: 'Active Mixed Content: Insecure HTTP Script Loaded over HTTPS',
          description: `The HTTPS page loads active JavaScript resources over plaintext HTTP (${sampleUrls.join(', ')}). Attackers in a machine-in-the-middle position can tamper with these scripts to execute arbitrary JavaScript in victim browsers.`,
          severity: 'HIGH',
          confidence: 'CONFIRMED',
          remediationGuidance: 'Update all script tags to load over HTTPS or use protocol-relative URLs. Enforce "upgrade-insecure-requests" via Content-Security-Policy.',
        });
      }

      // Passive Mixed Content: <img src="http://..."> or <link rel="stylesheet" href="http://...">
      const passiveMatches = Array.from(
        baseHtml.matchAll(/<(?:img|audio|video)[^>]+src=["'](http:\/\/[^"']+)["']|<link[^>]+href=["'](http:\/\/[^"']+)["']/gi)
      );
      if (passiveMatches.length > 0) {
        const sampleUrls = passiveMatches.slice(0, 3).map((m) => m[1] || m[2]);
        findings.push({
          category: 'WEB_HYGIENE',
          findingCode: 'MIXED-CONTENT-PASSIVE-RESOURCE',
          title: 'Passive Mixed Content: Insecure HTTP Media / Stylesheet Loaded over HTTPS',
          description: `The HTTPS page includes passive resources over plaintext HTTP (${sampleUrls.join(', ')}). This degrades TLS security posture and can cause browser mixed content warnings.`,
          severity: 'LOW',
          confidence: 'CONFIRMED',
          remediationGuidance: 'Migrate all media and asset URLs to HTTPS or your secure CDN endpoint.',
        });
      }
    }

    // ==========================================
    // 4. Subresource Integrity (SRI) on Third-Party Scripts
    // ==========================================
    if (baseHtml) {
      const scriptTags = Array.from(baseHtml.matchAll(/<script\s+([^>]*?)>/gi));
      const missingSriExternalScripts: string[] = [];

      for (const tag of scriptTags) {
        const fullAttributes = tag[1] || '';
        const srcMatch = fullAttributes.match(/src=["'](https?:\/\/[^"']+)["']/i);
        if (!srcMatch) continue;

        const scriptUrl = srcMatch[1];
        try {
          const parsed = new URL(scriptUrl);
          // Check if third-party origin
          const isThirdParty = parsed.hostname !== host && !parsed.hostname.endsWith(`.${host}`);
          if (isThirdParty) {
            const hasIntegrity = /integrity=["'][^"']+["']/i.test(fullAttributes);
            if (!hasIntegrity) {
              missingSriExternalScripts.push(scriptUrl);
            }
          }
        } catch {}
      }

      if (missingSriExternalScripts.length > 0) {
        const sampleScripts = missingSriExternalScripts.slice(0, 3);
        findings.push({
          category: 'WEB_HYGIENE',
          findingCode: 'SRI-MISSING-EXTERNAL-RESOURCE',
          title: 'Missing Subresource Integrity (SRI) on Cross-Origin Scripts',
          description: `Cross-origin scripts are loaded from external CDNs without Subresource Integrity (SRI) hashes (${sampleScripts.join(', ')}). If the third-party CDN is compromised, malicious code can be injected without detection.`,
          severity: 'LOW',
          confidence: 'CONFIRMED',
          remediationGuidance: 'Add "integrity" attributes with sha384 or sha512 hashes and "crossorigin=anonymous" to all external third-party script tags.',
        });
      }
    }

    // ==========================================
    // 5. Cookie Security Flags (Set-Cookie)
    // ==========================================
    const setCookieHeaders = baseResponse.headers.get('set-cookie');
    if (setCookieHeaders) {
      const cookies = setCookieHeaders.split(/,(?=[^;]+;)/g);
      for (const cookieStr of cookies) {
        const cookieNameMatch = cookieStr.match(/^\s*([^=;]+)=/);
        const cookieName = cookieNameMatch ? cookieNameMatch[1].trim() : 'Unknown';
        const lowerCookie = cookieStr.toLowerCase();

        const hasHttpOnly = lowerCookie.includes('httponly');
        const hasSecure = lowerCookie.includes('secure');
        const hasSameSite = lowerCookie.includes('samesite');

        const isSessionCookie = /session|sid|token|auth|jwt|connect\.sid|phpsessid|laravel_session|rails_session/i.test(
          cookieName
        );

        if (isSessionCookie && (!hasHttpOnly || !hasSecure)) {
          findings.push({
            category: 'WEB_HYGIENE',
            findingCode: 'COOKIE-FLAG-SESSION-INSECURE',
            title: `Insecure Session Cookie Configuration: "${cookieName}"`,
            description: `Session cookie "${cookieName}" is missing critical security attributes (${[
              !hasHttpOnly ? 'HttpOnly' : null,
              !hasSecure ? 'Secure' : null,
            ]
              .filter(Boolean)
              .join(', ')}). Without HttpOnly, sessions can be stolen via XSS. Without Secure, cookies can be leaked in plaintext over HTTP.`,
            severity: 'MEDIUM',
            confidence: 'CONFIRMED',
            remediationGuidance: `Configure your session manager to set "HttpOnly; Secure; SameSite=Lax" (or SameSite=Strict) on "${cookieName}".`,
          });
        } else if (!hasSecure && isHttps) {
          findings.push({
            category: 'WEB_HYGIENE',
            findingCode: 'COOKIE-FLAG-GENERAL-INSECURE',
            title: `Cookie "${cookieName}" Missing Secure Flag on HTTPS Endpoint`,
            description: `Cookie "${cookieName}" lacks the "Secure" flag on an HTTPS website, allowing browsers to transmit it across unencrypted HTTP connections.`,
            severity: 'LOW',
            confidence: 'CONFIRMED',
            remediationGuidance: `Add the "Secure" attribute to "${cookieName}" in your web server or application framework.`,
          });
        }
      }
    }

    // ==========================================
    // 6. Client-Side JS Library Vulnerability Scanning
    // ==========================================
    if (baseHtml) {
      for (const lib of VULNERABLE_LIBRARIES) {
        let detectedVersion: string | null = null;

        // Search in script src URLs
        const scriptUrls = Array.from(baseHtml.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)).map((m) => m[1]);
        for (const url of scriptUrls) {
          const v = lib.extractVersion(url);
          if (v) {
            detectedVersion = v;
            break;
          }
        }

        // If not found in URLs, check inline script text
        if (!detectedVersion) {
          const v = lib.extractVersion(baseHtml);
          if (v) detectedVersion = v;
        }

        if (detectedVersion) {
          const vulCheck = lib.isVulnerable(detectedVersion);
          if (vulCheck.vulnerable) {
            // STRICT CONFIDENCE GUARD: Version matching is hypothesis-based, NEVER exceeds MEDIUM confidence
            const confidence: 'MEDIUM' = 'MEDIUM';

            findings.push({
              category: 'WEB_HYGIENE',
              findingCode: 'JS-LIB-VULN-OUTDATED',
              title: `Vulnerable Client-Side Library Detected: ${lib.name} ${detectedVersion}`,
              description: `The application loads an outdated version of ${lib.name} (${detectedVersion}) which has known publicly documented vulnerabilities: ${
                vulCheck.cve || 'Known vulnerability'
              }. Advisory: ${vulCheck.advisory}.`,
              severity: 'MEDIUM',
              confidence,
              remediationGuidance: `Upgrade ${lib.name} to the latest stable release (e.g. jQuery >= 3.5.1, Lodash >= 4.17.21, Bootstrap >= 4.3.1).`,
            });
          }
        }
      }
    }

    // ==========================================
    // 7. Cookie Consent Management Platform (Trust Indicator)
    // ==========================================
    if (baseHtml) {
      for (const cmp of CMP_SIGNATURES) {
        if (cmp.pattern.test(baseHtml)) {
          findings.push({
            category: 'WEB_HYGIENE',
            findingCode: 'TRUST-COOKIE-CONSENT-DETECTED',
            title: `Consent Management Platform Verified: ${cmp.name}`,
            description: `A recognized Cookie Consent Management Platform (${cmp.name}) was detected on ${host}. Demonstrates active user privacy and ePrivacy / GDPR compliance mechanisms.`,
            severity: 'INFORMATIONAL',
            confidence: 'CONFIRMED',
            remediationGuidance: 'Ensure cookie preferences accurately block third-party analytics and ad cookies until explicit consent is granted.',
          });
          break;
        }
      }
    }

    evidence.push({
      checkType: 'WEB_HYGIENE',
      rawObservation: {
        host,
        baseUrl,
        statusCode: baseResponse.status,
        headers: rawHeaders,
        scannedAt: new Date().toISOString(),
      },
    });

    return {
      status: 'COMPLETED',
      evidence,
      findings,
      durationMs: Date.now() - startTime,
    };
  },
};
