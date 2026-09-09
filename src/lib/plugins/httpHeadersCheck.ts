import { CheckPlugin, PluginContext, PluginResult, FindingSpec } from './types';
import { detectWafOrBotBlock } from './waf';

export const httpHeadersCheckPlugin: CheckPlugin = {
  id: 'http-security-headers-check',
  name: 'HTTP Security Headers & Policy Analyzer',
  category: 'HTTP_SECURITY_HEADERS',
  defaultConfidence: 'CONFIRMED',

  appliesTo(asset: { fqdn: string; type: string }) {
    return Boolean(asset.fqdn && asset.fqdn.includes('.'));
  },

  async run(asset, ctx: PluginContext): Promise<PluginResult> {
    const startTime = Date.now();
    const findings: FindingSpec[] = [];

    let targetUrl = `https://${asset.fqdn}`;
    let response: Response | null = null;
    let bodyText = '';

    try {
      // First attempt HTTPS
      try {
        response = await ctx.safeFetch(targetUrl, {
          method: 'GET',
          redirect: 'manual',
          timeoutMs: ctx.timeoutMs,
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; PlioraThreatMonitor/1.0; +https://pliora.io)',
            Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          },
        });
      } catch (httpsErr: any) {
        // Fallback to HTTP if HTTPS refused or failed
        targetUrl = `http://${asset.fqdn}`;
        response = await ctx.safeFetch(targetUrl, {
          method: 'GET',
          redirect: 'manual',
          timeoutMs: ctx.timeoutMs,
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; PlioraThreatMonitor/1.0; +https://pliora.io)',
            Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          },
        });
      }

      try {
        bodyText = await response.text();
      } catch {}

      // Extract all headers into a clean dictionary
      const rawHeaders: Record<string, string> = {};
      response.headers.forEach((val, key) => {
        rawHeaders[key.toLowerCase()] = val;
      });

      // 1. WAF / Anti-Bot Detection: prevent recording a false clean pass
      const wafCheck = detectWafOrBotBlock(response.status, response.headers, bodyText);
      if (wafCheck.isWafDetected) {
        return {
          status: 'INCONCLUSIVE',
          isWafDetected: true,
          evidence: [
            {
              checkType: 'HTTP_SECURITY_HEADERS',
              rawObservation: {
                targetUrl,
                statusCode: response.status,
                rawHeaders,
                wafDetails: wafCheck,
                note: 'Target presented active WAF challenge or anti-bot interstitial. Direct header analysis inconclusive.',
                analyzedAt: new Date().toISOString(),
              },
            },
          ],
          findings: [],
          error: `WAF/Bot challenge encountered (${wafCheck.vendor || 'Unknown'})`,
          durationMs: Date.now() - startTime,
        };
      }

      // 2. Strict-Transport-Security (HSTS) Check
      const hsts = rawHeaders['strict-transport-security'];
      if (!hsts) {
        findings.push({
          category: 'HTTP_SECURITY_HEADERS',
          findingCode: 'SEC-HEADER-HSTS-MISSING',
          title: 'Missing HTTP Strict Transport Security (HSTS) Header',
          description: `The HSTS header was not returned by ${asset.fqdn}. Without HSTS, initial connections may occur over unencrypted HTTP, exposing sessions to man-in-the-middle downgrade attacks (SSL stripping).`,
          severity: 'MEDIUM',
          confidence: 'CONFIRMED',
          remediationGuidance: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload to all HTTPS responses.',
        });
      } else {
        const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
        const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;

        if (maxAge < 15552000) {
          // Less than 180 days
          findings.push({
            category: 'HTTP_SECURITY_HEADERS',
            findingCode: 'SEC-HEADER-HSTS-SHORT-MAXAGE',
            title: 'HSTS max-age is Too Short',
            description: `The HSTS max-age value is ${maxAge} seconds (recommended minimum is 31536000 seconds / 1 year). Short durations leave users vulnerable during periods of absence.`,
            severity: 'LOW',
            confidence: 'CONFIRMED',
            remediationGuidance: 'Increase HSTS max-age to at least 31536000 (1 year).',
          });
        }

        if (!hsts.toLowerCase().includes('includesubdomains')) {
          findings.push({
            category: 'HTTP_SECURITY_HEADERS',
            findingCode: 'SEC-HEADER-HSTS-NO-SUBDOMAINS',
            title: 'HSTS Missing includeSubDomains Directive',
            description: 'The HSTS policy does not cover subdomains. Subdomains may remain vulnerable to MITM downgrade attacks.',
            severity: 'INFORMATIONAL',
            confidence: 'CONFIRMED',
            remediationGuidance: 'Add the includeSubDomains directive to your Strict-Transport-Security header once all subdomains support HTTPS.',
          });
        }
      }

      // 3. Content-Security-Policy (CSP) Check
      const csp = rawHeaders['content-security-policy'] || rawHeaders['content-security-policy-report-only'];
      const isReportOnly = !rawHeaders['content-security-policy'] && Boolean(rawHeaders['content-security-policy-report-only']);

      if (!csp) {
        findings.push({
          category: 'HTTP_SECURITY_HEADERS',
          findingCode: 'SEC-HEADER-CSP-MISSING',
          title: 'Missing Content Security Policy (CSP)',
          description: `No Content-Security-Policy header was detected on ${asset.fqdn}. A strong CSP prevents Cross-Site Scripting (XSS), clickjacking, and unauthorized data exfiltration.`,
          severity: 'LOW',
          confidence: 'CONFIRMED',
          remediationGuidance: 'Implement a Content-Security-Policy header defining trusted sources for scripts, styles, objects, and framing.',
        });
      } else if (isReportOnly) {
        // Report-only is an active deployment phase, informational/low note
        findings.push({
          category: 'HTTP_SECURITY_HEADERS',
          findingCode: 'SEC-HEADER-CSP-REPORT-ONLY',
          title: 'Content Security Policy Running in Report-Only Mode',
          description: `The endpoint ${asset.fqdn} provides a Content-Security-Policy-Report-Only header. Violations are reported but not actively blocked by client browsers.`,
          severity: 'INFORMATIONAL',
          confidence: 'CONFIRMED',
          remediationGuidance: 'Review violation telemetry and transition policy to enforced Content-Security-Policy header once violations are resolved.',
        });
      } else {
        const lowerCsp = csp.toLowerCase();
        if (
          lowerCsp.includes("'unsafe-inline'") ||
          lowerCsp.includes("'unsafe-eval'") ||
          lowerCsp.includes('default-src *')
        ) {
          findings.push({
            category: 'HTTP_SECURITY_HEADERS',
            findingCode: 'SEC-HEADER-CSP-WEAK',
            title: 'Permissive Content Security Policy (unsafe-inline / unsafe-eval / wildcard)',
            description: `The CSP returned contains permissive directives that weaken XSS defenses: "${csp.substring(0, 120)}...".`,
            severity: 'LOW',
            confidence: 'CONFIRMED',
            remediationGuidance: 'Refactor inline scripts to use nonces or hashes (e.g. \'nonce-...\') and avoid \'unsafe-eval\' or wildcard (*) script sources.',
          });
        }
      }

      // 4. X-Frame-Options Check (Clickjacking defense)
      const xfo = rawHeaders['x-frame-options'];
      const cspFrameAncestors = csp && csp.toLowerCase().includes('frame-ancestors');
      if (!xfo && !cspFrameAncestors) {
        findings.push({
          category: 'HTTP_SECURITY_HEADERS',
          findingCode: 'SEC-HEADER-XFO-MISSING',
          title: 'Missing X-Frame-Options / frame-ancestors (Clickjacking Risk)',
          description: `The endpoint ${asset.fqdn} does not prevent UI redressing / clickjacking via X-Frame-Options or CSP frame-ancestors. An attacker could embed this site inside a malicious iframe.`,
          severity: 'LOW',
          confidence: 'CONFIRMED',
          remediationGuidance: 'Add X-Frame-Options: DENY (or SAMEORIGIN), or configure Content-Security-Policy: frame-ancestors \'self\'.',
        });
      }

      // 5. Referrer-Policy Check
      const refPolicy = rawHeaders['referrer-policy'];
      if (!refPolicy || refPolicy.toLowerCase().includes('unsafe-url')) {
        findings.push({
          category: 'HTTP_SECURITY_HEADERS',
          findingCode: 'SEC-HEADER-REFERRER-POLICY-WEAK',
          title: 'Missing or Insecure Referrer-Policy',
          description: refPolicy
            ? `The Referrer-Policy is set to "${refPolicy}", which leaks sensitive URL paths and query parameters to third-party domains.`
            : `No Referrer-Policy header was returned by ${asset.fqdn}.`,
          severity: 'LOW',
          confidence: 'CONFIRMED',
          remediationGuidance: 'Set Referrer-Policy: strict-origin-when-cross-origin to prevent URL parameter leakage across origins.',
        });
      }

      // 6. X-Content-Type-Options Check
      const xcto = rawHeaders['x-content-type-options'];
      if (!xcto || !xcto.toLowerCase().includes('nosniff')) {
        findings.push({
          category: 'HTTP_SECURITY_HEADERS',
          findingCode: 'SEC-HEADER-XCTO-MISSING',
          title: 'Missing X-Content-Type-Options: nosniff',
          description: `The X-Content-Type-Options: nosniff header is missing on ${asset.fqdn}. Legacy browsers may attempt MIME-sniffing, leading to XSS vulnerabilities when rendering non-executable files.`,
          severity: 'LOW',
          confidence: 'CONFIRMED',
          remediationGuidance: 'Configure your web server to return X-Content-Type-Options: nosniff on all responses.',
        });
      }

      // 7. Permissions-Policy Check
      const permissionsPolicy = rawHeaders['permissions-policy'] || rawHeaders['feature-policy'];
      if (!permissionsPolicy) {
        findings.push({
          category: 'HTTP_SECURITY_HEADERS',
          findingCode: 'SEC-HEADER-PERMISSIONS-POLICY-MISSING',
          title: 'Missing Permissions-Policy Header',
          description: `The Permissions-Policy header is absent on ${asset.fqdn}. Defining permissions explicitly restricts browser features like geolocation, camera, microphone, and payment APIs.`,
          severity: 'INFORMATIONAL',
          confidence: 'CONFIRMED',
          remediationGuidance: 'Add a Permissions-Policy header disabling unnecessary browser features (e.g., camera=(), microphone=(), geolocation=()).',
        });
      }

      return {
        status: 'COMPLETED',
        evidence: [
          {
            checkType: 'HTTP_SECURITY_HEADERS',
            rawObservation: {
              targetUrl,
              statusCode: response.status,
              rawHeaders,
              checkedHeaders: {
                hsts: hsts || null,
                csp: csp || null,
                xfo: xfo || null,
                refPolicy: refPolicy || null,
                xcto: xcto || null,
                permissionsPolicy: permissionsPolicy || null,
              },
              analyzedAt: new Date().toISOString(),
            },
          },
        ],
        findings,
        durationMs: Date.now() - startTime,
      };
    } catch (err: any) {
      return {
        status: 'FAILED',
        evidence: [
          {
            checkType: 'HTTP_SECURITY_HEADERS',
            rawObservation: {
              targetUrl,
              error: err.message,
              timestamp: new Date().toISOString(),
            },
          },
        ],
        findings: [],
        error: err.message,
        durationMs: Date.now() - startTime,
      };
    }
  },
};
