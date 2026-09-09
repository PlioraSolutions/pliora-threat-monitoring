import { CheckPlugin, PluginContext, PluginResult, FindingSpec } from './types';
import { detectWafOrBotBlock } from './waf';

interface FingerprintSignal {
  source: 'HEADER' | 'BODY_META' | 'BODY_ASSET';
  technology: string;
  version?: string;
  rawIndicator: string;
}

export const techFingerprintCheckPlugin: CheckPlugin = {
  id: 'tech-fingerprint-check',
  name: 'Technology & Server Fingerprint Analyzer',
  category: 'TECH_VERSION',
  defaultConfidence: 'MEDIUM', // Non-negotiable ceiling: version strings are hypotheses, not proof of vulnerability

  appliesTo(asset: { fqdn: string; type: string }) {
    return Boolean(asset.fqdn && asset.fqdn.includes('.'));
  },

  async run(asset, ctx: PluginContext): Promise<PluginResult> {
    const startTime = Date.now();
    const findings: FindingSpec[] = [];
    const detectedSignals: FingerprintSignal[] = [];

    let targetUrl = `https://${asset.fqdn}`;
    let response: Response | null = null;
    let bodyText = '';

    try {
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

      // WAF Detection
      const wafCheck = detectWafOrBotBlock(response.status, response.headers, bodyText);
      if (wafCheck.isWafDetected) {
        return {
          status: 'INCONCLUSIVE',
          isWafDetected: true,
          evidence: [
            {
              checkType: 'TECH_FINGERPRINT',
              rawObservation: {
                targetUrl,
                wafDetails: wafCheck,
                note: 'Fingerprinting inconclusive due to upstream WAF / anti-bot challenge.',
                analyzedAt: new Date().toISOString(),
              },
            },
          ],
          findings: [],
          error: `WAF encountered (${wafCheck.vendor || 'Unknown'})`,
          durationMs: Date.now() - startTime,
        };
      }

      // 1. Server Header Analysis
      const serverHeader = response.headers.get('server');
      if (serverHeader && serverHeader.trim()) {
        const parts = serverHeader.trim().split('/');
        const tech = parts[0];
        const ver = parts[1] || undefined;

        detectedSignals.push({
          source: 'HEADER',
          technology: tech,
          version: ver,
          rawIndicator: `Server: ${serverHeader}`,
        });

        findings.push({
          category: 'TECH_VERSION',
          findingCode: `TECH-SERVER-BANNER-${tech.toUpperCase().replace(/[^A-Z0-9]/g, '')}`,
          title: `Server Software Banner Disclosed: ${tech}${ver ? ' ' + ver : ''}`,
          description: `The web server exposed its software identity and/or version in the HTTP Server response header ("${serverHeader}"). Version disclosures assist threat actors in targeting version-specific exploits.`,
          severity: ver ? 'LOW' : 'INFORMATIONAL',
          confidence: 'MEDIUM',
          remediationGuidance: 'Configure your web server (e.g. server_tokens off in nginx, ServerSignature Off in Apache) to suppress version details in response headers.',
        });
      }

      // 2. X-Powered-By Header Analysis
      const xPoweredBy = response.headers.get('x-powered-by');
      if (xPoweredBy && xPoweredBy.trim()) {
        const parts = xPoweredBy.trim().split('/');
        const tech = parts[0];
        const ver = parts[1] || undefined;

        detectedSignals.push({
          source: 'HEADER',
          technology: tech,
          version: ver,
          rawIndicator: `X-Powered-By: ${xPoweredBy}`,
        });

        findings.push({
          category: 'TECH_VERSION',
          findingCode: `TECH-POWERED-BY-${tech.toUpperCase().replace(/[^A-Z0-9]/g, '')}`,
          title: `Application Framework Disclosed: ${xPoweredBy}`,
          description: `The application framework returned the X-Powered-By header ("${xPoweredBy}"). Revealing internal runtimes simplifies targeted vulnerability enumeration.`,
          severity: 'LOW',
          confidence: 'MEDIUM',
          remediationGuidance: 'Remove the X-Powered-By header in your application framework configuration (e.g. app.disable("x-powered-by") in Express, expose_php = Off in php.ini).',
        });
      }

      // 3. HTML Generator Meta Tag Inspection
      const generatorMatch = bodyText.match(/<meta\s+name=["']generator["']\s+content=["']([^"']+)["']/i);
      if (generatorMatch && generatorMatch[1]) {
        const generatorStr = generatorMatch[1].trim();
        const genParts = generatorStr.split(/\s+/);
        const tech = genParts[0];
        const ver = genParts[1] || undefined;

        detectedSignals.push({
          source: 'BODY_META',
          technology: tech,
          version: ver,
          rawIndicator: `<meta name="generator" content="${generatorStr}">`,
        });

        findings.push({
          category: 'TECH_VERSION',
          findingCode: `TECH-META-GENERATOR-${tech.toUpperCase().replace(/[^A-Z0-9]/g, '')}`,
          title: `CMS / Framework Disclosed in HTML Generator: ${generatorStr}`,
          description: `The application exposed its CMS or site generator in the HTML meta tag ("${generatorStr}").`,
          severity: 'LOW',
          confidence: 'MEDIUM',
          remediationGuidance: 'Disable or remove generator meta tags in your CMS or template settings.',
        });
      }

      // 4. Common Static Asset Path Heuristics
      if (bodyText.includes('/wp-content/') || bodyText.includes('/wp-includes/')) {
        detectedSignals.push({
          source: 'BODY_ASSET',
          technology: 'WordPress',
          rawIndicator: '/wp-content/ path pattern',
        });
      }
      if (bodyText.includes('/_next/static/')) {
        detectedSignals.push({
          source: 'BODY_ASSET',
          technology: 'Next.js',
          rawIndicator: '/_next/static/ path pattern',
        });
      }

      return {
        status: 'COMPLETED',
        evidence: [
          {
            checkType: 'TECH_FINGERPRINT',
            rawObservation: {
              targetUrl,
              detectedSignals,
              serverHeader: serverHeader || null,
              xPoweredBy: xPoweredBy || null,
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
            checkType: 'TECH_FINGERPRINT',
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
