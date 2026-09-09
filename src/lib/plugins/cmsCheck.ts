import { CheckPlugin, PluginContext, PluginResult, FindingSpec, PluginEvidenceSpec } from './types';

interface KnownVulnerableWpPlugin {
  slug: string;
  name: string;
  maxVulnerableVersion: [number, number, number];
  cve: string;
  advisory: string;
}

function parseSemver(ver: string): [number, number, number] {
  const parts = ver.split('.').map((p) => parseInt(p.replace(/\D/g, ''), 10) || 0);
  return [parts[0] || 0, parts[1] || 0, parts[2] || 0];
}

function isOlderOrEqual(actual: string, target: [number, number, number]): boolean {
  const [maj, min, pat] = parseSemver(actual);
  if (maj !== target[0]) return maj < target[0];
  if (min !== target[1]) return min < target[1];
  return pat <= target[2];
}

const KNOWN_VULNERABLE_PLUGINS: KnownVulnerableWpPlugin[] = [
  {
    slug: 'wp-file-manager',
    name: 'WP File Manager',
    maxVulnerableVersion: [6, 8, 0],
    cve: 'CVE-2020-25213',
    advisory: 'Unauthenticated Remote Code Execution in connector.minimal.php',
  },
  {
    slug: 'elementor',
    name: 'Elementor Website Builder',
    maxVulnerableVersion: [3, 6, 2],
    cve: 'CVE-2022-1329',
    advisory: 'Authenticated arbitrary file upload leading to Remote Code Execution',
  },
  {
    slug: 'contact-form-7',
    name: 'Contact Form 7',
    maxVulnerableVersion: [5, 3, 1],
    cve: 'CVE-2020-35489',
    advisory: 'Unrestricted file upload vulnerability leading to remote script execution',
  },
  {
    slug: 'revslider',
    name: 'Slider Revolution (RevSlider)',
    maxVulnerableVersion: [4, 2, 2],
    cve: 'CVE-2014-9734',
    advisory: 'Arbitrary file download and SQL injection vulnerability in revslider admin-ajax',
  },
  {
    slug: 'duplicator',
    name: 'Duplicator WordPress Migration Plugin',
    maxVulnerableVersion: [1, 3, 26],
    cve: 'CVE-2020-11738',
    advisory: 'Unauthenticated directory traversal and database dump download vulnerability',
  },
];

export const cmsCheckPlugin: CheckPlugin = {
  id: 'cms-check',
  name: 'WordPress & CMS Vulnerability Analyzer',
  category: 'CMS_VULNERABILITY',
  defaultConfidence: 'CONFIRMED',

  appliesTo(asset: { fqdn: string; type: string }) {
    return Boolean(asset.fqdn && asset.fqdn.includes('.'));
  },

  async run(asset, ctx: PluginContext): Promise<PluginResult> {
    const startTime = Date.now();
    const findings: FindingSpec[] = [];
    const evidence: PluginEvidenceSpec[] = [];
    const host = asset.fqdn.toLowerCase().trim();

    const baseUrl = `https://${host}`;
    let baseHtml = '';

    try {
      const homeRes = await ctx.safeFetch(baseUrl, {
        method: 'GET',
        timeoutMs: ctx.timeoutMs,
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; PlioraThreatMonitor/1.0; +https://pliora.io)',
          Accept: 'text/html,application/xhtml+xml,*/*',
        },
      });
      baseHtml = await homeRes.text();
    } catch {
      try {
        const httpHome = await ctx.safeFetch(`http://${host}`, {
          method: 'GET',
          timeoutMs: ctx.timeoutMs,
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; PlioraThreatMonitor/1.0; +https://pliora.io)',
            Accept: 'text/html,application/xhtml+xml,*/*',
          },
        });
        baseHtml = await httpHome.text();
      } catch {}
    }

    const isWordPress =
      baseHtml.includes('/wp-content/') ||
      baseHtml.includes('/wp-includes/') ||
      /<meta\s+name=["']generator["']\s+content=["']WordPress/i.test(baseHtml);

    // ==========================================
    // 1. WordPress Version Fingerprinting
    // ==========================================
    let detectedWpVersion: string | null = null;
    const metaMatch = baseHtml.match(/<meta\s+name=["']generator["']\s+content=["']WordPress\s+([0-9.]+)["']/i);
    if (metaMatch && metaMatch[1]) {
      detectedWpVersion = metaMatch[1];
    }

    // Probe readme.html if WordPress is suspected or meta wasn't exposed
    if (isWordPress || !detectedWpVersion) {
      try {
        const readmeRes = await ctx.safeFetch(`${baseUrl}/readme.html`, {
          method: 'GET',
          timeoutMs: Math.min(ctx.timeoutMs || 4000, 3000),
        });
        if (readmeRes.status === 200) {
          const readmeText = await readmeRes.text();
          const readmeMatch = readmeText.match(/Version\s+([0-9.]+)/i);
          if (readmeMatch && readmeMatch[1]) {
            detectedWpVersion = readmeMatch[1];
          }
        }
      } catch {}
    }

    if (detectedWpVersion) {
      const [maj, min] = parseSemver(detectedWpVersion);
      // WordPress current LTS branch is 6.x. Anything < 6.2 is significantly outdated
      if (maj < 6 || (maj === 6 && min < 2)) {
        findings.push({
          category: 'CMS_VULNERABILITY',
          findingCode: 'WP-CORE-OUTDATED',
          title: `Outdated WordPress Core Version Disclosed: v${detectedWpVersion}`,
          description: `WordPress core version ${detectedWpVersion} was identified on ${host}. Outdated versions have numerous known vulnerabilities across authentication, XML-RPC, and media upload subroutines.`,
          severity: 'LOW',
          confidence: 'MEDIUM', // Strict ceiling: version disclosure is hypothesis-based
          remediationGuidance: 'Update WordPress to the latest release and configure auto-updates in wp-config.php.',
        });
      }
    }

    // ==========================================
    // 2. Outdated Plugin & Theme Detection
    // ==========================================
    if (baseHtml) {
      // Find all plugins mentioned in asset URLs: /wp-content/plugins/{slug}/...ver=X.Y.Z
      const pluginMatches = Array.from(
        baseHtml.matchAll(/\/wp-content\/plugins\/([a-z0-9-_]+)\/[^"']*?[?&]ver=([0-9.]+)/gi)
      );

      const discoveredPlugins = new Map<string, string>();
      for (const m of pluginMatches) {
        const slug = m[1].toLowerCase();
        const ver = m[2];
        discoveredPlugins.set(slug, ver);
      }

      for (const [slug, ver] of Array.from(discoveredPlugins.entries())) {
        const vulnSpec = KNOWN_VULNERABLE_PLUGINS.find((p) => p.slug === slug);
        if (vulnSpec && isOlderOrEqual(ver, vulnSpec.maxVulnerableVersion)) {
          findings.push({
            category: 'CMS_VULNERABILITY',
            findingCode: 'WP-OUTDATED-PLUGIN-DETECTED',
            title: `Known Vulnerable WordPress Plugin Detected: ${vulnSpec.name} v${ver}`,
            description: `The site includes assets from plugin "${vulnSpec.name}" version ${ver}, which is affected by ${vulnSpec.cve}. Advisory: ${vulnSpec.advisory}.`,
            severity: 'MEDIUM',
            confidence: 'MEDIUM', // Strict ceiling: passive version string match
            remediationGuidance: `Immediately update ${vulnSpec.name} through the WordPress administrative dashboard or remove it if unused.`,
          });
        }
      }
    }

    // ==========================================
    // 3. wp-login.php / wp-admin Reachability
    // ==========================================
    try {
      const loginRes = await ctx.safeFetch(`${baseUrl}/wp-login.php`, {
        method: 'GET',
        timeoutMs: Math.min(ctx.timeoutMs || 4000, 3000),
      });

      if (loginRes.status === 200) {
        const loginHtml = await loginRes.text();
        if (
          loginHtml.includes('user_login') &&
          (loginHtml.includes('wp-submit') || loginHtml.includes('loginform'))
        ) {
          // Contextual finding: normal administrative surface, framed informatively rather than alarmist
          findings.push({
            category: 'CMS_VULNERABILITY',
            findingCode: 'WP-LOGIN-EXPOSED',
            title: 'WordPress Administrative Login Interface Reachable (wp-login.php)',
            description: `The WordPress administrative login endpoint is reachable at ${baseUrl}/wp-login.php. While expected for CMS operations, public administrative endpoints should be fortified with Multi-Factor Authentication (MFA), strict rate limiting, and CAPTCHA to thwart automated credential stuffing.`,
            severity: 'INFORMATIONAL',
            confidence: 'CONFIRMED',
            remediationGuidance: 'Enforce Multi-Factor Authentication (MFA), deploy rate-limiting rules at the CDN/WAF layer, and restrict wp-admin access to trusted corporate IP ranges if feasible.',
          });
        }
      }
    } catch {}

    // ==========================================
    // 4. XML-RPC Interface Exposure
    // ==========================================
    try {
      const xmlrpcRes = await ctx.safeFetch(`${baseUrl}/xmlrpc.php`, {
        method: 'POST',
        timeoutMs: Math.min(ctx.timeoutMs || 4000, 3000),
        headers: {
          'Content-Type': 'application/xml',
        },
        body: '<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>',
      });

      const xmlBody = await xmlrpcRes.text();
      const isXmlRpcActive =
        xmlrpcRes.status === 200 &&
        (xmlBody.includes('<methodResponse>') ||
          xmlBody.includes('system.listMethods') ||
          xmlBody.includes('XML-RPC server accepts POST requests only'));

      if (isXmlRpcActive) {
        findings.push({
          category: 'CMS_VULNERABILITY',
          findingCode: 'WP-XMLRPC-EXPOSED',
          title: 'WordPress XML-RPC API Interface Exposed (xmlrpc.php)',
          description: `The XML-RPC interface at ${baseUrl}/xmlrpc.php is enabled and responding to remote requests. XML-RPC is commonly weaponized by botnets for brute-force credential stuffing and distributed denial-of-service (DDoS) pingback amplification attacks.`,
          severity: 'LOW',
          confidence: 'CONFIRMED',
          remediationGuidance: 'Disable XML-RPC in your web server configuration or WordPress functions.php file (add_filter("xmlrpc_enabled", "__return_false")) if the WordPress mobile app or legacy Jetpack features are not required.',
        });
      }
    } catch {}

    evidence.push({
      checkType: 'CMS_AUDIT',
      rawObservation: {
        host,
        isWordPress,
        detectedWpVersion,
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
