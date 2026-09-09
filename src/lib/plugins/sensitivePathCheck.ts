import { CheckPlugin, PluginContext, PluginResult, FindingSpec, PluginEvidenceSpec } from './types';

export const sensitivePathCheckPlugin: CheckPlugin = {
  id: 'sensitive-path-check',
  name: 'Sensitive File, Credential & Endpoint Exposure Analyzer',
  category: 'SENSITIVE_EXPOSURE',
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

    const probedResults: Record<string, any> = {};

    // Helper: Safely fetch path with 3-second timeout
    const fetchPath = async (path: string, options: any = {}): Promise<{ status: number; text: string; headers: Headers } | null> => {
      try {
        const res = await ctx.safeFetch(`${baseUrl}${path}`, {
          timeoutMs: 3500,
          redirect: 'manual',
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; PlioraSecurityScanner/1.0)',
            ...options.headers,
          },
          ...options,
        });
        const text = await res.text();
        return { status: res.status, text, headers: res.headers };
      } catch {
        return null;
      }
    };

    // 1. Check Exposed .git/HEAD
    const gitRes = await fetchPath('/.git/HEAD');
    if (gitRes && gitRes.status === 200) {
      const trimmed = gitRes.text.trim();
      // Strict content validation: Must match git pointer, not custom 200 SPA HTML page
      if (trimmed.startsWith('ref: refs/') || /^[a-f0-9]{40}$/i.test(trimmed)) {
        findings.push({
          category: 'SENSITIVE_EXPOSURE',
          findingCode: 'EXPOSURE-GIT-FOLDER',
          title: 'Critical Source Code Exposure: Publicly Accessible .git Directory',
          description: `The Git repository metadata folder (${baseUrl}/.git/HEAD) is publicly accessible and returned valid Git reference data: "${trimmed.substring(0, 40)}". Attackers can download your entire source code repository, history, and embedded secrets.`,
          severity: 'CRITICAL',
          confidence: 'CONFIRMED',
          remediationGuidance: 'Configure your web server or reverse proxy (Nginx, Apache, Caddy, Cloudflare) to return HTTP 403/404 on all requests to path "/.git*".',
        });
        probedResults['git_head'] = { exposed: true, signature: trimmed.substring(0, 60) };
      }
    }

    // 2. Check Exposed .env File
    const envRes = await fetchPath('/.env');
    if (envRes && envRes.status === 200) {
      const body = envRes.text;
      const hasKeyPatterns =
        (body.includes('DB_') || body.includes('SECRET') || body.includes('KEY=') || body.includes('PASSWORD=') || body.includes('TOKEN=')) &&
        body.includes('=') &&
        !body.toLowerCase().includes('<!doctype html') &&
        !body.toLowerCase().includes('<html');

      if (hasKeyPatterns) {
        findings.push({
          category: 'SENSITIVE_EXPOSURE',
          findingCode: 'EXPOSURE-ENV-FILE',
          title: 'Critical Credential Leak: Publicly Accessible .env Configuration File',
          description: `An active environment configuration file was detected at ${baseUrl}/.env containing plaintext credentials, database strings, or API secrets.`,
          severity: 'CRITICAL',
          confidence: 'CONFIRMED',
          remediationGuidance: 'Immediately block public web server access to .env files and rotate all exposed database passwords and API tokens.',
        });
        probedResults['env_file'] = { exposed: true };
      }
    }

    // 3. Check Database Backup Dumps
    const backupPaths = ['/backup.sql', '/dump.sql', '/database.sql'];
    for (const bPath of backupPaths) {
      const bRes = await fetchPath(bPath);
      if (bRes && bRes.status === 200) {
        const body = bRes.text;
        if (
          (body.includes('INSERT INTO ') || body.includes('CREATE TABLE ') || body.includes('MySQL dump') || body.includes('PostgreSQL database dump')) &&
          !body.includes('<!DOCTYPE html>')
        ) {
          findings.push({
            category: 'SENSITIVE_EXPOSURE',
            findingCode: 'EXPOSURE-DATABASE-DUMP',
            title: `Exposed Database Backup File (${bPath})`,
            description: `A database SQL dump file is publicly downloadable at ${baseUrl}${bPath}. Full schema, user records, and tables are exposed to the public.`,
            severity: 'CRITICAL',
            confidence: 'CONFIRMED',
            remediationGuidance: `Immediately delete or restrict public access to ${bPath} and audit database access logs for unauthorized downloads.`,
          });
          probedResults['db_dump'] = { path: bPath, exposed: true };
          break;
        }
      }
    }

    // 4. Check Exposed Swagger / OpenAPI Documentation
    const apiDocPaths = ['/swagger.json', '/openapi.json', '/v2/api-docs'];
    for (const docPath of apiDocPaths) {
      const docRes = await fetchPath(docPath);
      if (docRes && docRes.status === 200) {
        try {
          const parsed = JSON.parse(docRes.text);
          if (parsed && (parsed.openapi || parsed.swagger) && parsed.paths) {
            findings.push({
              category: 'SENSITIVE_EXPOSURE',
              findingCode: 'EXPOSURE-API-DOCS',
              title: `Publicly Disclosed OpenAPI / Swagger Specification (${docPath})`,
              description: `The internal API schema is publicly accessible at ${baseUrl}${docPath}. It lists all backend endpoints, data parameters, and authentication methods.`,
              severity: 'LOW',
              confidence: 'CONFIRMED',
              remediationGuidance: 'If this API documentation is intended for internal teams only, place it behind corporate authentication.',
            });
            probedResults['api_docs'] = { path: docPath, exposed: true };
            break;
          }
        } catch {}
      }
    }

    // 5. GraphQL Introspection Query Check
    const gqlRes = await fetchPath('/graphql', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: '{ __schema { types { name } } }' }),
    });

    if (gqlRes && gqlRes.status === 200) {
      try {
        const gqlData = JSON.parse(gqlRes.text);
        if (gqlData?.data?.__schema?.types && Array.isArray(gqlData.data.__schema.types)) {
          findings.push({
            category: 'SENSITIVE_EXPOSURE',
            findingCode: 'EXPOSURE-GRAPHQL-INTROSPECTION',
            title: 'GraphQL Schema Introspection Enabled in Production',
            description: `The GraphQL endpoint at ${baseUrl}/graphql answered an introspection query. Threat actors can enumerate your full database schema, types, queries, and mutations.`,
            severity: 'MEDIUM',
            confidence: 'CONFIRMED',
            remediationGuidance: 'Disable GraphQL introspection in your production environment config (e.g., introspection: false in Apollo Server / Yoga / GraphQL Yoga).',
          });
          probedResults['graphql_introspection'] = { enabled: true };
        }
      } catch {}
    }

    // 6. Security.txt Presence Check (Best practice signal)
    const secTxtRes = await fetchPath('/.well-known/security.txt');
    const hasSecTxt = secTxtRes && secTxtRes.status === 200 && secTxtRes.text.toLowerCase().includes('contact:');

    if (hasSecTxt) {
      findings.push({
        category: 'SENSITIVE_EXPOSURE',
        findingCode: 'TRUST-SECURITY-TXT-PRESENT',
        title: 'RFC 9116 Vulnerability Disclosure Policy Published (security.txt)',
        description: `Verified valid security contact policy published at ${baseUrl}/.well-known/security.txt. Demonstrates proactive vulnerability disclosure hygiene.`,
        severity: 'INFORMATIONAL',
        confidence: 'CONFIRMED',
        remediationGuidance: 'Ensure contact email, encryption keys, and policy expiration dates in security.txt remain up to date.',
      });
    } else {
      findings.push({
        category: 'SENSITIVE_EXPOSURE',
        findingCode: 'SECURITY-TXT-MISSING',
        title: 'Missing security.txt Disclosure Policy (RFC 9116)',
        description: `No security contact policy published at ${baseUrl}/.well-known/security.txt. Security researchers identifying vulnerabilities have no designated channel to report them safely.`,
        severity: 'INFORMATIONAL',
        confidence: 'CONFIRMED',
        remediationGuidance: 'Create a security.txt file at /.well-known/security.txt containing Contact: mailto:security@' + host + ' and Policy: links per RFC 9116.',
      });
    }

    evidence.push({
      checkType: 'SENSITIVE_EXPOSURE',
      rawObservation: {
        host,
        probedResults,
        securityTxtConfigured: hasSecTxt,
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
