import { CheckPlugin, PluginContext, PluginResult, FindingSpec } from './types';

/**
 * Checks if a hostname matches a Subject Alternative Name (including wildcard patterns).
 */
function matchesSanOrCn(hostname: string, pattern: string): boolean {
  const host = hostname.toLowerCase();
  const pat = pattern.toLowerCase();

  if (host === pat) return true;

  // Wildcard match: *.example.com matches sub.example.com
  if (pat.startsWith('*.')) {
    const root = pat.substring(2);
    const hostParts = host.split('.');
    const rootParts = root.split('.');

    if (hostParts.length === rootParts.length + 1) {
      const hostSuffix = hostParts.slice(1).join('.');
      return hostSuffix === root;
    }
  }

  return false;
}

export const tlsCertCheckPlugin: CheckPlugin = {
  id: 'tls-cert-check',
  name: 'TLS / SSL Certificate & Handshake Analyzer',
  category: 'TRANSPORT_SECURITY',
  defaultConfidence: 'CONFIRMED',

  appliesTo(asset: { fqdn: string; type: string }) {
    return Boolean(asset.fqdn && asset.fqdn.includes('.'));
  },

  async run(asset, ctx: PluginContext): Promise<PluginResult> {
    const startTime = Date.now();
    const findings: FindingSpec[] = [];

    try {
      const tlsResult = await ctx.safeTlsHandshake(asset.fqdn, 443, {
        timeoutMs: ctx.timeoutMs,
      });

      const {
        protocol,
        cipher,
        peerCertificate,
        daysRemaining,
        isExpired,
        isSelfSigned,
        subjectAltNames,
        commonName,
        authorized,
        authorizationError,
        pinnedIp,
      } = tlsResult;

      const rawObservation = {
        fqdn: asset.fqdn,
        pinnedIp,
        protocol,
        cipher,
        peerCertificate,
        daysRemaining,
        isExpired,
        isSelfSigned,
        subjectAltNames,
        commonName,
        authorized,
        authorizationError,
        analyzedAt: new Date().toISOString(),
      };

      // 1. Check Obsolete Protocol (TLS 1.0, TLS 1.1, SSLv3)
      if (protocol && (protocol === 'TLSv1' || protocol === 'TLSv1.1' || protocol.startsWith('SSL'))) {
        findings.push({
          category: 'TRANSPORT_SECURITY',
          findingCode: 'TLS-OBSOLETE-PROTOCOL',
          title: `Obsolete Protocol Accepted (${protocol})`,
          description: `The endpoint ${asset.fqdn} accepted connection using deprecated protocol ${protocol}. Deprecated TLS versions are vulnerable to POODLE, BEAST, and lack modern forward secrecy guarantees.`,
          severity: 'HIGH',
          confidence: 'CONFIRMED',
          remediationGuidance: 'Disable TLS 1.0 and TLS 1.1 on your web server or load balancer. Enforce TLS 1.2 and TLS 1.3 only.',
        });
      }

      // 2. Check Weak / Insecure Ciphers
      if (cipher && cipher.name) {
        const cipherUpper = cipher.name.toUpperCase();
        const weakPatterns = ['RC4', '3DES', 'DES', 'EXPORT', 'NULL', 'MD5', 'RC2'];
        const isWeak = weakPatterns.some((w) => cipherUpper.includes(w));

        if (isWeak) {
          findings.push({
            category: 'TRANSPORT_SECURITY',
            findingCode: 'TLS-WEAK-CIPHER',
            title: `Weak Cipher Suite Negotiated (${cipher.name})`,
            description: `The endpoint negotiated a weak or broken cipher suite (${cipher.name}). Weak ciphers allow attackers to intercept or decrypt traffic via cryptographic collision attacks.`,
            severity: 'HIGH',
            confidence: 'CONFIRMED',
            remediationGuidance: 'Configure strong cipher suites prioritizing ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-RSA-AES128-GCM-SHA256, and ChaCha20-Poly1305.',
          });
        }
      }

      // 3. Certificate Expiration Check
      if (isExpired) {
        findings.push({
          category: 'TRANSPORT_SECURITY',
          findingCode: 'TLS-CERT-EXPIRED',
          title: `SSL Certificate Expired (${Math.abs(daysRemaining)} days ago)`,
          description: `The SSL certificate for ${asset.fqdn} expired on ${peerCertificate?.valid_to || 'past date'}. Browsers will block visitors with strict security interstitial warnings.`,
          severity: 'HIGH',
          confidence: 'CONFIRMED',
          remediationGuidance: 'Immediately renew and deploy a valid SSL/TLS certificate for this domain via your CA or ACME provider.',
        });
      } else if (daysRemaining <= 7) {
        findings.push({
          category: 'TRANSPORT_SECURITY',
          findingCode: 'TLS-CERT-EXPIRING-CRITICAL',
          title: `SSL Certificate Expiring in ${daysRemaining} Days`,
          description: `The SSL certificate for ${asset.fqdn} will expire on ${peerCertificate?.valid_to}. Immediate renewal is required to prevent service downtime.`,
          severity: 'MEDIUM',
          confidence: 'CONFIRMED',
          remediationGuidance: 'Renew the certificate before expiration using Let\'s Encrypt, Cloudflare, AWS ACM, or your certificate authority.',
        });
      } else if (daysRemaining <= 30) {
        findings.push({
          category: 'TRANSPORT_SECURITY',
          findingCode: 'TLS-CERT-EXPIRING-SOON',
          title: `SSL Certificate Renewal Recommended (${daysRemaining} days remaining)`,
          description: `The SSL certificate for ${asset.fqdn} is within its 30-day renewal window (valid until ${peerCertificate?.valid_to}).`,
          severity: 'LOW',
          confidence: 'CONFIRMED',
          remediationGuidance: 'Verify automated ACME certificate renewal is functioning as expected.',
        });
      }

      // 4. Self-Signed Certificate Check
      if (isSelfSigned) {
        findings.push({
          category: 'TRANSPORT_SECURITY',
          findingCode: 'TLS-SELF-SIGNED-CERT',
          title: 'Self-Signed SSL Certificate in Production',
          description: `The SSL certificate presented by ${asset.fqdn} is self-signed and not issued by a recognized root Certificate Authority. Public browsers and API clients will reject connections.`,
          severity: 'MEDIUM',
          confidence: 'CONFIRMED',
          remediationGuidance: 'Replace self-signed certificates with a publicly trusted certificate from a CA or automated provider (Let\'s Encrypt / ZeroSSL).',
        });
      }

      // 5. Hostname / SAN Mismatch Check
      if (peerCertificate && !isSelfSigned) {
        const candidates = [commonName, ...subjectAltNames].filter(Boolean);
        const hasMatch = candidates.some((pattern) => matchesSanOrCn(asset.fqdn, pattern));

        if (candidates.length > 0 && !hasMatch) {
          findings.push({
            category: 'TRANSPORT_SECURITY',
            findingCode: 'TLS-HOST-MISMATCH',
            title: `SSL Certificate Name Mismatch for ${asset.fqdn}`,
            description: `The certificate presented does not cover "${asset.fqdn}". Valid names on the certificate are: ${candidates.slice(0, 5).join(', ')}${candidates.length > 5 ? ' (and more)' : ''}.`,
            severity: 'HIGH',
            confidence: 'CONFIRMED',
            remediationGuidance: 'Reissue the certificate to include this hostname in the Subject Alternative Name (SAN) list.',
          });
        }
      }

      return {
        status: 'COMPLETED',
        evidence: [
          {
            checkType: 'TLS_HANDSHAKE',
            rawObservation,
          },
        ],
        findings,
        durationMs: Date.now() - startTime,
      };
    } catch (err: any) {
      // If port 443 is unreachable or refused, record cleanly as evidence
      const isRefused = err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND' || err.code === 'ETIMEDOUT';
      return {
        status: isRefused ? 'COMPLETED' : 'FAILED',
        evidence: [
          {
            checkType: 'TLS_HANDSHAKE',
            rawObservation: {
              fqdn: asset.fqdn,
              error: err.message,
              code: err.code,
              timestamp: new Date().toISOString(),
            },
          },
        ],
        findings: isRefused ? [] : [],
        error: isRefused ? undefined : err.message,
        durationMs: Date.now() - startTime,
      };
    }
  },
};
