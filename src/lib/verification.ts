import crypto from 'crypto';
import dns from 'dns/promises';
import { assertSafeTargetHostname, safeFetch } from './security';

export const VERIFICATION_PREFIX = 'pliora-site-verification=';

/**
 * Generates a cryptographically secure verification token for domain ownership challenge.
 */
export function generateVerificationToken(): string {
  const randomBytes = crypto.randomBytes(16).toString('hex');
  return `${VERIFICATION_PREFIX}${randomBytes}`;
}

export interface VerificationResult {
  verified: boolean;
  method: 'DNS_TXT' | 'HTTP_WELL_KNOWN' | 'NONE';
  message: string;
  foundRecords?: string[];
}

/**
 * Verifies domain ownership via DNS TXT records.
 * Checks both `_pliora-challenge.<domain>` and `<domain>`.
 */
export async function verifyDomainOwnership(
  rootDomain: string,
  expectedToken: string
): Promise<VerificationResult> {
  const normalizedDomain = rootDomain.trim().toLowerCase();
  const challengeSubdomain = `_pliora-challenge.${normalizedDomain}`;

  // Acceptable valid token variations (handles raw token, pliora-site-verification= prefix, and pliora-verify= prefix)
  const cleanExpected = expectedToken.trim();
  const rawToken = cleanExpected.replace(/^(pliora-site-verification=|pliora-verify=)/, '');
  const acceptedTokens = new Set([
    cleanExpected,
    rawToken,
    `pliora-site-verification=${rawToken}`,
    `pliora-verify=${rawToken}`,
    `pliora-verify=${cleanExpected}`,
  ]);

  const candidatesToCheck = [challengeSubdomain, normalizedDomain];
  const allFoundRecords: string[] = [];

  for (const host of candidatesToCheck) {
    try {
      const records = await dns.resolveTxt(host);
      const flatRecords = records.map((chunks) => chunks.join(''));
      allFoundRecords.push(...flatRecords);

      const hasMatch = flatRecords.some((val) => {
        const trimmed = val.trim();
        return acceptedTokens.has(trimmed);
      });

      if (hasMatch) {
        return {
          verified: true,
          method: 'DNS_TXT',
          message: `Successfully verified domain ownership via DNS TXT record on ${host}.`,
          foundRecords: allFoundRecords,
        };
      }
    } catch (err: any) {
      // dns.NODATA or dns.NOTFOUND are expected if record is not yet published
    }
  }

  // Optional Fallback: HTTP Well-Known check (checking both HTTPS/HTTP on standard challenge paths)
  const httpPaths = [
    `https://${normalizedDomain}/.well-known/pliora-challenge`,
    `http://${normalizedDomain}/.well-known/pliora-challenge`,
    `https://${normalizedDomain}/.well-known/pliora-verification.txt`,
    `http://${normalizedDomain}/.well-known/pliora-verification.txt`,
  ];

  for (const challengeUrl of httpPaths) {
    try {
      const res = await safeFetch(challengeUrl, {
        timeoutMs: 4000,
        maxRedirects: 3,
        headers: { 'User-Agent': 'PlioraThreatMonitor-Verification/1.0' },
      });

      if (res.ok) {
        const text = (await res.text()).trim();
        if (acceptedTokens.has(text)) {
          return {
            verified: true,
            method: 'HTTP_WELL_KNOWN',
            message: `Successfully verified domain ownership via ${challengeUrl}.`,
            foundRecords: allFoundRecords,
          };
        }
      }
    } catch {
      // Ignore individual fetch failures
    }
  }

  return {
    verified: false,
    method: 'NONE',
    message: `Verification challenge token not found in DNS TXT records for ${challengeSubdomain} or ${normalizedDomain}.`,
    foundRecords: allFoundRecords,
  };
}
