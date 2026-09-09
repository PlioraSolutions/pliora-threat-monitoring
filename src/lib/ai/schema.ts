import { z } from 'zod';
import { ConfidenceTier } from './types';

export const REGISTERED_CHECK_TYPES = [
  'DNS_RECORD',
  'TLS_HANDSHAKE',
  'HTTP_SECURITY_HEADERS',
  'SERVICE_BANNER',
  'SUBDOMAIN_ENUMERATION',
  'TECH_FINGERPRINT',
  'WHOIS_LOOKUP',
  'ASN_LOOKUP',
  'CT_LOG_MATCH',
  'EMAIL_SECURITY',
  'DNS_HEALTH',
  'SUBDOMAIN_TAKEOVER',
  'SENSITIVE_EXPOSURE',
  'CLOUD_BUCKET_SCAN',
  'WEB_HYGIENE',
  'CMS_AUDIT',
  'LEAKED_CREDENTIAL',
] as const;

export type RegisteredCheckType = typeof REGISTERED_CHECK_TYPES[number];

export const RawAIResponseSchema = z.object({
  explanation: z.string().min(10, 'Explanation must be at least 10 characters'),
  businessImpact: z.string().min(10, 'Business impact must be at least 10 characters'),
  remediationSteps: z.array(z.string().min(5)).min(1, 'At least one remediation step is required'),
  citedEvidenceFields: z.array(z.string()).min(1, 'Must cite at least one evidence field'),
  requestedEvidence: z.enum(REGISTERED_CHECK_TYPES).optional(),
});

export type RawAIResponse = z.infer<typeof RawAIResponseSchema>;

/**
 * §2.1 Confidence Caveat Is Templated, Not Model-Authored.
 * Deterministic mapping guaranteed across the platform.
 */
export const CONFIDENCE_CAVEATS: Record<ConfidenceTier, string> = {
  CONFIRMED:
    'This finding was verified directly by active protocol handshake or corroborating security evidence.',
  HIGH:
    'This risk is corroborated by strong technical signals; remediation is recommended during normal operations.',
  MEDIUM:
    'This observation is derived from version or technology headers. Direct exploitability has not been verified.',
  LOW:
    'This indicator suggests potential misconfiguration but may not represent an active or exploitable vulnerability.',
  INFORMATIONAL:
    'This is an informational indicator only. No active vulnerability or malicious intent is confirmed.',
};

export function getConfidenceCaveat(tier: ConfidenceTier): string {
  return CONFIDENCE_CAVEATS[tier] || CONFIDENCE_CAVEATS.INFORMATIONAL;
}
