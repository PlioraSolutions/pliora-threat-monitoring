import { safeFetch, safeTlsHandshake, safeTcpConnect } from '@/lib/security';
import { FindingCategory, FindingConfidence, FindingSeverity, CheckType } from '@/types';

export interface PluginContext {
  safeFetch: typeof safeFetch;
  safeTlsHandshake: typeof safeTlsHandshake;
  safeTcpConnect?: typeof safeTcpConnect;
  scanId?: string;
  organizationId?: string;
  timeoutMs?: number;
}

export interface PluginEvidenceSpec {
  checkType: CheckType;
  rawObservation: Record<string, any>;
  contentHash?: string;
}

export interface FindingSpec {
  category: FindingCategory;
  findingCode: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  remediationGuidance?: string;
  hasCorroboratingEvidence?: boolean;
}

export interface PluginResult {
  status: 'COMPLETED' | 'FAILED' | 'INCONCLUSIVE';
  evidence: PluginEvidenceSpec[];
  findings: FindingSpec[];
  isWafDetected?: boolean;
  error?: string;
  durationMs?: number;
}

export interface CheckPlugin {
  id: string;
  name: string;
  category: FindingCategory;
  defaultConfidence: FindingConfidence;
  appliesTo(asset: { fqdn: string; type: string }): boolean;
  run(
    asset: { fqdn: string; type: string; _id?: any; organizationId?: any },
    ctx: PluginContext
  ): Promise<PluginResult>;
}
