import { FindingSeverity, FindingConfidence } from '@/types';

export interface CveDefinition {
  cveId: string;
  technology: string;
  title: string;
  description: string;
  cvssScore: number;
  epssScore: number; // Exploit Prediction Scoring System (0.0 to 1.0)
  severity: FindingSeverity;
  affectedVersionRegex: RegExp;
  remediation: string;
  advisoryUrl: string;
}

/**
 * Curated high-fidelity CVE database with real-world EPSS exploitation likelihood data.
 * Adheres to §A.2: Factors in EPSS scores so rarely-exploited CVEs do not disproportionately dominate risk.
 */
export const KNOWN_CVE_DATABASE: CveDefinition[] = [
  {
    cveId: 'CVE-2021-41773',
    technology: 'Apache',
    title: 'Apache HTTP Server Path Traversal & Remote Code Execution',
    description: 'Path traversal and file disclosure vulnerability in Apache HTTP Server 2.4.49. Threat actors can map URLs to files outside the document root and achieve remote code execution if CGI scripts are enabled.',
    cvssScore: 9.8,
    epssScore: 0.97, // Actively weaponized in the wild
    severity: 'CRITICAL',
    affectedVersionRegex: /^2\.4\.49(\b|$)/,
    remediation: 'Upgrade Apache HTTP Server immediately to version 2.4.51 or later. Ensure directory access restrictions are strictly configured.',
    advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2021-41773',
  },
  {
    cveId: 'CVE-2021-42013',
    technology: 'Apache',
    title: 'Apache HTTP Server Incomplete Path Traversal Fix',
    description: 'An incomplete fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 allowed attackers to still execute path traversal and remote code execution attacks.',
    cvssScore: 9.8,
    epssScore: 0.96,
    severity: 'CRITICAL',
    affectedVersionRegex: /^2\.4\.50(\b|$)/,
    remediation: 'Upgrade Apache HTTP Server immediately to version 2.4.51 or later.',
    advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2021-42013',
  },
  {
    cveId: 'CVE-2021-23017',
    technology: 'Nginx',
    title: 'Nginx Resolver 1-Byte Memory Overwrite Off-by-One Vulnerability',
    description: 'A 1-byte memory overwrite vulnerability exists in the Nginx DNS resolver module when processing DNS responses, potentially permitting remote code execution.',
    cvssScore: 7.7,
    epssScore: 0.85,
    severity: 'HIGH',
    affectedVersionRegex: /^(0\.[6-9]\.|1\.[0-9]\.|1\.[1][0-9]\.|1\.20\.0(\b|$))/,
    remediation: 'Upgrade Nginx to version 1.20.1, 1.21.0, or newer, or disable the internal resolver directive if unused.',
    advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2021-23017',
  },
  {
    cveId: 'CVE-2014-0160',
    technology: 'OpenSSL',
    title: 'OpenSSL Heartbeat Information Disclosure (Heartbleed)',
    description: 'Missing bound check in the TLS heartbeat extension allows remote attackers to read up to 64KB of server memory containing private keys, passwords, and sensitive session tokens.',
    cvssScore: 7.5,
    epssScore: 0.94,
    severity: 'HIGH',
    affectedVersionRegex: /^1\.0\.1([a-f])?(\b|$)/,
    remediation: 'Upgrade OpenSSL to 1.0.1g or later, or recompile with -DOPENSSL_NO_HEARTBEATS.',
    advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2014-0160',
  },
  {
    cveId: 'CVE-2022-3602',
    technology: 'OpenSSL',
    title: 'OpenSSL X.509 Email Address Buffer Overrun',
    description: 'An arbitrary 4-byte stack buffer overflow can be triggered during X.509 certificate email address constraint validation.',
    cvssScore: 7.5,
    epssScore: 0.42, // Lower EPSS: difficult to reliably exploit in modern environments
    severity: 'HIGH',
    affectedVersionRegex: /^3\.0\.[0-6](\b|$)/,
    remediation: 'Upgrade OpenSSL to version 3.0.7 or later.',
    advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2022-3602',
  },
  {
    cveId: 'CVE-2024-4577',
    technology: 'PHP',
    title: 'PHP CGI Windows Command Injection Vulnerability',
    description: 'Argument injection vulnerability in PHP-CGI on Windows systems when using certain locale configurations (e.g., Traditional Chinese, Simplified Chinese, or Japanese).',
    cvssScore: 9.8,
    epssScore: 0.93,
    severity: 'CRITICAL',
    affectedVersionRegex: /^(8\.1\.[0-2][0-9]|8\.2\.[0-1][0-9]|8\.3\.[0-7])(\b|$)/,
    remediation: 'Upgrade PHP to version 8.1.29, 8.2.20, or 8.3.8 or later. Migrate away from legacy PHP-CGI wrapper to FastCGI/PHP-FPM.',
    advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2024-4577',
  },
];

export interface CveCorrelationResult {
  cveId: string;
  technology: string;
  title: string;
  description: string;
  cvssScore: number;
  epssScore: number;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  remediation: string;
  advisoryUrl: string;
  isBehaviorallyCorroborated: boolean;
}

/**
 * Correlates a technology name and optional version string against known CVEs.
 * 
 * NON-NEGOTIABLE CEILING (§A.2):
 * A CVE match derived strictly from a version string MUST NOT exceed MEDIUM confidence.
 * Escalation to HIGH or CONFIRMED is only permitted when isBehaviorallyCorroborated is true.
 */
export function correlateTechnologyCves(
  technology: string,
  version?: string,
  hasBehavioralProof: boolean = false
): CveCorrelationResult[] {
  if (!version) {
    return []; // No CVE correlation without explicit version indicator
  }

  const normalizedTech = technology.trim().toLowerCase();
  const normalizedVersion = version.trim();

  const matches = KNOWN_CVE_DATABASE.filter((def) => {
    const techMatches = def.technology.toLowerCase() === normalizedTech ||
      normalizedTech.includes(def.technology.toLowerCase());
    if (!techMatches) return false;

    return def.affectedVersionRegex.test(normalizedVersion);
  });

  return matches.map((def) => {
    // STRICT HARD GUARD: Version match alone is capped at MEDIUM confidence
    const confidence: FindingConfidence = hasBehavioralProof ? 'HIGH' : 'MEDIUM';

    return {
      cveId: def.cveId,
      technology: def.technology,
      title: `${def.cveId}: ${def.title}`,
      description: `${def.description} (EPSS Exploitation Probability: ${(def.epssScore * 100).toFixed(1)}%, CVSS: ${def.cvssScore})`,
      cvssScore: def.cvssScore,
      epssScore: def.epssScore,
      severity: def.severity,
      confidence,
      remediation: def.remediation,
      advisoryUrl: def.advisoryUrl,
      isBehaviorallyCorroborated: hasBehavioralProof,
    };
  });
}
