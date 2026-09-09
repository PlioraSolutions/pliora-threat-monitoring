import { ThreatConfidence, ThreatCorroborationFactors } from '@/types';

export interface CorroborationInput {
  matchType: 'TYPOSQUAT_PERMUTATION' | 'KEYWORD_MATCH' | 'TLD_VARIANT';
  editDistance?: number;
  isLiveDns: boolean;
  resolvedIps?: string[];
  registrarAgeDays?: number;
  createdDate?: string;
  registrarName?: string;
  hostingAsn?: string;
  hostingOrg?: string;
  isKnownAbuseAsn?: boolean;
  hasTlsCert?: boolean;
  isMxConfigured?: boolean;
  contentSimilarity?: {
    similarityScore: number;
    hasMatchingLoginForm?: boolean;
    hasSharedAssets?: boolean;
  };
}

export interface CorroborationResult {
  corroborationScore: number;
  confidence: ThreatConfidence;
  factors: ThreatCorroborationFactors;
  reason: string;
}

/**
 * Pure decision engine that computes a corroboration score and confidence tier
 * for a detected look-alike or typosquatted domain.
 * 
 * Design Principles & Weight Table:
 * 1. Match Fidelity Points: max 30 pts (Keyword: 30, TLD: 25, Permutation dist<=1: 30, dist>1: 20)
 * 2. Live DNS Reachability: max 20 pts (Non-resolving capped strictly at INFORMATIONAL <= 24 pts)
 * 3. Registrar Age Factor: max 25 pts (<=14 days: 25, <=60 days: 15, <=180 days: 5, >365 days: 0)
 * 4. Hosting ASN Reputation: max 15 pts (Known bulletproof/abuse ASN: 15)
 * 5. Phishing Weaponization: max 20 pts (Active MX: 15, Active TLS: 10, capped)
 * 6. Structural Content Similarity (§B.2): max 25 pts (Matching Login Form: +15, DOM layout match >=60%: +10, shared assets: +5)
 * 
 * Confidence Thresholds:
 * - >= 80: CONFIRMED
 * - >= 65: HIGH
 * - >= 45: MEDIUM
 * - >= 25: LOW
 * - <  25 or Non-resolving: INFORMATIONAL
 */
export function computeCorroborationScore(input: CorroborationInput): CorroborationResult {
  let matchPoints = 0;
  let dnsPoints = 0;
  let agePoints = 0;
  let hostingPoints = 0;
  let weaponizationPoints = 0;

  // 1. Match Fidelity Points (max 30)
  if (input.matchType === 'KEYWORD_MATCH') {
    matchPoints = 30; // e.g. "acme-login.com" or "secure-acme.net"
  } else if (input.matchType === 'TLD_VARIANT') {
    matchPoints = 25; // exact brand string under alternate TLD
  } else {
    // TYPOSQUAT_PERMUTATION
    const distance = input.editDistance ?? 1;
    matchPoints = distance <= 1 ? 30 : 20;
  }

  // 2. Live DNS Reachability (max 20)
  // Non-resolving domains cannot actively impersonate or harm users
  if (input.isLiveDns) {
    dnsPoints = 20;
  } else {
    dnsPoints = 0;
  }

  // 3. Registrar Age Factor (max 25)
  // Attackers register look-alike domains shortly before launching campaigns
  if (typeof input.registrarAgeDays === 'number') {
    if (input.registrarAgeDays <= 14) {
      agePoints = 25; // Registered within 2 weeks: critical recency
    } else if (input.registrarAgeDays <= 60) {
      agePoints = 15; // Registered within 2 months: high recency
    } else if (input.registrarAgeDays <= 180) {
      agePoints = 5;  // Registered within 6 months: mild recency
    } else if (input.registrarAgeDays <= 365) {
      agePoints = 0;  // 1 year old
    } else {
      agePoints = 0;  // Older than 1 year: likely pre-existing or unrelated
    }
  } else {
    // Unknown registration age: assign neutral score
    agePoints = 5;
  }

  // 4. Hosting & Infrastructure Factor (max 15)
  if (input.isKnownAbuseAsn) {
    hostingPoints = 15;
  }

  // 5. Phishing Weaponization Factor (max 20)
  if (input.isMxConfigured) {
    weaponizationPoints += 15; // Ready to receive or send phishing emails
  }
  if (input.hasTlsCert) {
    weaponizationPoints += 10; // Active SSL certificate enables HTTPS phishing padlock
  }

  // 6. Structural Content Similarity Factor (max 25) — Phase B §B.2
  let similarityPoints = 0;
  if (input.isLiveDns && input.contentSimilarity) {
    if (input.contentSimilarity.hasMatchingLoginForm) {
      similarityPoints += 15; // Phishing login / credential harvesting form
    }
    if (input.contentSimilarity.similarityScore >= 60) {
      similarityPoints += 10; // High structural tag alignment
    } else if (input.contentSimilarity.similarityScore >= 30) {
      similarityPoints += 5; // Moderate structural tag alignment
    }
    if (input.contentSimilarity.hasSharedAssets && similarityPoints < 25) {
      similarityPoints = Math.min(25, similarityPoints + 5);
    }
  }

  // Aggregate Raw Score
  let totalScore =
    matchPoints + dnsPoints + agePoints + hostingPoints + weaponizationPoints + similarityPoints;
  totalScore = Math.min(100, Math.max(0, totalScore));

  // Hard Guard: Non-resolving domains are strictly capped at INFORMATIONAL (max score 24)
  if (!input.isLiveDns) {
    totalScore = Math.min(24, totalScore);
  }

  // Determine Confidence Tier based on explicit thresholds
  let confidence: ThreatConfidence;
  if (!input.isLiveDns || totalScore < 25) {
    confidence = 'INFORMATIONAL';
  } else if (totalScore < 45) {
    confidence = 'LOW';
  } else if (totalScore < 65) {
    confidence = 'MEDIUM';
  } else if (totalScore < 80) {
    confidence = 'HIGH';
  } else {
    confidence = 'CONFIRMED';
  }

  const factors: ThreatCorroborationFactors = {
    matchType: input.matchType,
    editDistance: input.editDistance,
    isLiveDns: input.isLiveDns,
    resolvedIps: input.resolvedIps,
    registrarAgeDays: input.registrarAgeDays,
    createdDate: input.createdDate,
    registrarName: input.registrarName,
    hostingAsn: input.hostingAsn,
    hostingOrg: input.hostingOrg,
    isKnownAbuseAsn: input.isKnownAbuseAsn,
    hasTlsCert: input.hasTlsCert,
    isMxConfigured: input.isMxConfigured,
    contentSimilarity: input.contentSimilarity,
    breakdown: {
      matchPoints,
      dnsPoints,
      agePoints,
      hostingPoints,
      weaponizationPoints,
      similarityPoints,
    },
  };

  const reason = buildCorroborationReason(confidence, totalScore, input);

  return {
    corroborationScore: totalScore,
    confidence,
    factors,
    reason,
  };
}

function buildCorroborationReason(
  confidence: ThreatConfidence,
  score: number,
  input: CorroborationInput
): string {
  if (!input.isLiveDns) {
    return `Domain does not currently resolve via DNS (Score: ${score}/100, Tier: ${confidence}). Passive look-alike observation only.`;
  }

  const parts: string[] = [];
  if (typeof input.registrarAgeDays === 'number' && input.registrarAgeDays <= 60) {
    parts.push(`recently registered (${input.registrarAgeDays} days ago)`);
  }
  if (input.isMxConfigured) {
    parts.push('active MX mail server configured');
  }
  if (input.isKnownAbuseAsn) {
    parts.push(`hosted on known high-abuse network (${input.hostingAsn})`);
  }
  if (input.hasTlsCert) {
    parts.push('active TLS certificate');
  }
  if (input.contentSimilarity?.hasMatchingLoginForm) {
    parts.push('cloned login/credential harvesting form detected');
  } else if (input.contentSimilarity && input.contentSimilarity.similarityScore >= 60) {
    parts.push(`high structural DOM similarity (${input.contentSimilarity.similarityScore}% match)`);
  }

  const detail = parts.length > 0 ? parts.join(', ') : 'resolving look-alike hostname';
  return `Corroborated threat (Score: ${score}/100, Tier: ${confidence}): ${detail}.`;
}
