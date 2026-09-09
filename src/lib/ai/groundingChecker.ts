import { RawAIResponse } from './schema';
import { GroundingValidationResult } from './types';
import { validateRemediationSteps } from './remediationLibrary';

export interface GroundingContext {
  target: any; // IFinding or IThreat
  evidence?: any; // IEvidence
  asset?: any; // IAsset
}

/**
 * §4 Evidence-Consistency Checker.
 * Validates that every claim in the generated AI response is strictly rooted in input data
 * before it can be presented to any user.
 */
export function validateEvidenceGrounding(
  response: RawAIResponse,
  context: GroundingContext
): GroundingValidationResult {
  const violations: string[] = [];
  const offendingFields: string[] = [];

  const { target, evidence, asset } = context;

  // Flatten available source fields for verification
  const availableTargetKeys = new Set(Object.keys(target || {}));
  const availableEvidenceKeys = new Set(Object.keys(evidence?.details || evidence || {}));
  const availableAssetKeys = new Set(Object.keys(asset || {}));

  // Also include top-level properties from Evidence if present
  if (evidence) {
    availableEvidenceKeys.add('rawOutput');
    availableEvidenceKeys.add('checkType');
    availableEvidenceKeys.add('targetDomain');
    availableEvidenceKeys.add('contentHash');
  }

  // -------------------------------------------------------------
  // 1. Cited Field Verification
  // -------------------------------------------------------------
  if (!response.citedEvidenceFields || response.citedEvidenceFields.length === 0) {
    violations.push('AI response failed to provide any cited evidence fields.');
    offendingFields.push('citedEvidenceFields');
  } else {
    for (const field of response.citedEvidenceFields) {
      const existsInTarget =
        availableTargetKeys.has(field) && target[field] !== undefined && target[field] !== null;
      const existsInEvidence =
        availableEvidenceKeys.has(field) ||
        (evidence?.details && evidence.details[field] !== undefined && evidence.details[field] !== null);
      const existsInAsset =
        availableAssetKeys.has(field) && asset && asset[field] !== undefined && asset[field] !== null;

      if (!existsInTarget && !existsInEvidence && !existsInAsset) {
        violations.push(
          `Cited evidence field '${field}' does not exist or is empty in the source Finding/Threat/Evidence record.`
        );
        offendingFields.push(`citedEvidenceFields:${field}`);
      }
    }
  }

  const combinedText = `${response.explanation} ${response.businessImpact}`;

  // -------------------------------------------------------------
  // 2. Anti-Hallucination: CVE Identifiers
  // -------------------------------------------------------------
  const cveMatches = combinedText.match(/CVE-\d{4}-\d{4,}/gi);
  if (cveMatches) {
    const sourceBlob = JSON.stringify({ target, evidence, asset });
    for (const cve of cveMatches) {
      if (!sourceBlob.toLowerCase().includes(cve.toLowerCase())) {
        violations.push(`Hallucinated CVE identifier '${cve}' not found in source evidence.`);
        offendingFields.push('explanation:cve');
      }
    }
  }

  // -------------------------------------------------------------
  // 3. Anti-Hallucination: Unverified Port Numbers
  // -------------------------------------------------------------
  const portMatches = combinedText.match(/\bport\s+(\d{1,5})\b/gi);
  if (portMatches) {
    const sourceBlob = JSON.stringify({ target, evidence, asset });
    for (const portStr of portMatches) {
      const portNum = portStr.replace(/\D+/g, '');
      if (
        !sourceBlob.includes(portNum) &&
        portNum !== '80' &&
        portNum !== '443' // standard default web ports
      ) {
        violations.push(`Hallucinated port number '${portNum}' not found in source evidence.`);
        offendingFields.push('explanation:port');
      }
    }
  }

  // -------------------------------------------------------------
  // 4. Anti-Hallucination: Unverified IP Addresses
  // -------------------------------------------------------------
  const ipMatches = combinedText.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g);
  if (ipMatches) {
    const sourceBlob = JSON.stringify({ target, evidence, asset });
    for (const ip of ipMatches) {
      if (!sourceBlob.includes(ip) && ip !== '127.0.0.1' && ip !== '0.0.0.0') {
        violations.push(`Hallucinated IP address '${ip}' not found in source record.`);
        offendingFields.push('explanation:ip');
      }
    }
  }

  // -------------------------------------------------------------
  // 5. Confidence Ceiling & Exploitability Guard
  // -------------------------------------------------------------
  const confidence = target.confidence || 'INFORMATIONAL';
  const severity = target.severity || 'INFORMATIONAL';

  if (['MEDIUM', 'LOW', 'INFORMATIONAL'].includes(confidence)) {
    const activeExploitPatterns = [
      /\bactive(ly)?\s+exploit(ed|ing)?\b/i,
      /\bactively\s+under\s+attack\b/i,
      /\bconfirmed\s+breach\b/i,
      /\bransomware\b/i,
      /\bzero-day\b/i,
    ];

    for (const pattern of activeExploitPatterns) {
      if (pattern.test(combinedText)) {
        violations.push(
          `AI claimed active exploitation/breach ('${pattern.source}') for a ${confidence}-confidence item, violating confidence bounding.`
        );
        offendingFields.push('explanation:exploitability');
        break;
      }
    }
  }

  // Contradictory severity claims (e.g. claiming critical when item is low)
  if (['LOW', 'INFORMATIONAL'].includes(severity)) {
    if (/\bcritical(\s+severity)?\s+(vulnerability|risk|threat)\b/i.test(combinedText)) {
      violations.push(`AI claimed 'critical severity' on a ${severity} finding.`);
      offendingFields.push('explanation:severityContradiction');
    }
  }

  // -------------------------------------------------------------
  // 6. Approved Remediation Guidance Library Validation
  // -------------------------------------------------------------
  const targetCode = target.findingCode || target.source || 'GENERAL';
  const remValidation = validateRemediationSteps(targetCode, response.remediationSteps);
  if (!remValidation.valid) {
    for (const rejected of remValidation.rejectedSteps) {
      violations.push(
        `Remediation step '${rejected}' is not approved in the verified remediation library for '${targetCode}'.`
      );
      offendingFields.push('remediationSteps:unapproved');
    }
  }

  return {
    isValid: violations.length === 0,
    violations,
    offendingFields,
  };
}
