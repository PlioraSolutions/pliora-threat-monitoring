import { deriveExposure } from '../src/lib/risk/exposure';
import { computeRiskScore } from '../src/lib/risk/scoring';
import { aggregateRiskScore, recordRiskScoreSnapshot } from '../src/lib/risk/orgScore';
import { memoryStore } from '../src/lib/store';
import { FindingSeverity, FindingConfidence, AssetImportance } from '../src/types';

let passed = 0;
let failed = 0;

function assert(condition: boolean, msg: string) {
  if (condition) {
    console.log(`  ✅ PASS: ${msg}`);
    passed++;
  } else {
    console.error(`  ❌ FAIL: ${msg}`);
    failed++;
  }
}

async function runRiskScoringTests() {
  console.log('⚖️ Running Risk Scoring Engine & Exposure Tests...\n');

  // ==========================================
  // Test Group 1: Exposure Factor Derivation
  // ==========================================
  console.log('Test Group 1: Exposure Factor Derivation');

  const prodRoot = deriveExposure({
    fqdn: 'acme.com',
    type: 'ROOT_DOMAIN',
    verificationStatus: 'VERIFIED',
    ipAddresses: ['93.184.216.34'],
    tags: ['production'],
  });

  const stagingSubdomain = deriveExposure({
    fqdn: 'staging.api.acme.com',
    type: 'SUBDOMAIN',
    verificationStatus: 'VERIFIED',
    ipAddresses: ['93.184.216.35'],
    tags: ['staging'],
  });

  const unverifiedDevHost = deriveExposure({
    fqdn: 'dev-internal.acme.com',
    type: 'SUBDOMAIN',
    verificationStatus: 'PENDING',
    ipAddresses: [],
    tags: ['dev'],
  });

  assert(prodRoot.exposureFactor > 0.8, `Production root domain has high exposure factor (${prodRoot.exposureFactor})`);
  assert(stagingSubdomain.exposureFactor < prodRoot.exposureFactor, `Staging subdomain has lower exposure (${stagingSubdomain.exposureFactor}) than prod root (${prodRoot.exposureFactor})`);
  assert(unverifiedDevHost.exposureFactor < stagingSubdomain.exposureFactor, `Unverified dev host has lowest exposure (${unverifiedDevHost.exposureFactor})`);
  assert(prodRoot.exposureFactor >= 0.1 && prodRoot.exposureFactor <= 1.0, 'Exposure factor is strictly bounded in [0.10, 1.00]');

  // ==========================================
  // Test Group 2: Pure computeRiskScore Function
  // ==========================================
  console.log('\nTest Group 2: Pure computeRiskScore Engine');

  const criticalFinding = {
    severity: 'CRITICAL' as FindingSeverity,
    confidence: 'CONFIRMED' as FindingConfidence,
    category: 'TRANSPORT_SECURITY',
    findingCode: 'TLS-OBSOLETE-PROTOCOL',
  };

  const highFinding = {
    severity: 'HIGH' as FindingSeverity,
    confidence: 'CONFIRMED' as FindingConfidence,
    category: 'HTTP_SECURITY_HEADERS',
    findingCode: 'SEC-HEADER-CSP-MISSING',
  };

  const mediumFinding = {
    severity: 'MEDIUM' as FindingSeverity,
    confidence: 'CONFIRMED' as FindingConfidence,
    category: 'HTTP_SECURITY_HEADERS',
    findingCode: 'SEC-HEADER-XFO-MISSING',
  };

  const lowFinding = {
    severity: 'LOW' as FindingSeverity,
    confidence: 'CONFIRMED' as FindingConfidence,
    category: 'TECH_VERSION',
    findingCode: 'TECH-SERVER-BANNER',
  };

  const prodAsset = {
    fqdn: 'secure.acme.com',
    type: 'ROOT_DOMAIN' as const,
    importance: 'CRITICAL' as AssetImportance,
    verificationStatus: 'VERIFIED' as const,
    ipAddresses: ['93.184.216.34'],
    tags: ['production'],
  };

  const stagingAsset = {
    fqdn: 'staging.acme.com',
    type: 'SUBDOMAIN' as const,
    importance: 'LOW' as AssetImportance,
    verificationStatus: 'VERIFIED' as const,
    ipAddresses: ['93.184.216.35'],
    tags: ['staging'],
  };

  const score1 = computeRiskScore(criticalFinding, prodAsset);
  const score2 = computeRiskScore(criticalFinding, prodAsset);
  assert(score1.score === score2.score, 'computeRiskScore is pure and deterministic across repeated executions');

  const criticalScore = computeRiskScore(criticalFinding, prodAsset).score;
  const highScore = computeRiskScore(highFinding, prodAsset).score;
  const mediumScore = computeRiskScore(mediumFinding, prodAsset).score;
  const lowScore = computeRiskScore(lowFinding, prodAsset).score;

  assert(criticalScore > highScore, `Severity monotonicity: CRITICAL (${criticalScore}) > HIGH (${highScore})`);
  assert(highScore > mediumScore, `Severity monotonicity: HIGH (${highScore}) > MEDIUM (${mediumScore})`);
  assert(mediumScore > lowScore, `Severity monotonicity: MEDIUM (${mediumScore}) > LOW (${lowScore})`);

  // Exposure & Asset Importance Sensitivity
  const prodCriticalScore = computeRiskScore(criticalFinding, prodAsset).score;
  const stagingCriticalScore = computeRiskScore(criticalFinding, stagingAsset).score;
  assert(
    prodCriticalScore > stagingCriticalScore,
    `Production critical asset produces higher risk (${prodCriticalScore}) than staging asset (${stagingCriticalScore})`
  );

  // Factor breakdown explainability
  const explanationResult = computeRiskScore(criticalFinding, prodAsset);
  assert(typeof explanationResult.explanation === 'string' && explanationResult.explanation.length > 20, 'Returns human-readable explanation');
  assert(explanationResult.factors.severity === 1.0, 'Factor breakdown returns severity weight (1.0)');
  assert(explanationResult.factors.confidence === 1.0, 'Factor breakdown returns confidence weight (1.0)');
  assert(explanationResult.factors.assetImportance === 1.0, 'Factor breakdown returns asset importance weight (1.0)');
  assert(typeof explanationResult.factors.exposure === 'number', 'Factor breakdown returns exposure weight');

  // ==========================================
  // Test Group 3: Organization-Level Aggregate Score
  // ==========================================
  console.log('\nTest Group 3: Organization-Level Aggregate Score');

  // Clean state
  const cleanScore = aggregateRiskScore([]);
  assert(cleanScore.score === 0, 'Clean state produces 0 risk score');
  assert(cleanScore.securityPosture === 100, 'Clean state produces 100 security posture');
  assert(cleanScore.grade === 'A', 'Clean state produces Grade A');

  // Org with 1 CRITICAL and 3 LOW findings
  const orgFindingsInitial = [
    { severity: 'CRITICAL' as FindingSeverity, status: 'OPEN' as const, riskScore: 85 },
    { severity: 'LOW' as FindingSeverity, status: 'OPEN' as const, riskScore: 15 },
    { severity: 'LOW' as FindingSeverity, status: 'OPEN' as const, riskScore: 15 },
    { severity: 'LOW' as FindingSeverity, status: 'OPEN' as const, riskScore: 15 },
  ];

  const initialOrgScore = aggregateRiskScore(orgFindingsInitial);
  assert(initialOrgScore.score >= 85, `Org risk score (${initialOrgScore.score}) is anchored by the top CRITICAL finding`);
  assert(initialOrgScore.grade === 'F' || initialOrgScore.grade === 'D', `Org grade is ${initialOrgScore.grade}`);

  // Resolve the CRITICAL finding
  const orgFindingsAfterResolve = [
    { severity: 'CRITICAL' as FindingSeverity, status: 'RESOLVED' as const, riskScore: 85 },
    { severity: 'LOW' as FindingSeverity, status: 'OPEN' as const, riskScore: 15 },
    { severity: 'LOW' as FindingSeverity, status: 'OPEN' as const, riskScore: 15 },
    { severity: 'LOW' as FindingSeverity, status: 'OPEN' as const, riskScore: 15 },
  ];

  const resolvedOrgScore = aggregateRiskScore(orgFindingsAfterResolve);
  const scoreDrop = initialOrgScore.score - resolvedOrgScore.score;
  assert(
    scoreDrop >= 50,
    `Resolving the sole CRITICAL finding visibly drops org risk score by a massive margin (${initialOrgScore.score} -> ${resolvedOrgScore.score}, drop: ${scoreDrop} pts)`
  );
  assert(resolvedOrgScore.grade === 'A' || resolvedOrgScore.grade === 'B', `Org grade improves to ${resolvedOrgScore.grade} after resolving critical finding`);

  // ACCEPTED_RISK finding has reduced weight (30%)
  const orgFindingsAccepted = [
    { severity: 'CRITICAL' as FindingSeverity, status: 'ACCEPTED_RISK' as const, riskScore: 85 },
    { severity: 'LOW' as FindingSeverity, status: 'OPEN' as const, riskScore: 15 },
  ];

  const acceptedOrgScore = aggregateRiskScore(orgFindingsAccepted);
  assert(
    acceptedOrgScore.score < initialOrgScore.score && acceptedOrgScore.score > resolvedOrgScore.score,
    `ACCEPTED_RISK score (${acceptedOrgScore.score}) is lower than OPEN (${initialOrgScore.score}) but higher than RESOLVED (${resolvedOrgScore.score})`
  );

  // FALSE_POSITIVE does not contribute
  const falsePositiveScore = aggregateRiskScore([
    { severity: 'CRITICAL' as FindingSeverity, status: 'FALSE_POSITIVE' as const, riskScore: 90 },
  ]);
  assert(falsePositiveScore.score === 0, 'FALSE_POSITIVE finding contributes zero risk');

  // ==========================================
  // Test Group 4: Time-Series Snapshots
  // ==========================================
  console.log('\nTest Group 4: Time-Series Drift Tracking & Snapshots');

  const testOrgId = 'org-test-drift-001';
  const snap1 = await recordRiskScoreSnapshot(testOrgId, initialOrgScore, 'SCAN_COMPLETED', 'scan-001');
  const snap2 = await recordRiskScoreSnapshot(testOrgId, resolvedOrgScore, 'FINDING_MUTATED');

  assert(snap1.score === initialOrgScore.score, 'Snapshot 1 records initial risk score');
  assert(snap2.score === resolvedOrgScore.score, 'Snapshot 2 records improved risk score');
  assert(snap1.trigger === 'SCAN_COMPLETED', 'Snapshot 1 records SCAN_COMPLETED trigger');
  assert(snap2.trigger === 'FINDING_MUTATED', 'Snapshot 2 records FINDING_MUTATED trigger');

  const storedSnapshots = memoryStore.riskScoreSnapshots.filter((s) => s.organizationId === testOrgId);
  assert(storedSnapshots.length >= 2, `Time-series storage contains ${storedSnapshots.length} snapshots for org`);

  console.log(`\n========================================`);
  console.log(`Risk Scoring Test Results: ${passed} Passed, ${failed} Failed`);
  console.log(`========================================\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

runRiskScoringTests().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
