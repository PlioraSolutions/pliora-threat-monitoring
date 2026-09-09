export {
  computeRiskScore,
  SEVERITY_WEIGHTS,
  CONFIDENCE_WEIGHTS,
  IMPORTANCE_WEIGHTS,
  type FindingRiskInput,
  type AssetRiskInput,
  type RiskScoreResult,
} from './scoring';
export { deriveExposure, type AssetExposureInput, type ExposureBreakdown } from './exposure';
