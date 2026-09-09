import mongoose, { Schema, Document, Model, Types } from 'mongoose';

export interface IRiskScoreSnapshot extends Document {
  organizationId: Types.ObjectId;
  scanId?: Types.ObjectId;
  score: number; // 0 to 100
  securityPosture: number; // 100 - score
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  factors: {
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    informationalCount: number;
    totalActiveFindings: number;
    acceptedRiskCount: number;
    topFindingScore: number;
  };
  trigger: 'SCAN_COMPLETED' | 'FINDING_MUTATED' | 'MANUAL';
  computedAt: Date;
  createdAt: Date;
}

const RiskScoreSnapshotSchema = new Schema<IRiskScoreSnapshot>(
  {
    organizationId: { type: Schema.Types.ObjectId, ref: 'Organization', required: true, index: true },
    scanId: { type: Schema.Types.ObjectId, ref: 'Scan' },
    score: { type: Number, required: true, min: 0, max: 100 },
    securityPosture: { type: Number, required: true, min: 0, max: 100 },
    grade: { type: String, enum: ['A', 'B', 'C', 'D', 'F'], required: true },
    factors: {
      criticalCount: { type: Number, default: 0 },
      highCount: { type: Number, default: 0 },
      mediumCount: { type: Number, default: 0 },
      lowCount: { type: Number, default: 0 },
      informationalCount: { type: Number, default: 0 },
      totalActiveFindings: { type: Number, default: 0 },
      acceptedRiskCount: { type: Number, default: 0 },
      topFindingScore: { type: Number, default: 0 },
    },
    trigger: {
      type: String,
      enum: ['SCAN_COMPLETED', 'FINDING_MUTATED', 'MANUAL'],
      default: 'SCAN_COMPLETED',
    },
    computedAt: { type: Date, default: Date.now, index: true },
  },
  { timestamps: { createdAt: true, updatedAt: false } }
);

RiskScoreSnapshotSchema.index({ organizationId: 1, computedAt: -1 });

export const RiskScoreSnapshot: Model<IRiskScoreSnapshot> =
  mongoose.models.RiskScoreSnapshot ||
  mongoose.model<IRiskScoreSnapshot>('RiskScoreSnapshot', RiskScoreSnapshotSchema);
