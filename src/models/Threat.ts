import mongoose, { Schema, Document, Model, Types } from 'mongoose';
import { ThreatStatus, ThreatConfidence, ThreatSource, ThreatCorroborationFactors } from '@/types';

export interface IThreat extends Document {
  organizationId: Types.ObjectId;
  indicator: string;
  relatedRootDomain: string;
  source: ThreatSource;
  confidence: ThreatConfidence;
  corroborationScore: number;
  corroborationFactors?: ThreatCorroborationFactors;
  evidenceId?: Types.ObjectId;
  status: ThreatStatus;
  firstSeen: Date;
  lastSeen: Date;
  dedupKey: string;
  resolvedIps?: string[];
  registrarAge?: number;
  hostingAsn?: string;
  hostingOrg?: string;
  createdAt: Date;
  updatedAt: Date;
}

const ThreatSchema = new Schema<IThreat>(
  {
    organizationId: { type: Schema.Types.ObjectId, ref: 'Organization', required: true, index: true },
    indicator: { type: String, required: true, index: true },
    relatedRootDomain: { type: String, required: true, index: true },
    source: {
      type: String,
      enum: ['CT_LOG', 'TYPOSQUAT_PERMUTATION', 'KEYWORD_MATCH', 'MANUAL_REPORT'],
      required: true,
      index: true,
    },
    confidence: {
      type: String,
      enum: ['CONFIRMED', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'],
      default: 'INFORMATIONAL',
      index: true,
    },
    corroborationScore: { type: Number, min: 0, max: 100, default: 0, index: true },
    corroborationFactors: { type: Schema.Types.Mixed },
    evidenceId: { type: Schema.Types.ObjectId, ref: 'Evidence' },
    status: {
      type: String,
      enum: ['OPEN', 'MONITORING', 'ACCEPTED_RISK', 'RESOLVED'],
      default: 'OPEN',
      index: true,
    },
    firstSeen: { type: Date, default: Date.now },
    lastSeen: { type: Date, default: Date.now },
    dedupKey: { type: String, required: true, index: true },
    resolvedIps: [{ type: String }],
    registrarAge: { type: Number },
    hostingAsn: { type: String },
    hostingOrg: { type: String },
  },
  { timestamps: true }
);

// Compound unique index ensuring no duplicate threat indicator records per organization
ThreatSchema.index({ organizationId: 1, dedupKey: 1 }, { unique: true });

export const Threat: Model<IThreat> =
  mongoose.models.Threat || mongoose.model<IThreat>('Threat', ThreatSchema);
