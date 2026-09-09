import mongoose, { Schema, Document, Model, Types } from 'mongoose';
import { FindingCategory, FindingSeverity, FindingConfidence, FindingStatus } from '@/types';

export interface IFinding extends Document {
  organizationId: Types.ObjectId;
  assetId: Types.ObjectId;
  evidenceId: Types.ObjectId;
  category: FindingCategory;
  findingCode: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  riskScore: number;
  status: FindingStatus;
  dedupHash: string;
  remediationGuidance?: string;
  firstSeen: Date;
  lastSeen: Date;
  createdAt: Date;
  updatedAt: Date;
}

const FindingSchema = new Schema<IFinding>(
  {
    organizationId: { type: Schema.Types.ObjectId, ref: 'Organization', required: true, index: true },
    assetId: { type: Schema.Types.ObjectId, ref: 'Asset', required: true, index: true },
    evidenceId: { type: Schema.Types.ObjectId, ref: 'Evidence', required: true },
    category: {
      type: String,
      enum: [
        'TRANSPORT_SECURITY',
        'HTTP_SECURITY_HEADERS',
        'EXPOSED_SERVICES',
        'TECH_VERSION',
        'BRAND_THREAT',
        'EMAIL_SECURITY',
        'DNS_HEALTH',
        'SUBDOMAIN_TAKEOVER',
        'SENSITIVE_EXPOSURE',
        'CLOUD_STORAGE',
        'WEB_HYGIENE',
        'CMS_VULNERABILITY',
      ],
      required: true,
      index: true,
    },
    findingCode: { type: String, required: true },
    title: { type: String, required: true },
    description: { type: String, required: true },
    severity: {
      type: String,
      enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'],
      required: true,
      index: true,
    },
    confidence: {
      type: String,
      enum: ['CONFIRMED', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'],
      required: true,
    },
    riskScore: { type: Number, min: 0, max: 100, default: 0, index: true },
    status: {
      type: String,
      enum: ['OPEN', 'ACCEPTED_RISK', 'FALSE_POSITIVE', 'RESOLVED'],
      default: 'OPEN',
      index: true,
    },
    dedupHash: { type: String, required: true, index: true },
    remediationGuidance: { type: String },
    firstSeen: { type: Date, default: Date.now },
    lastSeen: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

// Unique index on dedupHash per organization ensures duplicate scans do not create duplicate findings
FindingSchema.index({ organizationId: 1, dedupHash: 1 }, { unique: true });

export const Finding: Model<IFinding> =
  mongoose.models.Finding || mongoose.model<IFinding>('Finding', FindingSchema);
