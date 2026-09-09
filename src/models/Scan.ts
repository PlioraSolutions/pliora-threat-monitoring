import mongoose, { Schema, Document, Model, Types } from 'mongoose';
import { ScanType, ScanStatus } from '@/types';

export interface IPluginRun {
  pluginId: string;
  status: 'COMPLETED' | 'FAILED' | 'INCONCLUSIVE';
  findingsCount: number;
  error?: string;
  durationMs?: number;
}

export interface IScan extends Document {
  organizationId: Types.ObjectId;
  targetAssetId: Types.ObjectId;
  scanType: ScanType;
  status: ScanStatus;
  progress: number;
  counters: {
    subdomainsFound: number;
    findingsCreated: number;
    checksCompleted: number;
  };
  pluginRuns: IPluginRun[];
  error?: string;
  startedAt?: Date;
  completedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

const ScanSchema = new Schema<IScan>(
  {
    organizationId: { type: Schema.Types.ObjectId, ref: 'Organization', required: true, index: true },
    targetAssetId: { type: Schema.Types.ObjectId, ref: 'Asset', required: true, index: true },
    scanType: {
      type: String,
      enum: ['DOMAIN_VERIFICATION', 'DISCOVERY', 'EXPOSURE', 'FULL_SWEEP'],
      default: 'FULL_SWEEP',
    },
    status: {
      type: String,
      enum: ['QUEUED', 'ACTIVE', 'COMPLETED', 'PARTIAL', 'FAILED'],
      default: 'QUEUED',
      index: true,
    },
    progress: { type: Number, min: 0, max: 100, default: 0 },
    counters: {
      subdomainsFound: { type: Number, default: 0 },
      findingsCreated: { type: Number, default: 0 },
      checksCompleted: { type: Number, default: 0 },
    },
    pluginRuns: [
      {
        pluginId: { type: String, required: true },
        status: { type: String, enum: ['COMPLETED', 'FAILED', 'INCONCLUSIVE'], required: true },
        findingsCount: { type: Number, default: 0 },
        error: { type: String },
        durationMs: { type: Number },
      },
    ],
    error: { type: String },
    startedAt: { type: Date },
    completedAt: { type: Date },
  },
  { timestamps: true }
);

export const Scan: Model<IScan> =
  mongoose.models.Scan || mongoose.model<IScan>('Scan', ScanSchema);
