import mongoose, { Schema, Document, Model, Types } from 'mongoose';
import { AlertType, AlertSeverity, AlertDeliveryStatus, AlertDeliveryChannel } from '@/types';

export interface IAlert extends Document {
  organizationId: Types.ObjectId;
  type: AlertType;
  severity: AlertSeverity;
  relatedFindingId?: Types.ObjectId;
  relatedAssetId?: Types.ObjectId;
  relatedThreatId?: Types.ObjectId;
  title: string;
  summary: string;
  deliveryStatus: AlertDeliveryStatus;
  deliveryChannel: AlertDeliveryChannel;
  recipients: string[];
  retryCount: number;
  dedupKey: string;
  deliveredAt?: Date;
  error?: string;
  createdAt: Date;
  updatedAt: Date;
}

const AlertSchema = new Schema<IAlert>(
  {
    organizationId: {
      type: Schema.Types.ObjectId,
      ref: 'Organization',
      required: true,
      index: true,
    },
    type: {
      type: String,
      enum: [
        'NEW_CRITICAL_FINDING',
        'NEW_HIGH_FINDING',
        'FINDING_AUTO_REOPENED',
        'NEW_ASSET_DISCOVERED',
        'SCAN_FAILED',
        'THREAT_DETECTED',
      ],
      required: true,
      index: true,
    },
    severity: {
      type: String,
      enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
      required: true,
    },
    relatedFindingId: {
      type: Schema.Types.ObjectId,
      ref: 'Finding',
    },
    relatedAssetId: {
      type: Schema.Types.ObjectId,
      ref: 'Asset',
    },
    relatedThreatId: {
      type: Schema.Types.ObjectId,
      ref: 'Threat',
    },
    title: {
      type: String,
      required: true,
      trim: true,
    },
    summary: {
      type: String,
      required: true,
      trim: true,
    },
    deliveryStatus: {
      type: String,
      enum: ['PENDING', 'SENT', 'FAILED'],
      default: 'PENDING',
      index: true,
    },
    deliveryChannel: {
      type: String,
      enum: ['EMAIL', 'WEBHOOK'],
      default: 'EMAIL',
    },
    recipients: [
      {
        type: String,
        trim: true,
      },
    ],
    retryCount: {
      type: Number,
      default: 0,
    },
    dedupKey: {
      type: String,
      required: true,
      index: true,
    },
    deliveredAt: {
      type: Date,
    },
    error: {
      type: String,
    },
  },
  { timestamps: true }
);

// Compound index to support rapid deduplication checks per organization
AlertSchema.index({ organizationId: 1, dedupKey: 1, createdAt: -1 });

export const Alert: Model<IAlert> =
  mongoose.models.Alert || mongoose.model<IAlert>('Alert', AlertSchema);
