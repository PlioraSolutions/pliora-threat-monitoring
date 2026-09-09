import mongoose, { Schema, Document, Model, Types } from 'mongoose';
import { FindingCategory, FindingSeverity, FindingConfidence } from '@/types';

export type TriageAction = 'ACCEPTED_RISK' | 'RESOLVED' | 'FALSE_POSITIVE' | 'REOPENED';

export interface ICalibrationFeedback extends Document {
  organizationId: Types.ObjectId;
  findingId: Types.ObjectId;
  findingCode: string;
  category: FindingCategory;
  severityAtTriage: FindingSeverity;
  confidenceAtTriage: FindingConfidence;
  action: TriageAction;
  actorId: string;
  reason?: string;
  notes?: string;
  createdAt: Date;
}

const CalibrationFeedbackSchema = new Schema<ICalibrationFeedback>(
  {
    organizationId: { type: Schema.Types.ObjectId, ref: 'Organization', required: true, index: true },
    findingId: { type: Schema.Types.ObjectId, ref: 'Finding', required: true, index: true },
    findingCode: { type: String, required: true },
    category: {
      type: String,
      enum: [
        'TRANSPORT_SECURITY',
        'HTTP_SECURITY_HEADERS',
        'EXPOSED_SERVICES',
        'TECH_VERSION',
        'BRAND_THREAT',
      ],
      required: true,
    },
    severityAtTriage: {
      type: String,
      enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'],
      required: true,
    },
    confidenceAtTriage: {
      type: String,
      enum: ['CONFIRMED', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'],
      required: true,
    },
    action: {
      type: String,
      enum: ['ACCEPTED_RISK', 'RESOLVED', 'FALSE_POSITIVE', 'REOPENED'],
      required: true,
      index: true,
    },
    actorId: { type: String, required: true },
    reason: { type: String },
    notes: { type: String },
  },
  { timestamps: { createdAt: true, updatedAt: false } }
);

CalibrationFeedbackSchema.index({ organizationId: 1, createdAt: -1 });

export const CalibrationFeedback: Model<ICalibrationFeedback> =
  mongoose.models.CalibrationFeedback ||
  mongoose.model<ICalibrationFeedback>('CalibrationFeedback', CalibrationFeedbackSchema);
