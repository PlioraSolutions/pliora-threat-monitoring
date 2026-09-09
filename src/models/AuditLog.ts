import mongoose, { Schema, Document, Model, Types } from 'mongoose';

export interface IAuditLog extends Document {
  organizationId: Types.ObjectId;
  actorId: string;
  action: string;
  objectType: string;
  objectId: string;
  result: 'SUCCESS' | 'FAILURE';
  details?: Record<string, any>;
  ipAddress?: string;
  createdAt: Date;
}

const AuditLogSchema = new Schema<IAuditLog>(
  {
    organizationId: { type: Schema.Types.ObjectId, ref: 'Organization', required: true, index: true },
    actorId: { type: String, required: true },
    action: { type: String, required: true, index: true },
    objectType: { type: String, required: true },
    objectId: { type: String, required: true },
    result: { type: String, enum: ['SUCCESS', 'FAILURE'], default: 'SUCCESS' },
    details: { type: Schema.Types.Mixed },
    ipAddress: { type: String },
  },
  { timestamps: { createdAt: true, updatedAt: false } }
);

export const AuditLog: Model<IAuditLog> =
  mongoose.models.AuditLog || mongoose.model<IAuditLog>('AuditLog', AuditLogSchema);
