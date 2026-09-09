import mongoose, { Schema, Document, Model, Types } from 'mongoose';
import { CheckType } from '@/types';

export interface IEvidence extends Document {
  organizationId: Types.ObjectId;
  assetId: Types.ObjectId;
  scanId: Types.ObjectId;
  checkType: CheckType;
  rawObservation: Record<string, any>;
  contentHash: string;
  observedAt: Date;
  createdAt: Date;
}

const EvidenceSchema = new Schema<IEvidence>(
  {
    organizationId: { type: Schema.Types.ObjectId, ref: 'Organization', required: true, index: true },
    assetId: { type: Schema.Types.ObjectId, ref: 'Asset', required: true, index: true },
    scanId: { type: Schema.Types.ObjectId, ref: 'Scan', required: true, index: true },
    checkType: {
      type: String,
      enum: [
        'DNS_RECORD',
        'TLS_HANDSHAKE',
        'HTTP_SECURITY_HEADERS',
        'SERVICE_BANNER',
        'SUBDOMAIN_ENUMERATION',
        'TECH_FINGERPRINT',
        'WHOIS_LOOKUP',
        'ASN_LOOKUP',
        'CT_LOG_MATCH',
        'EMAIL_SECURITY',
        'DNS_HEALTH',
        'SUBDOMAIN_TAKEOVER',
        'SENSITIVE_EXPOSURE',
        'CLOUD_BUCKET_SCAN',
        'WEB_HYGIENE',
        'CMS_AUDIT',
      ],
      required: true,
    },
    rawObservation: { type: Schema.Types.Mixed, required: true },
    contentHash: { type: String, required: true, index: true },
    observedAt: { type: Date, default: Date.now },
  },
  { timestamps: { createdAt: true, updatedAt: false } } // Immutable record: no updates allowed
);

export const Evidence: Model<IEvidence> =
  mongoose.models.Evidence || mongoose.model<IEvidence>('Evidence', EvidenceSchema);
