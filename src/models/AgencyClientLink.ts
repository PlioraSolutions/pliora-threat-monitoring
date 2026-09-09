import mongoose, { Schema, Document, Model, Types } from 'mongoose';
import { AgencyLinkStatus, AgencyLinkScope } from '@/types';

export interface IAgencyClientLinkDocument extends Document {
  agencyOrgId: Types.ObjectId | string;
  clientOrgId: Types.ObjectId | string;
  grantedByUserId?: string;
  status: AgencyLinkStatus;
  scopes: AgencyLinkScope[];
  delegateBranding: boolean;
  grantedAt?: Date;
  revokedAt?: Date;
  revokedByUserId?: string;
  createdAt: Date;
  updatedAt: Date;
}

const AgencyClientLinkSchema = new Schema<IAgencyClientLinkDocument>(
  {
    agencyOrgId: {
      type: Schema.Types.ObjectId,
      ref: 'Organization',
      required: true,
      index: true,
    },
    clientOrgId: {
      type: Schema.Types.ObjectId,
      ref: 'Organization',
      required: true,
      index: true,
    },
    grantedByUserId: {
      type: String,
      trim: true,
    },
    status: {
      type: String,
      enum: ['PENDING', 'ACTIVE', 'REVOKED'],
      default: 'PENDING',
      index: true,
      required: true,
    },
    scopes: {
      type: [{ type: String, enum: ['READ_ONLY'] }],
      default: ['READ_ONLY'],
    },
    delegateBranding: {
      type: Boolean,
      default: false,
    },
    grantedAt: {
      type: Date,
    },
    revokedAt: {
      type: Date,
    },
    revokedByUserId: {
      type: String,
      trim: true,
    },
  },
  { timestamps: true }
);

// Compound index for querying agency-client relationship pairs quickly
AgencyClientLinkSchema.index({ agencyOrgId: 1, clientOrgId: 1 });
AgencyClientLinkSchema.index({ clientOrgId: 1, status: 1 });
AgencyClientLinkSchema.index({ agencyOrgId: 1, status: 1 });

export const AgencyClientLink: Model<IAgencyClientLinkDocument> =
  mongoose.models.AgencyClientLink ||
  mongoose.model<IAgencyClientLinkDocument>('AgencyClientLink', AgencyClientLinkSchema);
