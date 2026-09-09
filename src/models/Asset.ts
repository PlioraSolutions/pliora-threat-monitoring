import mongoose, { Schema, Document, Model, Types } from 'mongoose';
import { AssetType, AssetImportance, VerificationStatus, DiscoveryMethod } from '@/types';

export interface IAsset extends Document {
  organizationId: Types.ObjectId;
  rootDomain: string;
  fqdn: string;
  type: AssetType;
  importance: AssetImportance;
  verificationStatus: VerificationStatus;
  verificationToken: string;
  verifiedAt?: Date;
  discoveredVia: DiscoveryMethod[];
  ipAddresses: string[];
  tags: string[];
  firstSeen: Date;
  lastSeen: Date;
  createdAt: Date;
  updatedAt: Date;
}

const AssetSchema = new Schema<IAsset>(
  {
    organizationId: { type: Schema.Types.ObjectId, ref: 'Organization', required: true, index: true },
    rootDomain: { type: String, required: true, lowercase: true, trim: true, index: true },
    fqdn: { type: String, required: true, lowercase: true, trim: true },
    type: {
      type: String,
      enum: ['ROOT_DOMAIN', 'SUBDOMAIN', 'IP_ADDRESS', 'SERVICE'],
      default: 'ROOT_DOMAIN',
    },
    importance: {
      type: String,
      enum: ['CRITICAL', 'HIGH', 'NORMAL', 'LOW'],
      default: 'NORMAL',
    },
    verificationStatus: {
      type: String,
      enum: ['PENDING', 'VERIFIED', 'FAILED', 'INHERITED_VERIFIED'],
      default: 'PENDING',
      index: true,
    },
    verificationToken: { type: String, required: true },
    verifiedAt: { type: Date },
    discoveredVia: [{ type: String, default: ['MANUAL'] }],
    ipAddresses: [{ type: String }],
    tags: [{ type: String }],
    firstSeen: { type: Date, default: Date.now },
    lastSeen: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

// Compound index to guarantee uniqueness of an FQDN per Organization
AssetSchema.index({ organizationId: 1, fqdn: 1 }, { unique: true });

export const Asset: Model<IAsset> =
  mongoose.models.Asset || mongoose.model<IAsset>('Asset', AssetSchema);
