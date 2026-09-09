import mongoose, { Schema, Document, Model, Types } from 'mongoose';

export interface IApiKey extends Document {
  organizationId: Types.ObjectId;
  name: string;
  keyPrefix: string;
  hashedKey: string;
  role: 'VIEWER' | 'ADMIN';
  lastUsedAt?: Date;
  expiresAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

const ApiKeySchema = new Schema<IApiKey>(
  {
    organizationId: {
      type: Schema.Types.ObjectId,
      ref: 'Organization',
      required: true,
      index: true,
    },
    name: {
      type: String,
      required: true,
      trim: true,
    },
    keyPrefix: {
      type: String,
      required: true,
      index: true,
    },
    hashedKey: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    role: {
      type: String,
      enum: ['VIEWER', 'ADMIN'],
      default: 'VIEWER',
    },
    lastUsedAt: {
      type: Date,
    },
    expiresAt: {
      type: Date,
    },
  },
  { timestamps: true }
);

export const ApiKey: Model<IApiKey> =
  mongoose.models.ApiKey || mongoose.model<IApiKey>('ApiKey', ApiKeySchema);
