import mongoose, { Schema, Document, Model, Types } from 'mongoose';
import { AlertType } from '@/types';

export interface IWebhookEndpoint extends Document {
  organizationId: Types.ObjectId;
  name: string;
  url: string;
  format: 'GENERIC' | 'SLACK' | 'JSON';
  enabledTypes: AlertType[];
  secret: string;
  active: boolean;
  createdAt: Date;
  updatedAt: Date;
}

const WebhookEndpointSchema = new Schema<IWebhookEndpoint>(
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
    url: {
      type: String,
      required: true,
      trim: true,
    },
    format: {
      type: String,
      enum: ['GENERIC', 'SLACK', 'JSON'],
      default: 'GENERIC',
    },
    enabledTypes: [
      {
        type: String,
      },
    ],
    secret: {
      type: String,
      required: true,
    },
    active: {
      type: Boolean,
      default: true,
    },
  },
  { timestamps: true }
);

export const WebhookEndpoint: Model<IWebhookEndpoint> =
  mongoose.models.WebhookEndpoint ||
  mongoose.model<IWebhookEndpoint>('WebhookEndpoint', WebhookEndpointSchema);
