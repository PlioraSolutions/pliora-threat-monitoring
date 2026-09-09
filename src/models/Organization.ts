import mongoose, { Schema, Document, Model } from 'mongoose';
import { PlanTier } from '@/types';

export interface IOrganization extends Document {
  name: string;
  slug: string;
  ownerId: string;
  plan: PlanTier;
  accountType?: import('@/types').OrganizationAccountType;
  scanQuotas: {
    maxMonitoredDomains: number;
    dailyScanLimit: number;
    concurrentScans: number;
  };
  settings: {
    alertEmail?: string;
    notifyOnNewSubdomain: boolean;
    notifyOnHighCritical: boolean;
  };
  alertSettings?: {
    enabledTypes: import('@/types').AlertType[];
    minRiskScore?: number;
    additionalEmails?: string[];
    sendToAdmins?: boolean;
    webhookUrl?: string;
    webhookSecret?: string;
    webhookChannel?: 'GENERIC' | 'SLACK';
  };
  reportBranding?: import('@/types').ReportBrandingConfig;
  scheduledReports?: import('@/types').ScheduledReportSettings;
  stripeCustomerId?: string;
  stripeSubscriptionId?: string;
  subscriptionStatus?: import('@/types').SubscriptionStatus;
  currentPeriodEnd?: Date;
  cancelAtPeriodEnd?: boolean;
  gracePeriodEnd?: Date;
  createdAt: Date;
  updatedAt: Date;
}

const OrganizationSchema = new Schema<IOrganization>(
  {
    name: { type: String, required: true, trim: true },
    slug: { type: String, required: true, unique: true, lowercase: true, trim: true, index: true },
    ownerId: { type: String, required: true, index: true },
    accountType: {
      type: String,
      enum: ['STANDARD', 'AGENCY'],
      default: 'STANDARD',
    },
    plan: {
      type: String,
      enum: ['FREE', 'STARTER', 'BUSINESS', 'PRO'],
      default: 'FREE',
    },
    scanQuotas: {
      maxMonitoredDomains: { type: Number, default: 1 },
      dailyScanLimit: { type: Number, default: 5 },
      concurrentScans: { type: Number, default: 1 },
    },
    settings: {
      alertEmail: { type: String, trim: true },
      notifyOnNewSubdomain: { type: Boolean, default: true },
      notifyOnHighCritical: { type: Boolean, default: true },
    },
    alertSettings: {
      enabledTypes: [{ type: String }],
      minRiskScore: { type: Number, default: 70 },
      additionalEmails: [{ type: String, trim: true }],
      sendToAdmins: { type: Boolean, default: true },
      webhookUrl: { type: String, trim: true },
      webhookSecret: { type: String, trim: true },
      webhookChannel: { type: String, enum: ['GENERIC', 'SLACK'], default: 'GENERIC' },
    },
    reportBranding: {
      whiteLabelEnabled: { type: Boolean, default: false },
      customLogo: { type: String, trim: true },
      customName: { type: String, trim: true },
    },
    scheduledReports: {
      enabled: { type: Boolean, default: false },
      frequency: { type: String, enum: ['MONTHLY'], default: 'MONTHLY' },
      recipients: [{ type: String, trim: true }],
      lastSentAt: { type: Date },
    },
    stripeCustomerId: { type: String, trim: true, sparse: true, index: true },
    stripeSubscriptionId: { type: String, trim: true, sparse: true, index: true },
    subscriptionStatus: {
      type: String,
      enum: ['ACTIVE', 'TRIALING', 'PAST_DUE', 'CANCELED', 'UNPAID', 'INCOMPLETE'],
      default: 'ACTIVE',
    },
    currentPeriodEnd: { type: Date },
    cancelAtPeriodEnd: { type: Boolean, default: false },
    gracePeriodEnd: { type: Date },
  },
  { timestamps: true }
);

export const Organization: Model<IOrganization> =
  mongoose.models.Organization || mongoose.model<IOrganization>('Organization', OrganizationSchema);
