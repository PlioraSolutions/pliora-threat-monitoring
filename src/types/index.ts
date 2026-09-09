export type PlanTier = 'FREE' | 'STARTER' | 'BUSINESS' | 'PRO';

export type UserRole = 'OWNER' | 'ADMIN' | 'MEMBER' | 'VIEWER';

export type GlobalRole = 'SUPERADMIN' | 'USER';

export type AssetType = 'ROOT_DOMAIN' | 'SUBDOMAIN' | 'IP_ADDRESS' | 'SERVICE';

export type AssetImportance = 'CRITICAL' | 'HIGH' | 'NORMAL' | 'LOW';

export type VerificationStatus = 'PENDING' | 'VERIFIED' | 'FAILED' | 'INHERITED_VERIFIED';

export type DiscoveryMethod = 'MANUAL' | 'CT_LOG' | 'DNS_PERMUTATION';

export type CheckType = 
  | 'DNS_RECORD' 
  | 'TLS_HANDSHAKE' 
  | 'HTTP_SECURITY_HEADERS' 
  | 'SERVICE_BANNER'
  | 'SUBDOMAIN_ENUMERATION'
  | 'TECH_FINGERPRINT'
  | 'WHOIS_LOOKUP'
  | 'ASN_LOOKUP'
  | 'CT_LOG_MATCH'
  | 'EMAIL_SECURITY'
  | 'DNS_HEALTH'
  | 'SUBDOMAIN_TAKEOVER'
  | 'SENSITIVE_EXPOSURE'
  | 'CLOUD_BUCKET_SCAN'
  | 'WEB_HYGIENE'
  | 'CMS_AUDIT'
  | 'LEAKED_CREDENTIAL';

export type ThreatStatus = 'OPEN' | 'MONITORING' | 'ACCEPTED_RISK' | 'RESOLVED';

export type ThreatConfidence = 'CONFIRMED' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

export type ThreatSource = 'CT_LOG' | 'TYPOSQUAT_PERMUTATION' | 'KEYWORD_MATCH' | 'MANUAL_REPORT';

export interface ThreatCorroborationFactors {
  matchType: 'TYPOSQUAT_PERMUTATION' | 'KEYWORD_MATCH' | 'TLD_VARIANT';
  editDistance?: number;
  isLiveDns: boolean;
  resolvedIps?: string[];
  registrarAgeDays?: number;
  createdDate?: string;
  registrarName?: string;
  hostingAsn?: string;
  hostingOrg?: string;
  isKnownAbuseAsn?: boolean;
  hasTlsCert?: boolean;
  isMxConfigured?: boolean;
  contentSimilarity?: {
    similarityScore: number;
    hasMatchingLoginForm?: boolean;
    hasSharedAssets?: boolean;
  };
  breakdown?: {
    matchPoints: number;
    dnsPoints: number;
    agePoints: number;
    hostingPoints: number;
    weaponizationPoints: number;
    similarityPoints?: number;
  };
}

export type FindingCategory = 
  | 'TRANSPORT_SECURITY' 
  | 'HTTP_SECURITY_HEADERS' 
  | 'EXPOSED_SERVICES' 
  | 'TECH_VERSION' 
  | 'BRAND_THREAT'
  | 'EMAIL_SECURITY'
  | 'DNS_HEALTH'
  | 'SUBDOMAIN_TAKEOVER'
  | 'SENSITIVE_EXPOSURE'
  | 'CLOUD_STORAGE'
  | 'WEB_HYGIENE'
  | 'CMS_VULNERABILITY';

export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

export type FindingConfidence = 'CONFIRMED' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

export type FindingStatus = 'OPEN' | 'ACCEPTED_RISK' | 'FALSE_POSITIVE' | 'RESOLVED';

export type ScanType = 'DOMAIN_VERIFICATION' | 'DISCOVERY' | 'EXPOSURE' | 'FULL_SWEEP';

export type ScanStatus = 'QUEUED' | 'ACTIVE' | 'COMPLETED' | 'PARTIAL' | 'FAILED';

export type AlertType =
  | 'NEW_CRITICAL_FINDING'
  | 'NEW_HIGH_FINDING'
  | 'FINDING_AUTO_REOPENED'
  | 'NEW_ASSET_DISCOVERED'
  | 'SCAN_FAILED'
  | 'THREAT_DETECTED';

export type AlertSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type AlertDeliveryStatus = 'PENDING' | 'SENT' | 'FAILED';

export type AlertDeliveryChannel = 'EMAIL' | 'WEBHOOK';

export interface OrgAlertSettings {
  enabledTypes: AlertType[];
  minRiskScore?: number;
  additionalEmails?: string[];
  sendToAdmins?: boolean;
  webhookUrl?: string;
  webhookSecret?: string;
  webhookChannel?: 'GENERIC' | 'SLACK';
}

export interface ReportBrandingConfig {
  whiteLabelEnabled: boolean;
  customLogo?: string;
  customName?: string;
}

export interface ScheduledReportSettings {
  enabled: boolean;
  frequency: 'MONTHLY';
  recipients?: string[];
  lastSentAt?: Date;
}

export interface EmailAttachment {
  filename: string;
  content: Buffer | string;
  contentType: string;
}

export type SubscriptionStatus =
  | 'ACTIVE'
  | 'TRIALING'
  | 'PAST_DUE'
  | 'CANCELED'
  | 'UNPAID'
  | 'INCOMPLETE';

export interface PlanQuotas {
  maxMonitoredDomains: number;
  dailyScanLimit: number;
  concurrentScans: number;
  apiRateLimitPerMin: number;
  whiteLabelAllowed: boolean;
}

export interface BillingSubscriptionInfo {
  stripeCustomerId?: string;
  stripeSubscriptionId?: string;
  subscriptionStatus?: SubscriptionStatus;
  currentPeriodEnd?: Date;
  cancelAtPeriodEnd?: boolean;
  gracePeriodEnd?: Date;
}

export type OrganizationAccountType = 'STANDARD' | 'AGENCY';

export type AgencyLinkStatus = 'PENDING' | 'ACTIVE' | 'REVOKED';

export type AgencyLinkScope = 'READ_ONLY';

export interface IAgencyClientLink {
  _id?: string;
  id?: string;
  agencyOrgId: string;
  clientOrgId: string;
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



