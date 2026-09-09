import { IOrganization } from '@/models/Organization';
import { IAsset } from '@/models/Asset';
import { IScan } from '@/models/Scan';
import { IEvidence } from '@/models/Evidence';
import { IAuditLog } from '@/models/AuditLog';

// In-memory data store for standalone execution when MongoDB is not running locally
class MemoryStore {
  organizations: Map<string, any> = new Map();
  users: Map<string, any> = new Map();
  assets: Map<string, any> = new Map();
  scans: Map<string, any> = new Map();
  evidence: Map<string, any> = new Map();
  findings: Map<string, any> = new Map();
  riskScoreSnapshots: any[] = [];
  calibrationFeedback: any[] = [];
  calibrationAdjustments: any[] = [];
  aiFeedback: any[] = [];
  auditLogs: any[] = [];
  alerts: Map<string, any> = new Map();
  threats: Map<string, any> = new Map();
  apiKeys: Map<string, any> = new Map();
  webhooks: Map<string, any> = new Map();
  sentEmails: any[] = [];
  aiExplanations: Map<string, any> = new Map();
  agencyClientLinks: Map<string, any> = new Map();

  constructor() {
    this.seedDefaultOrg();
    this.seedDefaultUser();
  }

  seedDefaultUser() {
    const demoUser = {
      _id: 'demo-user-001',
      email: 'demo@pliora.io',
      // scrypt hash for "demo12345!" — generated via crypto.scrypt(pass, salt, 64)
      passwordHash: '122a187cc2e4d2e2f7e19288980a0bab:90697a9a61704fe535418e3cf7afcf2c1dd961b8380139653245104fa6b6d9b7a7b3739bc48fb60edf417a33456de0ca369f77f88fc437ff96ef3a980b38f06f',
      name: 'Demo Security Admin',
      globalRole: 'SUPERADMIN',
      organizationMemberships: [
        {
          organizationId: 'org-demo-001',
          role: 'OWNER',
          joinedAt: new Date(),
        },
      ],
      activeOrganizationId: 'org-demo-001',
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.users.set(demoUser._id, demoUser);
    this.users.set(demoUser.email, demoUser);
  }

  seedDefaultOrg() {
    const defaultOrg = {
      _id: 'org-demo-001',
      name: 'Acme Corp (Demo Org)',
      slug: 'acme-corp',
      ownerId: 'demo-user-001',
      plan: 'FREE',
      scanQuotas: {
        maxMonitoredDomains: 3,
        dailyScanLimit: 10,
        concurrentScans: 2,
      },
      settings: {
        alertEmail: 'security@acmecorp-demo.test',
        notifyOnNewSubdomain: true,
        notifyOnHighCritical: true,
      },
      subscriptionStatus: 'ACTIVE',
      cancelAtPeriodEnd: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.organizations.set(defaultOrg.slug, defaultOrg);
    this.organizations.set(defaultOrg._id, defaultOrg);
  }
}

declare global {
  // eslint-disable-next-line no-var
  var __memoryStore: MemoryStore | undefined;
}

function getStore(): MemoryStore {
  if (
    !global.__memoryStore ||
    !global.__memoryStore.users ||
    !global.__memoryStore.findings ||
    !global.__memoryStore.riskScoreSnapshots
  ) {
    global.__memoryStore = new MemoryStore();
  }
  if (!global.__memoryStore.alerts) {
    global.__memoryStore.alerts = new Map();
  }
  if (!global.__memoryStore.threats) {
    global.__memoryStore.threats = new Map();
  }
  if (!global.__memoryStore.apiKeys) {
    global.__memoryStore.apiKeys = new Map();
  }
  if (!global.__memoryStore.sentEmails) {
    global.__memoryStore.sentEmails = [];
  }
  if (!global.__memoryStore.aiExplanations) {
    global.__memoryStore.aiExplanations = new Map();
  }
  if (!global.__memoryStore.calibrationAdjustments) {
    global.__memoryStore.calibrationAdjustments = [];
  }
  if (!global.__memoryStore.aiFeedback) {
    global.__memoryStore.aiFeedback = [];
  }
  if (!global.__memoryStore.agencyClientLinks) {
    global.__memoryStore.agencyClientLinks = new Map();
  }
  return global.__memoryStore;
}

export const memoryStore = getStore();
