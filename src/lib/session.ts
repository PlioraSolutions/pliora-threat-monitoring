import { NextRequest } from 'next/server';
import { connectToDatabase, isMongoActive } from './db';
import { Organization } from '@/models/Organization';
import { memoryStore } from './store';
import { getAuthenticatedSession } from './auth';

const DEFAULT_DEMO_ORG_SLUG = 'acme-corp';
const DEFAULT_DEMO_OWNER_ID = 'demo-user-001';

export async function getSessionOrganization(request?: NextRequest): Promise<any> {
  if (request) {
    const session = await getAuthenticatedSession(request);
    if (session?.organization) {
      return session.organization;
    }
  }

  await connectToDatabase();

  if (isMongoActive()) {
    let org = await Organization.findOne({ slug: DEFAULT_DEMO_ORG_SLUG });
    if (!org) {
      org = await Organization.create({
        name: 'Acme Corp (Demo Org)',
        slug: DEFAULT_DEMO_ORG_SLUG,
        ownerId: DEFAULT_DEMO_OWNER_ID,
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
      });
    }
    return org;
  }

  // Fallback to memory store
  return memoryStore.organizations.get(DEFAULT_DEMO_ORG_SLUG);
}
