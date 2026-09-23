import { User } from '@/models/User';
import { Organization } from '@/models/Organization';

export const DEMO_PASSWORD_HASH =
  '122a187cc2e4d2e2f7e19288980a0bab:90697a9a61704fe535418e3cf7afcf2c1dd961b8380139653245104fa6b6d9b7a7b3739bc48fb60edf417a33456de0ca369f77f88fc437ff96ef3a980b38f06f';

/**
 * Ensures the default demo organization and user exist in MongoDB.
 * Called automatically when demo@pliora.io logs in, guaranteeing demo credentials always work.
 */
export async function ensureDemoAccountInMongo() {
  try {
    let org = await Organization.findOne({ slug: 'acme-corp' });
    if (!org) {
      org = await Organization.create({
        name: 'Acme Corp (Demo Org)',
        slug: 'acme-corp',
        ownerId: 'pending',
        plan: 'PRO',
        accountType: 'STANDARD',
        scanQuotas: {
          maxMonitoredDomains: 50,
          dailyScanLimit: 100,
          concurrentScans: 10,
        },
        settings: {
          alertEmail: 'demo@pliora.io',
          notifyOnNewSubdomain: true,
          notifyOnHighCritical: true,
        },
        subscriptionStatus: 'ACTIVE',
        cancelAtPeriodEnd: false,
      });
    }

    let user = await User.findOne({ email: 'demo@pliora.io' });

    if (!user) {
      user = await User.create({
        email: 'demo@pliora.io',
        passwordHash: DEMO_PASSWORD_HASH,
        name: 'Demo Security Admin',
        globalRole: 'SUPERADMIN',
        organizationMemberships: [
          {
            organizationId: org._id,
            role: 'OWNER',
            joinedAt: new Date(),
          },
        ],
        activeOrganizationId: org._id,
      });
      org.ownerId = user._id.toString();
      await org.save();
    } else {
      let needsSave = false;
      if (!user.activeOrganizationId || user.activeOrganizationId.toString() !== org._id.toString()) {
        user.activeOrganizationId = org._id;
        needsSave = true;
      }
      if (user.passwordHash !== DEMO_PASSWORD_HASH) {
        user.passwordHash = DEMO_PASSWORD_HASH;
        needsSave = true;
      }
      if (needsSave) {
        await user.save();
      }
    }
    return { user, org };
  } catch (err: any) {
    console.warn('[ensureDemoAccountInMongo] Warning:', err.message);
    return null;
  }
}
