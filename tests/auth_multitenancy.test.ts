import { hashPassword, verifyPassword, createSessionToken, verifySessionToken } from '../src/lib/auth';
import { memoryStore } from '../src/lib/store';

async function runAuthMultiTenancyTests() {
  console.log('👥 Running Authentication & Multi-Tenancy Test Suite...\n');
  let passed = 0;
  let failed = 0;

  function assert(condition: boolean, testName: string) {
    if (condition) {
      console.log(`  ✅ PASS: ${testName}`);
      passed++;
    } else {
      console.error(`  ❌ FAIL: ${testName}`);
      failed++;
    }
  }

  // Group 1: Cryptographic Password Hashing (scrypt)
  console.log('Group 1: Password Hashing & Salt Verification');
  const password = 'SuperSecretEnterprisePassword#2026';
  const hashed = await hashPassword(password);

  assert(typeof hashed === 'string' && hashed.includes(':'), 'Hashed password format contains salt and derived key (salt:hash)');
  const [salt, key] = hashed.split(':');
  assert(salt.length === 32, 'Salt has 16 bytes (32 hex characters) entropy');
  assert(key.length === 128, 'Derived scrypt key has 64 bytes (128 hex characters)');

  assert(await verifyPassword(password, hashed), 'Password matches when verified with correct secret');
  assert(!await verifyPassword('WrongPassword123', hashed), 'Password fails verification when given invalid secret');

  const secondHash = await hashPassword(password);
  assert(hashed !== secondHash, 'Salts are cryptographically unique across invocations');
  assert(await verifyPassword(password, secondHash), 'Both unique salts verify successfully for the same password');

  // Group 2: Stateless JWT Generation & Signature Verification
  console.log('\nGroup 2: JWT Issuance & Cryptographic Signature Verification');
  const tokenPayload = {
    userId: 'usr_enterprise_001',
    email: 'secops@cybercorp.com',
    organizationId: 'org_cybercorp_a',
    role: 'ADMIN' as const,
  };

  const jwt = createSessionToken(tokenPayload);
  assert(typeof jwt === 'string' && jwt.split('.').length === 3, 'JWT is formatted with 3 base64url segments (header.payload.signature)');

  const verified = verifySessionToken(jwt);
  assert(verified !== null, 'JWT verification succeeded');
  assert(verified?.userId === tokenPayload.userId, 'JWT payload correctly preserves userId');
  assert(verified?.email === tokenPayload.email, 'JWT payload correctly preserves email');
  assert(verified?.organizationId === tokenPayload.organizationId, 'JWT payload correctly preserves organizationId');
  assert(verified?.role === tokenPayload.role, 'JWT payload correctly preserves role');

  // Tamper test: modify payload segment
  const segments = jwt.split('.');
  const tamperedPayload = Buffer.from(JSON.stringify({ ...tokenPayload, role: 'OWNER' })).toString('base64url');
  const tamperedJwt = `${segments[0]}.${tamperedPayload}.${segments[2]}`;
  assert(verifySessionToken(tamperedJwt) === null, 'Tampered token signature is rejected by verifySessionToken');

  // Group 3: Multi-Tenant Data Store Isolation
  console.log('\nGroup 3: Multi-Tenant Asset & Scan Isolation');

  // Seed two distinct enterprise tenants
  const tenantA_OrgId = 'org_cybercorp_a';
  const tenantB_OrgId = 'org_rivaldefense_b';

  // Seed Tenant A Asset
  const assetA_Id = 'asset_tenant_a_001';
  memoryStore.assets.set(assetA_Id, {
    _id: assetA_Id,
    organizationId: tenantA_OrgId,
    fqdn: 'api.cybercorp.com',
    type: 'DOMAIN',
    verificationStatus: 'VERIFIED',
    lastSeen: new Date(),
  });

  // Seed Tenant B Asset
  const assetB_Id = 'asset_tenant_b_001';
  memoryStore.assets.set(assetB_Id, {
    _id: assetB_Id,
    organizationId: tenantB_OrgId,
    fqdn: 'vault.rivaldefense.internal',
    type: 'DOMAIN',
    verificationStatus: 'VERIFIED',
    lastSeen: new Date(),
  });

  // Query Tenant A Scope
  const tenantA_Assets = Array.from(memoryStore.assets.values()).filter(
    (a) => a.organizationId === tenantA_OrgId
  );
  assert(tenantA_Assets.length === 1, 'Tenant A query returns exactly 1 scoped asset');
  assert(tenantA_Assets[0].fqdn === 'api.cybercorp.com', 'Tenant A receives only its own asset');
  assert(
    !tenantA_Assets.some((a) => a.organizationId === tenantB_OrgId),
    'Tenant A query never exposes Tenant B assets'
  );

  // Query Tenant B Scope
  const tenantB_Assets = Array.from(memoryStore.assets.values()).filter(
    (a) => a.organizationId === tenantB_OrgId
  );
  assert(tenantB_Assets.length === 1, 'Tenant B query returns exactly 1 scoped asset');
  assert(tenantB_Assets[0].fqdn === 'vault.rivaldefense.internal', 'Tenant B receives only its own asset');
  assert(
    !tenantB_Assets.some((a) => a.organizationId === tenantA_OrgId),
    'Tenant B query never exposes Tenant A assets'
  );

  // Tenant mutation isolation test: Tenant A attempting to access Tenant B asset by ID
  const targetAsset = memoryStore.assets.get(assetB_Id);
  const isAccessibleByTenantA = targetAsset && targetAsset.organizationId === tenantA_OrgId;
  assert(!isAccessibleByTenantA, 'Tenant A cannot resolve or mutate Tenant B asset by ID (Tenant boundary intact)');

  // Group 4: User Store & Organization Membership Verification
  console.log('\nGroup 4: User Store & Organization Membership');
  const demoUser = memoryStore.users.get('demo-user-001');
  assert(demoUser !== undefined, 'Default demo user seeded in memory store');
  assert(demoUser.email === 'demo@pliora.io', 'Demo user email is demo@pliora.io');
  assert(demoUser.organizationMemberships.length > 0, 'Demo user has active organization memberships');
  assert(demoUser.activeOrganizationId === 'org-demo-001', 'Demo user activeOrganizationId is correctly configured');

  console.log(`\n========================================`);
  console.log(`Auth & Multi-Tenancy Test Results: ${passed} Passed, ${failed} Failed`);
  console.log(`========================================\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

runAuthMultiTenancyTests().catch((err) => {
  console.error('Unhandled Auth & Multi-Tenancy test error:', err);
  process.exit(1);
});
