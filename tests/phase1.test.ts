import { isSafeExternalIp, assertSafeTargetHostname } from '../src/lib/security';
import { generateVerificationToken, VERIFICATION_PREFIX } from '../src/lib/verification';

async function runTests() {
  console.log('🧪 Starting Phase 1 Foundation & Security Test Suite...\n');
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

  // 1. SSRF & Safe IP checks (R&D §9.1)
  console.log('Test Group 1: SSRF Egress Filtering (isSafeExternalIp)');
  assert(!isSafeExternalIp('127.0.0.1'), 'Blocks IPv4 loopback (127.0.0.1)');
  assert(!isSafeExternalIp('127.255.255.254'), 'Blocks entire 127.0.0.0/8 subnet');
  assert(!isSafeExternalIp('10.0.0.1'), 'Blocks RFC1918 Class A (10.0.0.1)');
  assert(!isSafeExternalIp('172.16.5.1'), 'Blocks RFC1918 Class B (172.16.5.1)');
  assert(!isSafeExternalIp('172.31.255.255'), 'Blocks RFC1918 Class B upper boundary');
  assert(!isSafeExternalIp('192.168.1.1'), 'Blocks RFC1918 Class C (192.168.1.1)');
  assert(!isSafeExternalIp('169.254.169.254'), 'Blocks AWS/GCP/Azure Cloud Metadata (169.254.169.254)');
  assert(!isSafeExternalIp('100.64.0.1'), 'Blocks Carrier-Grade NAT (100.64.0.1)');
  assert(!isSafeExternalIp('::1'), 'Blocks IPv6 loopback (::1)');
  assert(isSafeExternalIp('8.8.8.8'), 'Allows safe public IP (8.8.8.8)');
  assert(isSafeExternalIp('1.1.1.1'), 'Allows safe public IP (1.1.1.1)');
  assert(isSafeExternalIp('104.26.10.228'), 'Allows safe Cloudflare IP');

  console.log('\nTest Group 2: Hostname SSRF Assertion (assertSafeTargetHostname)');
  let localhostBlocked = false;
  try {
    await assertSafeTargetHostname('localhost');
  } catch (err: any) {
    localhostBlocked = err.message.includes('SSRF Blocked');
  }
  assert(localhostBlocked, 'Throws SSRF Blocked error on "localhost"');

  let internalDomainBlocked = false;
  try {
    await assertSafeTargetHostname('service.internal');
  } catch (err: any) {
    internalDomainBlocked = err.message.includes('SSRF Blocked');
  }
  assert(internalDomainBlocked, 'Throws SSRF Blocked error on ".internal"');

  // 3. Verification Token Generation
  console.log('\nTest Group 3: Domain Verification Token Mechanics');
  const token = generateVerificationToken();
  assert(token.startsWith(VERIFICATION_PREFIX), `Token starts with "${VERIFICATION_PREFIX}"`);
  assert(token.length >= 40, `Token has high cryptographic entropy (length: ${token.length})`);
  const token2 = generateVerificationToken();
  assert(token !== token2, 'Consecutive tokens are uniquely random');

  console.log(`\n========================================`);
  console.log(`Results: ${passed} Passed, ${failed} Failed`);
  console.log(`========================================`);

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('Unhandled test execution error:', err);
  process.exit(1);
});
