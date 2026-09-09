import { isSafeExternalIp, resolveAndPinTarget, assertSafeTargetHostname, safeFetch } from '../src/lib/security';

async function runSsrfTests() {
  console.log('🛡️  Running Hardened SSRF & Egress Protection Test Suite...\n');
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

  // Group 1: IPv4 Private, Loopback, Carrier NAT & Metadata Blocking
  console.log('Group 1: IPv4 Address Space Egress Restrictions');
  assert(!isSafeExternalIp('127.0.0.1'), 'Blocks 127.0.0.1 (Loopback)');
  assert(!isSafeExternalIp('127.255.255.254'), 'Blocks 127.255.255.254 (Loopback boundary)');
  assert(!isSafeExternalIp('0.0.0.0'), 'Blocks 0.0.0.0 (Current network)');
  assert(!isSafeExternalIp('10.0.0.1'), 'Blocks 10.0.0.1 (RFC1918 Class A)');
  assert(!isSafeExternalIp('10.255.255.254'), 'Blocks 10.255.255.254 (RFC1918 Class A boundary)');
  assert(!isSafeExternalIp('172.16.0.1'), 'Blocks 172.16.0.1 (RFC1918 Class B start)');
  assert(!isSafeExternalIp('172.24.100.50'), 'Blocks 172.24.100.50 (RFC1918 Class B middle)');
  assert(!isSafeExternalIp('172.31.255.254'), 'Blocks 172.31.255.254 (RFC1918 Class B end)');
  assert(!isSafeExternalIp('192.168.0.1'), 'Blocks 192.168.0.1 (RFC1918 Class C)');
  assert(!isSafeExternalIp('192.168.254.254'), 'Blocks 192.168.254.254 (RFC1918 Class C boundary)');
  assert(!isSafeExternalIp('169.254.169.254'), 'Blocks 169.254.169.254 (AWS / GCP / Azure IMDS)');
  assert(!isSafeExternalIp('169.254.1.1'), 'Blocks 169.254.1.1 (Link-Local)');
  assert(!isSafeExternalIp('100.64.0.1'), 'Blocks 100.64.0.1 (Carrier-Grade NAT RFC6598)');
  assert(!isSafeExternalIp('192.0.2.1'), 'Blocks 192.0.2.1 (TEST-NET-1)');
  assert(!isSafeExternalIp('198.51.100.1'), 'Blocks 198.51.100.1 (TEST-NET-2)');
  assert(!isSafeExternalIp('203.0.113.1'), 'Blocks 203.0.113.1 (TEST-NET-3)');
  assert(!isSafeExternalIp('224.0.0.1'), 'Blocks 224.0.0.1 (Multicast)');
  assert(!isSafeExternalIp('240.0.0.1'), 'Blocks 240.0.0.1 (Reserved / Future Use)');

  // Group 2: IPv6 Space Egress Restrictions
  console.log('\nGroup 2: IPv6 Address Space Egress Restrictions');
  assert(!isSafeExternalIp('::1'), 'Blocks IPv6 loopback (::1)');
  assert(!isSafeExternalIp('::'), 'Blocks IPv6 unspecified (::)');
  assert(!isSafeExternalIp('fe80::1'), 'Blocks IPv6 link-local (fe80::1)');
  assert(!isSafeExternalIp('fc00::1'), 'Blocks IPv6 unique local / ULA (fc00::1)');
  assert(!isSafeExternalIp('fd12:3456:789a::1'), 'Blocks IPv6 unique local / ULA (fd12::1)');
  assert(!isSafeExternalIp('ff02::1'), 'Blocks IPv6 multicast (ff02::1)');
  assert(!isSafeExternalIp('2001:db8::1'), 'Blocks IPv6 documentation (2001:db8::1)');
  assert(!isSafeExternalIp('100::1'), 'Blocks IPv6 discard (100::1)');
  assert(!isSafeExternalIp('::ffff:127.0.0.1'), 'Blocks IPv4-mapped IPv6 loopback (::ffff:127.0.0.1)');
  assert(!isSafeExternalIp('::ffff:169.254.169.254'), 'Blocks IPv4-mapped IPv6 cloud metadata');
  assert(!isSafeExternalIp('::ffff:10.0.0.1'), 'Blocks IPv4-mapped IPv6 private RFC1918');

  // Group 3: Valid Public IPs
  console.log('\nGroup 3: Legitimate Public IP Whitelisting');
  assert(isSafeExternalIp('8.8.8.8'), 'Permits Google Public DNS (8.8.8.8)');
  assert(isSafeExternalIp('1.1.1.1'), 'Permits Cloudflare DNS (1.1.1.1)');
  assert(isSafeExternalIp('93.184.216.34'), 'Permits Example.com Anycast IP (93.184.216.34)');
  assert(isSafeExternalIp('2606:4700:4700::1111'), 'Permits Cloudflare IPv6 DNS (2606:4700:4700::1111)');

  // Group 4: Hostname Pinning & TOCTOU Resolution
  console.log('\nGroup 4: Hostname Target Resolution & DNS Pinning');
  let localhostCaught = false;
  try {
    await resolveAndPinTarget('localhost');
  } catch (err: any) {
    localhostCaught = err.message.includes('SSRF Blocked');
  }
  assert(localhostCaught, 'resolveAndPinTarget strictly blocks "localhost"');

  let internalNamespaceCaught = false;
  try {
    await resolveAndPinTarget('kubernetes.default.svc.cluster.local');
  } catch (err: any) {
    internalNamespaceCaught = err.message.includes('SSRF Blocked');
  }
  assert(internalNamespaceCaught, 'resolveAndPinTarget blocks internal cluster suffixes (.local)');

  let rawIpMetadataCaught = false;
  try {
    await resolveAndPinTarget('169.254.169.254');
  } catch (err: any) {
    rawIpMetadataCaught = err.message.includes('SSRF Blocked');
  }
  assert(rawIpMetadataCaught, 'resolveAndPinTarget blocks direct IP targeting of 169.254.169.254');

  // Test resolution of legitimate host
  try {
    const pinned = await resolveAndPinTarget('dns.google');
    assert(
      pinned.hostname === 'dns.google' && pinned.allIps.length > 0 && isSafeExternalIp(pinned.pinnedIp),
      `Successfully pinned public host "dns.google" to IP ${pinned.pinnedIp}`
    );
  } catch (err: any) {
    console.warn('  ⚠️  DNS network resolution skipped or offline:', err.message);
  }

  // Group 5: SafeFetch Protocol & Target Validation
  console.log('\nGroup 5: SafeFetch Protocol & Target Verification');
  let fileProtocolCaught = false;
  try {
    await safeFetch('file:///etc/passwd');
  } catch (err: any) {
    fileProtocolCaught = err.message.includes('Unsupported protocol');
  }
  assert(fileProtocolCaught, 'safeFetch rejects non-HTTP protocols (file://)');

  let localFetchCaught = false;
  try {
    await safeFetch('http://127.0.0.1:8080/admin');
  } catch (err: any) {
    localFetchCaught = err.message.includes('SSRF Blocked');
  }
  assert(localFetchCaught, 'safeFetch blocks requests targeting 127.0.0.1:8080');

  let metadataFetchCaught = false;
  try {
    await safeFetch('http://169.254.169.254/latest/meta-data/');
  } catch (err: any) {
    metadataFetchCaught = err.message.includes('SSRF Blocked');
  }
  assert(metadataFetchCaught, 'safeFetch blocks requests targeting cloud metadata service');

  console.log(`\n========================================`);
  console.log(`SSRF Test Results: ${passed} Passed, ${failed} Failed`);
  console.log(`========================================\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

runSsrfTests().catch((err) => {
  console.error('Unhandled SSRF test error:', err);
  process.exit(1);
});
