import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { NextRequest } from 'next/server';
import { POST as freeAssessment } from '../src/app/api/free-assessment/route';

describe('Real-Time Free Perimeter Assessment Engine', () => {
  it('1. Domain Input Sanitization & Validation', async () => {
    // 1a. Missing domain
    const reqEmpty = new NextRequest('http://localhost:3000/api/free-assessment', {
      method: 'POST',
      body: JSON.stringify({}),
    });
    const resEmpty = await freeAssessment(reqEmpty);
    assert.equal(resEmpty.status, 400);
    const jsonEmpty = await resEmpty.json();
    assert.equal(jsonEmpty.success, false);

    // 1b. Invalid characters / spaces
    const reqInvalid = new NextRequest('http://localhost:3000/api/free-assessment', {
      method: 'POST',
      body: JSON.stringify({ domain: 'invalid domain name with spaces' }),
    });
    const resInvalid = await freeAssessment(reqInvalid);
    assert.equal(resInvalid.status, 400);

    // 1c. Non-existent domain
    const reqNonExistent = new NextRequest('http://localhost:3000/api/free-assessment', {
      method: 'POST',
      body: JSON.stringify({ domain: 'this-domain-surely-does-not-exist-xyz987654321.com' }),
    });
    const resNonExistent = await freeAssessment(reqNonExistent);
    assert.equal(resNonExistent.status, 404);
  });

  it('2. SSRF Guard & IP Range Protection', async () => {
    const dangerousDomains = ['localhost', '127.0.0.1', 'test.internal', 'router.local'];
    for (const d of dangerousDomains) {
      const req = new NextRequest('http://localhost:3000/api/free-assessment', {
        method: 'POST',
        body: JSON.stringify({ domain: d }),
      });
      const res = await freeAssessment(req);
      assert.ok(res.status === 400 || res.status === 403, `Must reject dangerous domain ${d}`);
    }
  });

  it('3. Real-Time Scan for risu.in vs innovaterax.in (Different Results Guaranteed)', async () => {
    // Scan risu.in
    const reqRisu = new NextRequest('http://localhost:3000/api/free-assessment', {
      method: 'POST',
      body: JSON.stringify({ domain: 'https://risu.in/' }), // test URL normalization
    });
    const resRisu = await freeAssessment(reqRisu);
    assert.equal(resRisu.status, 200);
    const risuData = await resRisu.json();
    assert.equal(risuData.success, true);
    assert.equal(risuData.domain, 'risu.in');
    assert.equal(risuData.ip, '216.198.79.1');
    assert.equal(risuData.server, 'Vercel');
    assert.equal(risuData.tls.issuer, "Let's Encrypt");

    // Scan innovaterax.in
    const reqInno = new NextRequest('http://localhost:3000/api/free-assessment', {
      method: 'POST',
      body: JSON.stringify({ domain: 'innovaterax.in' }),
    });
    const resInno = await freeAssessment(reqInno);
    assert.equal(resInno.status, 200);
    const innoData = await resInno.json();
    assert.equal(innoData.success, true);
    assert.equal(innoData.domain, 'innovaterax.in');
    assert.equal(innoData.ip, '76.76.21.21');
    assert.equal(innoData.server, 'Vercel');

    // Verify reports are NOT static or identical
    assert.notEqual(risuData.ip, innoData.ip, 'Different domains must resolve to their actual separate IPs');
    assert.notEqual(risuData.tls.validTo, innoData.tls.validTo, 'Different domains have different TLS cert expiry');
    assert.notEqual(risuData.securityPosture, innoData.securityPosture, 'Different domains have different posture scores');

    // Guarantee absolutely NO hardcoded mock python Werkzeug postgres traces
    for (const f of [...risuData.findings, ...innoData.findings]) {
      assert.ok(!f.evidence.includes('psycopg2.connect'), 'Must never contain mock psycopg2 evidence');
      assert.ok(!f.evidence.includes('10.0.4.12'), 'Must never contain mock 10.0.4.12 IP');
      assert.ok(!f.title.includes('Staging endpoint exposed with debug stack traces'), 'Must never return fake staging server finding');
    }
  });
});
