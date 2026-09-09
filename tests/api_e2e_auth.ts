async function runApiE2eTests() {
  console.log('🌐 Testing Live Auth & Multi-Tenancy REST APIs (http://localhost:3000)...\n');
  const baseUrl = 'http://localhost:3000';

  let passed = 0;
  let failed = 0;
  function assert(condition: boolean, msg: string) {
    if (condition) {
      console.log(`  ✅ PASS: ${msg}`);
      passed++;
    } else {
      console.error(`  ❌ FAIL: ${msg}`);
      failed++;
    }
  }

  // 1. Test Register
  const testEmail = `secops_${Date.now()}@guardian-defense.io`;
  const registerRes = await fetch(`${baseUrl}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: testEmail,
      password: 'EnterprisePassword#2026',
      name: 'Chief Security Officer',
      organizationName: 'Guardian Defense Corp',
    }),
  });

  const registerData = await registerRes.json();
  if (!registerData.success) {
    console.error('Register failed details:', registerData);
  }
  assert(registerRes.status === 201, `Register endpoint returned 201 Created (Status: ${registerRes.status})`);
  assert(registerData.success === true, 'Register response indicated success');
  assert(registerData.data.user.email === testEmail, 'User email matches registered email');
  assert(registerData.data.organization.name === 'Guardian Defense Corp', 'Organization created with provided name');

  // Extract set-cookie header
  const rawCookie = registerRes.headers.get('set-cookie') || '';
  const cookieMatch = rawCookie.match(/pliora_session=([^;]+)/);
  const sessionToken = cookieMatch ? cookieMatch[1] : '';
  assert(!!sessionToken, 'Register endpoint sets pliora_session HTTP-only cookie');

  // 2. Test /api/auth/me with Cookie
  const meRes = await fetch(`${baseUrl}/api/auth/me`, {
    headers: { Cookie: `pliora_session=${sessionToken}` },
  });
  const meData = await meRes.json();
  assert(meRes.status === 200, `/api/auth/me returned 200 OK with valid session cookie`);
  assert(meData.data.user.email === testEmail, `/api/auth/me correctly identifies authenticated user`);
  assert(meData.data.organization.name === 'Guardian Defense Corp', `/api/auth/me resolves active organization`);

  // 3. Test /api/auth/login
  const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: testEmail,
      password: 'EnterprisePassword#2026',
    }),
  });
  const loginData = await loginRes.json();
  assert(loginRes.status === 200, `Login endpoint returned 200 OK`);
  assert(loginData.success === true, 'Login response indicated success');
  assert(loginData.data.user.email === testEmail, 'Login identified correct user');

  // 4. Test Invalid Password
  const badLoginRes = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: testEmail,
      password: 'WrongPassword!',
    }),
  });
  assert(badLoginRes.status === 401, 'Login with incorrect password returns 401 Unauthorized');

  // 5. Test Authenticated Assets endpoint
  const assetsRes = await fetch(`${baseUrl}/api/assets`, {
    headers: { Cookie: `pliora_session=${sessionToken}` },
  });
  const assetsData = await assetsRes.json();
  assert(assetsRes.status === 200, 'GET /api/assets succeeds with session cookie');
  assert(assetsData.success === true && Array.isArray(assetsData.data), 'Assets returned as isolated scoped array');

  // 6. Test /api/auth/logout
  const logoutRes = await fetch(`${baseUrl}/api/auth/logout`, {
    method: 'POST',
    headers: { Cookie: `pliora_session=${sessionToken}` },
  });
  const logoutCookie = logoutRes.headers.get('set-cookie') || '';
  assert(logoutRes.status === 200, 'Logout returned 200 OK');
  assert(logoutCookie.includes('pliora_session=;'), 'Logout clears pliora_session cookie');

  console.log(`\n========================================`);
  console.log(`API E2E Test Results: ${passed} Passed, ${failed} Failed`);
  console.log(`========================================\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

runApiE2eTests().catch((err) => {
  console.error('Unhandled API E2E error:', err);
  process.exit(1);
});
