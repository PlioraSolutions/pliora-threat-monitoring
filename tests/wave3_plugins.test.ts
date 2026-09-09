import test from 'node:test';
import assert from 'node:assert/strict';
import { pluginRegistry } from '../src/lib/plugins/registry';
import { databaseMisconfigCheckPlugin } from '../src/lib/plugins/databaseMisconfigCheck';
import { smtpRelayCheckPlugin } from '../src/lib/plugins/smtpRelayCheck';
import { REMEDIATION_LIBRARY, validateRemediationSteps } from '../src/lib/ai/remediationLibrary';
import { PluginContext } from '../src/lib/plugins/types';
import { SafeTcpSession } from '../src/lib/security';

test('Wave 3: Database & Service Misconfiguration Detection Plugin Suite', async (t) => {

  // 1. Registry Test
  await t.test('Registry includes all Wave 3 plugins (at least 14 plugins loaded)', () => {
    const plugins = pluginRegistry.getAllPlugins();
    assert.ok(plugins.length >= 14, 'Registry should have at least 14 plugins loaded');
    assert.ok(pluginRegistry.getPlugin('database-misconfig-check'), 'database-misconfig-check should be registered');
    assert.ok(pluginRegistry.getPlugin('smtp-relay-check'), 'smtp-relay-check should be registered');
  });

  // 2. Database Misconfiguration Plugin — Redis Unauthenticated
  await t.test('Database Misconfig: Redis unauthenticated responds +PONG -> CRITICAL/CONFIRMED finding', async () => {
    let redisWrittenData: string[] = [];

    const mockSession: SafeTcpSession = {
      write: async (data: string | Buffer) => {
        redisWrittenData.push(data.toString());
      },
      read: async () => Buffer.from('+PONG\r\n'),
      readUntil: async () => Buffer.from('+PONG\r\n'),
      close: () => {},
    };

    const mockCtx: PluginContext = {
      safeFetch: async () => { throw new Error('Not used for Redis'); },
      safeTlsHandshake: async () => ({} as any),
      safeTcpConnect: async (host: string, port: number) => {
        if (port === 6379) return mockSession;
        throw new Error(`Port ${port} connection refused`);
      },
    };

    const res = await databaseMisconfigCheckPlugin.run({ fqdn: 'db.example.com', type: 'DOMAIN' }, mockCtx);
    assert.equal(res.status, 'COMPLETED');
    const redisFinding = res.findings.find(f => f.findingCode === 'DB-REDIS-UNAUTHENTICATED');
    assert.ok(redisFinding, 'Should detect unauthenticated Redis');
    assert.equal(redisFinding.severity, 'CRITICAL');
    assert.equal(redisFinding.confidence, 'CONFIRMED');
    assert.equal(redisFinding.category, 'EXPOSED_SERVICES');
    assert.ok(redisWrittenData.includes('PING\r\n'), 'Should send PING command');
  });

  // 3. Database Misconfig: Redis requiring authentication -> No finding
  await t.test('Database Misconfig: Redis requiring auth (NOAUTH) -> Zero finding emitted', async () => {
    const mockSession: SafeTcpSession = {
      write: async () => {},
      read: async () => Buffer.from('-NOAUTH Authentication required.\r\n'),
      readUntil: async () => Buffer.from('-NOAUTH Authentication required.\r\n'),
      close: () => {},
    };

    const mockCtx: PluginContext = {
      safeFetch: async () => { throw new Error('Port closed'); },
      safeTlsHandshake: async () => ({} as any),
      safeTcpConnect: async (host: string, port: number) => {
        if (port === 6379) return mockSession;
        throw new Error('Port closed');
      },
    };

    const res = await databaseMisconfigCheckPlugin.run({ fqdn: 'redis.secure.com', type: 'DOMAIN' }, mockCtx);
    const redisFinding = res.findings.find(f => f.findingCode === 'DB-REDIS-UNAUTHENTICATED');
    assert.equal(redisFinding, undefined, 'Must not report authenticated Redis as finding');
  });

  // 4. Database Misconfiguration Plugin — Elasticsearch Unauthenticated
  await t.test('Database Misconfig: Elasticsearch cluster exposed unauthenticated -> CRITICAL/CONFIRMED', async () => {
    const mockCtx: PluginContext = {
      safeFetch: async (url: string) => {
        if (url.includes(':9200')) {
          return new Response(JSON.stringify({
            name: 'node-1',
            cluster_name: 'prod-es-cluster',
            version: { number: '8.12.2' },
            tagline: 'You Know, for Search',
          }), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }
        throw new Error('Network error');
      },
      safeTlsHandshake: async () => ({} as any),
      safeTcpConnect: async () => { throw new Error('Port closed'); },
    };

    const res = await databaseMisconfigCheckPlugin.run({ fqdn: 'search.example.com', type: 'DOMAIN' }, mockCtx);
    const esFinding = res.findings.find(f => f.findingCode === 'DB-ELASTICSEARCH-UNAUTHENTICATED');
    assert.ok(esFinding, 'Should detect exposed unauthenticated Elasticsearch');
    assert.equal(esFinding.severity, 'CRITICAL');
    assert.equal(esFinding.confidence, 'CONFIRMED');
    assert.ok(esFinding.title.includes('prod-es-cluster'));
  });

  // 5. Database Misconfig: Elasticsearch 401 Unauthorized -> No finding
  await t.test('Database Misconfig: Elasticsearch 401 Unauthorized -> Zero finding', async () => {
    const mockCtx: PluginContext = {
      safeFetch: async (url: string) => {
        if (url.includes(':9200')) {
          return new Response('Unauthorized', { status: 401 });
        }
        throw new Error('Network error');
      },
      safeTlsHandshake: async () => ({} as any),
      safeTcpConnect: async () => { throw new Error('Port closed'); },
    };

    const res = await databaseMisconfigCheckPlugin.run({ fqdn: 'search.secure.com', type: 'DOMAIN' }, mockCtx);
    const esFinding = res.findings.find(f => f.findingCode === 'DB-ELASTICSEARCH-UNAUTHENTICATED');
    assert.equal(esFinding, undefined, 'Authenticated Elasticsearch must produce no finding');
  });

  // 6. Database Misconfiguration Plugin — MongoDB Unauthenticated
  await t.test('Database Misconfig: MongoDB responds to isMaster wire protocol -> CRITICAL/CONFIRMED', async () => {
    let mongoWrittenBuf: Buffer | null = null;

    const mockSession: SafeTcpSession = {
      write: async (data: string | Buffer) => {
        mongoWrittenBuf = Buffer.isBuffer(data) ? data : Buffer.from(data);
      },
      read: async () => {
        // Return simulated MongoDB isMaster BSON response
        const dummyBson = Buffer.alloc(100);
        dummyBson.write('ismaster', 20, 'ascii');
        dummyBson.write('maxBsonObjectSize', 40, 'ascii');
        return dummyBson;
      },
      readUntil: async () => Buffer.alloc(0),
      close: () => {},
    };

    const mockCtx: PluginContext = {
      safeFetch: async () => { throw new Error('Port closed'); },
      safeTlsHandshake: async () => ({} as any),
      safeTcpConnect: async (host: string, port: number) => {
        if (port === 27017) return mockSession;
        throw new Error('Port closed');
      },
    };

    const res = await databaseMisconfigCheckPlugin.run({ fqdn: 'mongo.example.com', type: 'DOMAIN' }, mockCtx);
    const mongoFinding = res.findings.find(f => f.findingCode === 'DB-MONGODB-UNAUTHENTICATED');
    assert.ok(mongoFinding, 'Should detect exposed unauthenticated MongoDB');
    assert.equal(mongoFinding.severity, 'CRITICAL');
    assert.equal(mongoFinding.confidence, 'CONFIRMED');
    assert.ok(mongoWrittenBuf !== null, 'Should have sent OP_QUERY wire packet');
  });

  // 7. Open SMTP Relay Plugin (Option 2A: Heuristic-Only, Aborted Dialogue)
  await t.test('SMTP Relay (Option 2A): Probes dialogue, safely aborts before DATA, sets MEDIUM confidence', async () => {
    const dialogueLog: string[] = [];
    let socketClosed = false;

    const mockSession: SafeTcpSession = {
      write: async (data: string | Buffer) => {
        const text = data.toString();
        dialogueLog.push(`CLIENT: ${text.trim()}`);
      },
      read: async () => {
        const lastClientMsg = dialogueLog[dialogueLog.length - 1];
        if (!lastClientMsg) {
          return Buffer.from('220 mail.example.com ESMTP Postfix\r\n');
        }
        if (lastClientMsg.includes('EHLO')) {
          return Buffer.from('250-mail.example.com\r\n250 HELP\r\n');
        }
        if (lastClientMsg.includes('MAIL FROM')) {
          return Buffer.from('250 2.1.0 Ok\r\n');
        }
        if (lastClientMsg.includes('RCPT TO')) {
          return Buffer.from('250 2.1.5 Ok recipient external-domain accepted\r\n');
        }
        return Buffer.from('221 2.0.0 Bye\r\n');
      },
      readUntil: async () => Buffer.alloc(0),
      close: () => {
        socketClosed = true;
      },
    };

    const mockCtx: PluginContext = {
      safeFetch: async () => { throw new Error('Not used'); },
      safeTlsHandshake: async () => ({} as any),
      safeTcpConnect: async (host: string, port: number) => {
        if (port === 25) return mockSession;
        throw new Error('Port 587 closed');
      },
    };

    const res = await smtpRelayCheckPlugin.run({ fqdn: 'mail.openrelay.com', type: 'DOMAIN' }, mockCtx);
    assert.equal(res.status, 'COMPLETED');
    const relayFinding = res.findings.find(f => f.findingCode === 'SMTP-OPEN-RELAY-SUSPECTED');
    assert.ok(relayFinding, 'Should detect suspected open relay');
    assert.equal(relayFinding.severity, 'HIGH');
    assert.equal(relayFinding.confidence, 'MEDIUM', 'Confidence ceiling MUST be MEDIUM under Option 2A');

    // VERIFY CRITICAL SAFETY INVARIANTS:
    // 1. Client must have sent QUIT
    assert.ok(dialogueLog.some(d => d.includes('QUIT')), 'Must have issued QUIT command to abort dialogue');
    // 2. Client must NEVER have sent DATA or email body
    assert.ok(!dialogueLog.some(d => d.includes('DATA')), 'Must NEVER send DATA command under Option 2A');
    // 3. Socket must be closed
    assert.ok(socketClosed, 'Socket must be closed after probe');
  });

  // 8. SMTP Relay Plugin: Relay Rejected -> No finding
  await t.test('SMTP Relay: Server returns 554 Relay Access Denied -> Zero finding', async () => {
    const dialogueLog: string[] = [];

    const mockSession: SafeTcpSession = {
      write: async (data: string | Buffer) => {
        dialogueLog.push(data.toString().trim());
      },
      read: async () => {
        const lastMsg = dialogueLog[dialogueLog.length - 1];
        if (!lastMsg) return Buffer.from('220 mail.protected.com ESMTP Postfix\r\n');
        if (lastMsg.includes('EHLO')) return Buffer.from('250 OK\r\n');
        if (lastMsg.includes('MAIL FROM')) return Buffer.from('250 OK\r\n');
        if (lastMsg.includes('RCPT TO')) return Buffer.from('554 5.7.1 <relay-test@external-unrelated-domain.com>: Relay access denied\r\n');
        return Buffer.from('221 Bye\r\n');
      },
      readUntil: async () => Buffer.alloc(0),
      close: () => {},
    };

    const mockCtx: PluginContext = {
      safeFetch: async () => { throw new Error('Not used'); },
      safeTlsHandshake: async () => ({} as any),
      safeTcpConnect: async () => mockSession,
    };

    const res = await smtpRelayCheckPlugin.run({ fqdn: 'mail.protected.com', type: 'DOMAIN' }, mockCtx);
    const relayFinding = res.findings.find(f => f.findingCode === 'SMTP-OPEN-RELAY-SUSPECTED');
    assert.equal(relayFinding, undefined, 'Protected SMTP server must not generate open relay finding');
  });

  // 9. AI Remediation Library & Grounding Coverage
  await t.test('AI Grounding Library: Covers all 4 Wave 3 codes and validates approved steps', () => {
    const wave3Codes = [
      'DB-REDIS-UNAUTHENTICATED',
      'DB-ELASTICSEARCH-UNAUTHENTICATED',
      'DB-MONGODB-UNAUTHENTICATED',
      'SMTP-OPEN-RELAY-SUSPECTED',
    ];

    for (const code of wave3Codes) {
      const entry = REMEDIATION_LIBRARY[code];
      assert.ok(entry, `Remediation library must contain entry for ${code}`);
      assert.equal(entry.version, '1.2.0', `Version must be 1.2.0 for ${code}`);
      assert.ok(entry.approvedSteps.length >= 2, `${code} must have at least 2 approved steps`);

      // Test valid remediation steps match
      const validationValid = validateRemediationSteps(code, entry.approvedSteps);
      assert.ok(validationValid.valid, `Approved steps for ${code} must pass validation`);

      // Test hallucinated step rejected
      const validationInvalid = validateRemediationSteps(code, ['Install an unauthorized cryptocurrency miner on the database host.']);
      assert.equal(validationInvalid.valid, false, 'Hallucinated steps must be rejected');
      assert.equal(validationInvalid.rejectedSteps.length, 1);
    }
  });

});
