import test from 'node:test';
import assert from 'node:assert/strict';
import { safeTcpConnect } from '../src/lib/security';

test('Security & SSRF Hardening: safeTcpConnect', async (t) => {

  await t.test('Blocks loopback IP (127.0.0.1)', async () => {
    await assert.rejects(
      async () => {
        await safeTcpConnect('127.0.0.1', 6379);
      },
      /SSRF Blocked/
    );
  });

  await t.test('Blocks RFC1918 private IP (10.0.0.1)', async () => {
    await assert.rejects(
      async () => {
        await safeTcpConnect('10.0.0.1', 27017);
      },
      /SSRF Blocked/
    );
  });

  await t.test('Blocks RFC1918 private IP (192.168.1.1)', async () => {
    await assert.rejects(
      async () => {
        await safeTcpConnect('192.168.1.1', 6379);
      },
      /SSRF Blocked/
    );
  });

  await t.test('Blocks RFC1918 private IP (172.16.0.1)', async () => {
    await assert.rejects(
      async () => {
        await safeTcpConnect('172.16.0.1', 9200);
      },
      /SSRF Blocked/
    );
  });

  await t.test('Blocks Cloud Metadata IP (169.254.169.254)', async () => {
    await assert.rejects(
      async () => {
        await safeTcpConnect('169.254.169.254', 80);
      },
      /SSRF Blocked/
    );
  });

  await t.test('Blocks localhost hostname', async () => {
    await assert.rejects(
      async () => {
        await safeTcpConnect('localhost', 6379);
      },
      /SSRF Blocked/
    );
  });
});
