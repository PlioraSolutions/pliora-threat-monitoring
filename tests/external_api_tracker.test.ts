import test from 'node:test';
import assert from 'node:assert/strict';
import { ExternalApiUsageTracker, externalApiTracker } from '../src/lib/usage/externalApiTracker';

test('ExternalApiUsageTracker: Rate Limits, Daily Budgets & Graceful Degradation Suite', async (t) => {
  const tracker = new ExternalApiUsageTracker({
    GITHUB_CODE_SEARCH: {
      requestsPerMinute: 3,
      requestsPerDay: 5,
      monthlyBudget: 100,
    },
    PASTE_AGGREGATOR: {
      requestsPerMinute: 2,
      requestsPerDay: 4,
      monthlyBudget: 50,
    },
    BREACH_DIRECTORY: {
      requestsPerMinute: 2,
      requestsPerDay: 3,
      monthlyBudget: 30,
    },
  });

  await t.test('1. Allows calls within rolling-minute and daily limits', async () => {
    tracker.resetForTesting();
    tracker.setLimits('GITHUB_CODE_SEARCH', { requestsPerMinute: 3, requestsPerDay: 5 });

    const clearance1 = tracker.canExecuteCall('GITHUB_CODE_SEARCH', 'org-1');
    assert.equal(clearance1.allowed, true);

    const execRes1 = await tracker.executeWithQuota('GITHUB_CODE_SEARCH', 'org-1', async () => {
      return { data: 'repo-result-1' };
    });

    assert.equal(execRes1.executed, true);
    if (execRes1.executed) {
      assert.equal(execRes1.result.data, 'repo-result-1');
    }
  });

  await t.test('2. Enforces rolling 1-minute rate limit', async () => {
    // We configured 3 req/min for GITHUB_CODE_SEARCH
    // 1 call was already made above. Let's make 2 more calls to reach 3.
    await tracker.executeWithQuota('GITHUB_CODE_SEARCH', 'org-1', async () => ({ data: 2 }));
    await tracker.executeWithQuota('GITHUB_CODE_SEARCH', 'org-1', async () => ({ data: 3 }));

    // 4th call within the same minute should be denied by rate limit
    const clearance = tracker.canExecuteCall('GITHUB_CODE_SEARCH', 'org-1');
    assert.equal(clearance.allowed, false);
    assert.ok(clearance.reason?.includes('minute rate limit exceeded'));
  });

  await t.test('3. Graceful degradation when rate limit or quota exceeded', async () => {
    let fnExecuted = false;
    const res = await tracker.executeWithQuota('GITHUB_CODE_SEARCH', 'org-1', async () => {
      fnExecuted = true;
      return { secret: 'should-not-run' };
    });

    // Proves function was NOT executed, no error was thrown, and degradation was graceful
    assert.equal(fnExecuted, false, 'Function should not execute when quota is exhausted');
    assert.equal(res.executed, false);
    assert.ok(res.reason?.includes('minute rate limit exceeded'));

    // Verify metrics recorded this as SKIPPED
    const metrics = tracker.getUsageMetrics();
    assert.equal(metrics.providers.GITHUB_CODE_SEARCH.totalSkipped >= 1, true);
  });

  await t.test('4. Enforces daily platform-wide budget', async () => {
    tracker.resetForTesting();
    tracker.setLimits('BREACH_DIRECTORY', { requestsPerMinute: 100, requestsPerDay: 2 });

    // Execute 2 allowed calls
    await tracker.executeWithQuota('BREACH_DIRECTORY', 'org-1', async () => 'call 1');
    await tracker.executeWithQuota('BREACH_DIRECTORY', 'org-2', async () => 'call 2');

    // 3rd call exceeds daily budget of 2
    const clearance = tracker.canExecuteCall('BREACH_DIRECTORY', 'org-3');
    assert.equal(clearance.allowed, false);
    assert.ok(clearance.reason?.includes('Daily free-tier platform budget exhausted'));

    let breachExecuted = false;
    const res = await tracker.executeWithQuota('BREACH_DIRECTORY', 'org-3', async () => {
      breachExecuted = true;
      return 'call 3';
    });

    assert.equal(breachExecuted, false);
    assert.equal(res.executed, false);
    assert.ok(res.reason?.includes('Daily free-tier platform budget exhausted'));
  });

  await t.test('5. Accurate operational metrics and organization breakdown', async () => {
    tracker.resetForTesting();
    tracker.setLimits('PASTE_AGGREGATOR', { requestsPerMinute: 10, requestsPerDay: 100 });

    await tracker.executeWithQuota('PASTE_AGGREGATOR', 'org-alpha', async () => 'alpha1');
    await tracker.executeWithQuota('PASTE_AGGREGATOR', 'org-alpha', async () => 'alpha2');
    await tracker.executeWithQuota('PASTE_AGGREGATOR', 'org-beta', async () => 'beta1');

    const metrics = tracker.getUsageMetrics();
    const pasteMetrics = metrics.providers.PASTE_AGGREGATOR;

    assert.equal(pasteMetrics.usedToday, 3);
    assert.equal(pasteMetrics.orgBreakdown['org-alpha'], 2);
    assert.equal(pasteMetrics.orgBreakdown['org-beta'], 1);
    assert.equal(metrics.totalPlatformCallsToday, 3);
  });

  await t.test('6. Global singleton tracker exists with default published limits', () => {
    const globalMetrics = externalApiTracker.getUsageMetrics();
    assert.ok(globalMetrics.providers.GITHUB_CODE_SEARCH);
    assert.equal(globalMetrics.providers.GITHUB_CODE_SEARCH.limits.requestsPerMinute, 30);
    assert.equal(globalMetrics.providers.GITHUB_CODE_SEARCH.limits.requestsPerDay, 500);

    assert.ok(globalMetrics.providers.PASTE_AGGREGATOR);
    assert.equal(globalMetrics.providers.PASTE_AGGREGATOR.limits.requestsPerMinute, 10);
    assert.equal(globalMetrics.providers.PASTE_AGGREGATOR.limits.requestsPerDay, 200);

    assert.ok(globalMetrics.providers.BREACH_DIRECTORY);
    assert.equal(globalMetrics.providers.BREACH_DIRECTORY.limits.requestsPerMinute, 10);
    assert.equal(globalMetrics.providers.BREACH_DIRECTORY.limits.requestsPerDay, 150);
  });
});
