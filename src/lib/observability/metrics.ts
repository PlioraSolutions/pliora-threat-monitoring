import { externalApiTracker } from '@/lib/usage/externalApiTracker';

export interface ScanMetrics {
  totalStarted: number;
  succeeded: number;
  failed: number;
  partial: number;
  totalDurationMs: number;
  averageDurationMs: number;
}

export interface ChannelDeliveryMetrics {
  attempted: number;
  succeeded: number;
  failed: number;
  successRatePercent: number;
}

export interface AlertMetrics {
  totalAttempted: number;
  totalSucceeded: number;
  totalFailed: number;
  byChannel: {
    EMAIL: ChannelDeliveryMetrics;
    WEBHOOK: ChannelDeliveryMetrics;
    SLACK: ChannelDeliveryMetrics;
  };
}

export interface AIMetrics {
  totalRequests: number;
  providerSuccesses: number;
  groundingRejections: number;
  fallbacksTriggered: number;
  fallbackRatePercent: number;
}

export interface BillingMetrics {
  webhooksReceived: number;
  webhooksProcessed: number;
  webhooksFailed: number;
  checkoutSessionsCreated: number;
  portalSessionsCreated: number;
}

export interface CalibrationMetrics {
  totalFeedbackSamples: number;
  miscalibratedCount: number;
  platformFpRatePercent: number;
  lastAnalysisTimestamp?: string;
}

export class MetricsCollector {
  private scans: ScanMetrics = {
    totalStarted: 0,
    succeeded: 0,
    failed: 0,
    partial: 0,
    totalDurationMs: 0,
    averageDurationMs: 0,
  };

  private alerts: AlertMetrics = {
    totalAttempted: 0,
    totalSucceeded: 0,
    totalFailed: 0,
    byChannel: {
      EMAIL: { attempted: 0, succeeded: 0, failed: 0, successRatePercent: 100 },
      WEBHOOK: { attempted: 0, succeeded: 0, failed: 0, successRatePercent: 100 },
      SLACK: { attempted: 0, succeeded: 0, failed: 0, successRatePercent: 100 },
    },
  };

  private ai: AIMetrics = {
    totalRequests: 0,
    providerSuccesses: 0,
    groundingRejections: 0,
    fallbacksTriggered: 0,
    fallbackRatePercent: 0,
  };

  private billing: BillingMetrics = {
    webhooksReceived: 0,
    webhooksProcessed: 0,
    webhooksFailed: 0,
    checkoutSessionsCreated: 0,
    portalSessionsCreated: 0,
  };

  private calibration: CalibrationMetrics = {
    totalFeedbackSamples: 0,
    miscalibratedCount: 0,
    platformFpRatePercent: 0,
  };

  // --- Scan Metrics ---
  recordScanStarted(): void {
    this.scans.totalStarted++;
  }

  recordScanCompleted(status: 'COMPLETED' | 'FAILED' | 'PARTIAL', durationMs: number): void {
    if (status === 'COMPLETED') this.scans.succeeded++;
    else if (status === 'FAILED') this.scans.failed++;
    else if (status === 'PARTIAL') this.scans.partial++;

    this.scans.totalDurationMs += durationMs;
    const completedTotal = this.scans.succeeded + this.scans.failed + this.scans.partial;
    this.scans.averageDurationMs = completedTotal > 0 ? Math.round(this.scans.totalDurationMs / completedTotal) : 0;
  }

  // --- Alert Delivery Metrics ---
  recordAlertDelivery(channel: 'EMAIL' | 'WEBHOOK' | 'SLACK', success: boolean): void {
    this.alerts.totalAttempted++;
    const target = this.alerts.byChannel[channel];
    target.attempted++;

    if (success) {
      this.alerts.totalSucceeded++;
      target.succeeded++;
    } else {
      this.alerts.totalFailed++;
      target.failed++;
    }

    target.successRatePercent = target.attempted > 0
      ? Math.round((target.succeeded / target.attempted) * 1000) / 10
      : 100;
  }

  // --- AI Grounding & Fallback Metrics ---
  recordAIRequest(providerSuccess: boolean, fallbackTriggered: boolean, groundingRejected: boolean = false): void {
    this.ai.totalRequests++;
    if (providerSuccess) this.ai.providerSuccesses++;
    if (groundingRejected) this.ai.groundingRejections++;
    if (fallbackTriggered) this.ai.fallbacksTriggered++;

    this.ai.fallbackRatePercent = this.ai.totalRequests > 0
      ? Math.round((this.ai.fallbacksTriggered / this.ai.totalRequests) * 1000) / 10
      : 0;
  }

  // --- Billing Metrics ---
  recordBillingWebhook(eventType: string, success: boolean): void {
    this.billing.webhooksReceived++;
    if (success) {
      this.billing.webhooksProcessed++;
    } else {
      this.billing.webhooksFailed++;
    }
  }

  recordCheckoutSessionCreated(): void {
    this.billing.checkoutSessionsCreated++;
  }

  recordPortalSessionCreated(): void {
    this.billing.portalSessionsCreated++;
  }

  // --- Calibration Drift Metrics ---
  recordCalibrationDrift(summary: { totalSamples: number; miscalibratedCount: number; platformFpRatePercent: number }): void {
    this.calibration.totalFeedbackSamples = summary.totalSamples;
    this.calibration.miscalibratedCount = summary.miscalibratedCount;
    this.calibration.platformFpRatePercent = summary.platformFpRatePercent;
    this.calibration.lastAnalysisTimestamp = new Date().toISOString();
  }

  // --- Telemetry Snapshot ---
  getMetricsSnapshot() {
    let externalApiSummary: any = null;
    try {
      externalApiSummary = externalApiTracker.getUsageMetrics();
    } catch {
      externalApiSummary = { status: 'unavailable' };
    }

    return {
      timestamp: new Date().toISOString(),
      uptimeSeconds: Math.floor(process.uptime()),
      scans: { ...this.scans },
      alerts: { ...this.alerts },
      aiAnalyst: { ...this.ai },
      billing: { ...this.billing },
      calibration: { ...this.calibration },
      externalApiUsage: externalApiSummary,
    };
  }

  resetForTesting(): void {
    this.scans = {
      totalStarted: 0,
      succeeded: 0,
      failed: 0,
      partial: 0,
      totalDurationMs: 0,
      averageDurationMs: 0,
    };
    this.alerts = {
      totalAttempted: 0,
      totalSucceeded: 0,
      totalFailed: 0,
      byChannel: {
        EMAIL: { attempted: 0, succeeded: 0, failed: 0, successRatePercent: 100 },
        WEBHOOK: { attempted: 0, succeeded: 0, failed: 0, successRatePercent: 100 },
        SLACK: { attempted: 0, succeeded: 0, failed: 0, successRatePercent: 100 },
      },
    };
    this.ai = {
      totalRequests: 0,
      providerSuccesses: 0,
      groundingRejections: 0,
      fallbacksTriggered: 0,
      fallbackRatePercent: 0,
    };
    this.billing = {
      webhooksReceived: 0,
      webhooksProcessed: 0,
      webhooksFailed: 0,
      checkoutSessionsCreated: 0,
      portalSessionsCreated: 0,
    };
    this.calibration = {
      totalFeedbackSamples: 0,
      miscalibratedCount: 0,
      platformFpRatePercent: 0,
    };
  }
}

export const metrics = new MetricsCollector();
