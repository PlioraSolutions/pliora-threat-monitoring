import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { Alert, IAlert } from '@/models/Alert';
import { Organization } from '@/models/Organization';
import { WebhookEndpoint } from '@/models/WebhookEndpoint';
import { AuditLog } from '@/models/AuditLog';
import { AlertType, AlertSeverity, OrgAlertSettings } from '@/types';
import {
  shouldAlertOnFinding,
  shouldAlertOnAssetDiscovery,
  shouldAlertOnThreat,
  computeAlertDedupKey,
  isAlertSuppressed,
  DEFAULT_ALERT_SETTINGS,
} from './rules';
import { renderAlertEmail } from './templates';
import { resolveAlertRecipients, getEmailProvider } from './email';
import { sendWebhookAlert } from './webhook';
import { errorTracker } from '@/lib/observability/errorTracker';
import { metrics } from '@/lib/observability/metrics';
import { logger } from '@/lib/observability/logger';

export interface AlertTriggerInput {
  organizationId: string;
  type: AlertType;
  targetName: string;
  finding?: any;
  asset?: any;
  threat?: any;
  scan?: any;
  method?: string;
  error?: string;
  dashboardBaseUrl?: string;
}

export interface AlertTriggerResult {
  triggered: boolean;
  alert?: any;
  reason?: string;
}

/**
 * Loads organization alert settings merged with default values.
 */
export async function getOrganizationAlertSettings(
  organizationId: string
): Promise<OrgAlertSettings> {
  const orgIdStr = organizationId.toString();
  let org: any = null;

  if (isMongoActive()) {
    org = await Organization.findById(organizationId);
  } else {
    org = memoryStore.organizations.get(orgIdStr);
  }

  const savedSettings = org?.alertSettings;
  return {
    enabledTypes: savedSettings?.enabledTypes || DEFAULT_ALERT_SETTINGS.enabledTypes,
    minRiskScore: savedSettings?.minRiskScore ?? DEFAULT_ALERT_SETTINGS.minRiskScore,
    additionalEmails: savedSettings?.additionalEmails || DEFAULT_ALERT_SETTINGS.additionalEmails,
    sendToAdmins: savedSettings?.sendToAdmins ?? DEFAULT_ALERT_SETTINGS.sendToAdmins,
    webhookUrl: savedSettings?.webhookUrl,
    webhookSecret: savedSettings?.webhookSecret,
    webhookChannel: savedSettings?.webhookChannel || 'GENERIC',
  };
}

/**
 * Queries recent alerts for an organization within the suppression window.
 */
async function getRecentAlertsForOrg(
  organizationId: string,
  dedupKey: string
): Promise<Array<{ dedupKey: string; createdAt: Date; type?: string }>> {
  const orgIdStr = organizationId.toString();

  if (isMongoActive()) {
    return await Alert.find({
      organizationId,
      dedupKey,
    })
      .sort({ createdAt: -1 })
      .limit(10)
      .lean();
  }

  const allAlerts = Array.from(memoryStore.alerts.values());
  return allAlerts.filter(
    (a) => a.organizationId?.toString() === orgIdStr && a.dedupKey === dedupKey
  );
}

/**
 * Core Alert Coordinator: Evaluates triggers, enforces deduplication, persists records,
 * and dispatches plain-language notifications (§1, §2, §3).
 */
export async function triggerAlert(input: AlertTriggerInput): Promise<AlertTriggerResult> {
  const orgIdStr = input.organizationId.toString();
  const alertSettings = await getOrganizationAlertSettings(orgIdStr);

  let alertType: AlertType = input.type;
  let severity: AlertSeverity = 'INFO';
  let title = '';
  let summary = '';
  let dedupKey = '';
  let targetUrl = `${input.dashboardBaseUrl || 'https://app.pliora.io'}/dashboard`;

  // 1. Evaluate Rule Engine by Event Category
  if (input.type === 'NEW_CRITICAL_FINDING' || input.type === 'NEW_HIGH_FINDING') {
    if (!input.finding) {
      return { triggered: false, reason: 'Finding object required for security alert.' };
    }

    const decision = shouldAlertOnFinding(input.finding, input.asset || {}, alertSettings);
    if (!decision.shouldAlert) {
      return { triggered: false, reason: decision.reason };
    }

    alertType = decision.alertType!;
    severity = input.finding.severity;
    title = `${severity} finding detected on ${input.targetName}: ${input.finding.title}`;
    summary = input.finding.description || title;
    targetUrl = `${input.dashboardBaseUrl || 'https://app.pliora.io'}/findings/${input.finding._id || input.finding.id}`;

    // Dedup key includes finding severity to allow escalation bypass (§2.3)
    dedupKey = computeAlertDedupKey(
      alertType,
      orgIdStr,
      (input.finding._id || input.finding.id).toString(),
      input.finding.severity
    );
  } else if (input.type === 'FINDING_AUTO_REOPENED') {
    if (!alertSettings.enabledTypes.includes('FINDING_AUTO_REOPENED')) {
      return { triggered: false, reason: 'FINDING_AUTO_REOPENED disabled in settings.' };
    }

    severity = input.finding?.severity || 'HIGH';
    title = `Issue re-opened on ${input.targetName}: ${input.finding?.title || 'Security finding'}`;
    summary = `A previously resolved finding (${input.finding?.findingCode}) was re-detected during an active scan.`;
    targetUrl = `${input.dashboardBaseUrl || 'https://app.pliora.io'}/findings/${input.finding?._id || input.finding?.id}`;

    // Unique reopen key (or bypass window)
    dedupKey = computeAlertDedupKey(
      alertType,
      orgIdStr,
      (input.finding?._id || input.finding?.id || 'reopen').toString(),
      `reopen-${Date.now()}`
    );
  } else if (input.type === 'NEW_ASSET_DISCOVERED') {
    const discDecision = shouldAlertOnAssetDiscovery(input.method || 'CT_LOG', alertSettings);
    if (!discDecision.shouldAlert) {
      return { triggered: false, reason: discDecision.reason };
    }

    severity = 'INFO';
    title = `New subdomain discovered: ${input.targetName}`;
    summary = `Asset ${input.targetName} was passively discovered via ${input.method || 'CT_LOG'}.`;
    targetUrl = `${input.dashboardBaseUrl || 'https://app.pliora.io'}/assets`;

    dedupKey = computeAlertDedupKey(
      alertType,
      orgIdStr,
      (input.asset?._id || input.asset?.id || input.targetName).toString()
    );
  } else if (input.type === 'SCAN_FAILED') {
    if (!alertSettings.enabledTypes.includes('SCAN_FAILED')) {
      return { triggered: false, reason: 'SCAN_FAILED disabled in settings.' };
    }

    severity = 'MEDIUM';
    title = `Scan failed for ${input.targetName}`;
    summary = input.error || 'The security scan encountered a critical error and could not complete.';
    targetUrl = `${input.dashboardBaseUrl || 'https://app.pliora.io'}/scans`;

    // Deduplicate operational failures within a 1-hour bucket
    const hourBucket = Math.floor(Date.now() / (60 * 60 * 1000));
    dedupKey = computeAlertDedupKey(
      alertType,
      orgIdStr,
      (input.asset?._id || input.targetName).toString(),
      `h-${hourBucket}`
    );
  } else if (input.type === 'THREAT_DETECTED') {
    if (!input.threat) {
      return { triggered: false, reason: 'Threat object required for brand threat alert.' };
    }

    const threatDecision = shouldAlertOnThreat(input.threat, alertSettings);
    if (!threatDecision.shouldAlert) {
      return { triggered: false, reason: threatDecision.reason };
    }

    severity = input.threat.confidence === 'CONFIRMED' ? 'CRITICAL' : 'HIGH';
    title = `Suspicious look-alike domain detected: ${input.targetName}`;
    summary = `Brand threat targeting ${input.threat.relatedRootDomain} was detected (${input.threat.confidence} confidence, score: ${input.threat.corroborationScore}/100).`;
    targetUrl = `${input.dashboardBaseUrl || 'https://app.pliora.io'}/threats`;

    // Dedup key includes threat confidence to allow escalation bypass (§2.3)
    dedupKey = computeAlertDedupKey(
      alertType,
      orgIdStr,
      (input.threat._id || input.threat.id || input.targetName).toString(),
      input.threat.confidence
    );
  } else {
    dedupKey = computeAlertDedupKey(alertType, orgIdStr, input.targetName);
  }

  // 2. Check Deduplication & Suppression Window (§2.3)
  const recentAlerts = await getRecentAlertsForOrg(orgIdStr, dedupKey);
  if (isAlertSuppressed(recentAlerts, dedupKey, alertType)) {
    return {
      triggered: false,
      reason: `Alert suppressed: identical alert sent within suppression window.`,
    };
  }

  // 3. Resolve Recipients
  const recipients = await resolveAlertRecipients(orgIdStr, alertSettings);

  // 4. Persist Alert Record in PENDING status
  let newAlert: any = null;

  if (isMongoActive()) {
    newAlert = await Alert.create({
      organizationId: input.organizationId,
      type: alertType,
      severity,
      relatedFindingId: input.finding?._id,
      relatedAssetId: input.asset?._id,
      relatedThreatId: input.threat?._id,
      title,
      summary,
      deliveryStatus: 'PENDING',
      deliveryChannel: 'EMAIL',
      recipients,
      retryCount: 0,
      dedupKey,
    });

    await AuditLog.create({
      organizationId: input.organizationId,
      actorId: 'system:alert_engine',
      action: 'ALERT_GENERATED',
      objectType: 'Alert',
      objectId: newAlert._id.toString(),
      result: 'SUCCESS',
      details: { type: alertType, severity, target: input.targetName, recipientsCount: recipients.length },
    });
  } else {
    const alertId = `alert-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    newAlert = {
      _id: alertId,
      id: alertId,
      organizationId: input.organizationId,
      type: alertType,
      severity,
      relatedFindingId: input.finding?._id || input.finding?.id,
      relatedAssetId: input.asset?._id || input.asset?.id,
      relatedThreatId: input.threat?._id || input.threat?.id,
      title,
      summary,
      deliveryStatus: 'PENDING',
      deliveryChannel: 'EMAIL',
      recipients,
      retryCount: 0,
      dedupKey,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    memoryStore.alerts.set(alertId, newAlert);
    memoryStore.auditLogs.push({
      organizationId: input.organizationId,
      actorId: 'system:alert_engine',
      action: 'ALERT_GENERATED',
      objectType: 'Alert',
      objectId: alertId,
      result: 'SUCCESS',
      details: { type: alertType, severity, target: input.targetName, recipientsCount: recipients.length },
      createdAt: new Date(),
    });
  }

  // 5. If no recipients, mark FAILED and return
  if (recipients.length === 0) {
    newAlert.deliveryStatus = 'FAILED';
    newAlert.error = 'No eligible recipient email addresses configured for organization.';
    if (isMongoActive()) await newAlert.save();
    return { triggered: true, alert: newAlert, reason: 'No recipients available' };
  }

  // 6. Render Plain-Language Email (Zero sensitive evidence)
  const rendered = renderAlertEmail({
    type: alertType,
    severity,
    targetName: input.targetName,
    findingTitle: input.finding?.title,
    riskScore: input.finding?.riskScore,
    reason: summary,
    remediationSummary: input.finding?.remediationGuidance?.summary,
    targetUrl,
  });

  // 7. Dispatch Email
  try {
    const sendRes = await getEmailProvider().send({
      to: recipients,
      subject: rendered.subject,
      text: rendered.text,
      html: rendered.html,
    });

    if (sendRes.success) {
      metrics.recordAlertDelivery('EMAIL', true);
      newAlert.deliveryStatus = 'SENT';
      newAlert.deliveredAt = new Date();

      if (isMongoActive()) {
        await newAlert.save();
        await AuditLog.create({
          organizationId: input.organizationId,
          actorId: 'system:alert_engine',
          action: 'ALERT_DELIVERED',
          objectType: 'Alert',
          objectId: newAlert._id.toString(),
          result: 'SUCCESS',
          details: { channel: 'EMAIL', messageId: sendRes.messageId, recipients },
        });
      } else {
        memoryStore.auditLogs.push({
          organizationId: input.organizationId,
          actorId: 'system:alert_engine',
          action: 'ALERT_DELIVERED',
          objectType: 'Alert',
          objectId: newAlert._id,
          result: 'SUCCESS',
          details: { channel: 'EMAIL', messageId: sendRes.messageId, recipients },
          createdAt: new Date(),
        });
      }
    } else {
      metrics.recordAlertDelivery('EMAIL', false);
      errorTracker.captureAlertDeliveryFailure('EMAIL', recipients.join(','), sendRes.error, input.organizationId);
      newAlert.deliveryStatus = 'FAILED';
      newAlert.error = sendRes.error || 'Provider rejected email send.';

      if (isMongoActive()) {
        await newAlert.save();
        await AuditLog.create({
          organizationId: input.organizationId,
          actorId: 'system:alert_engine',
          action: 'ALERT_DELIVERY_FAILED',
          objectType: 'Alert',
          objectId: newAlert._id.toString(),
          result: 'FAILURE',
          details: { error: sendRes.error },
        });
      } else {
        memoryStore.auditLogs.push({
          organizationId: input.organizationId,
          actorId: 'system:alert_engine',
          action: 'ALERT_DELIVERY_FAILED',
          objectType: 'Alert',
          objectId: newAlert._id,
          result: 'FAILURE',
          details: { error: sendRes.error },
          createdAt: new Date(),
        });
      }
    }
  } catch (err: any) {
    newAlert.deliveryStatus = 'FAILED';
    newAlert.error = err.message || 'Unhandled error during email dispatch.';
    if (isMongoActive()) await newAlert.save();
  }

  // 8. Dispatch Webhook / Slack if configured (§A.4 & §1.2)
  let activeEndpoints: any[] = [];
  if (isMongoActive()) {
    activeEndpoints = await WebhookEndpoint.find({
      organizationId: input.organizationId,
      active: true,
    }).lean();
  } else {
    activeEndpoints = Array.from(memoryStore.webhooks.values()).filter(
      (w) => w.organizationId.toString() === orgIdStr && w.active !== false
    );
  }

  // Include legacy alertSettings.webhookUrl if configured and not duplicated
  if (alertSettings.webhookUrl && !activeEndpoints.some((e) => e.url === alertSettings.webhookUrl)) {
    activeEndpoints.push({
      name: 'Default Org Webhook',
      url: alertSettings.webhookUrl,
      secret: alertSettings.webhookSecret,
      format: alertSettings.webhookChannel || 'GENERIC',
      enabledTypes: alertSettings.enabledTypes,
    });
  }

  for (const endpoint of activeEndpoints) {
    if (endpoint.enabledTypes && endpoint.enabledTypes.length > 0 && !endpoint.enabledTypes.includes(alertType)) {
      continue;
    }

    try {
      const webhookRes = await sendWebhookAlert(
        {
          event: alertType,
          severity,
          title,
          summary,
          targetName: input.targetName,
          riskScore: input.finding?.riskScore,
          findingTitle: input.finding?.title,
          remediationSummary: input.finding?.remediationGuidance?.summary,
          dashboardUrl: targetUrl,
          timestamp: new Date().toISOString(),
        },
        {
          url: endpoint.url,
          secret: endpoint.secret,
          channel: endpoint.format || 'GENERIC',
        }
      );

      const auditDetails = {
        channel: endpoint.format || 'GENERIC',
        url: endpoint.url,
        endpointName: endpoint.name,
        statusCode: webhookRes.statusCode,
      };

      const deliveryChannel: 'SLACK' | 'WEBHOOK' = endpoint.format === 'SLACK' ? 'SLACK' : 'WEBHOOK';

      if (webhookRes.success) {
        metrics.recordAlertDelivery(deliveryChannel, true);
        if (isMongoActive()) {
          await AuditLog.create({
            organizationId: input.organizationId,
            actorId: 'system:alert_engine',
            action: 'ALERT_WEBHOOK_DELIVERED',
            objectType: 'Alert',
            objectId: newAlert._id.toString(),
            result: 'SUCCESS',
            details: auditDetails,
          });
        } else {
          memoryStore.auditLogs.push({
            organizationId: input.organizationId,
            actorId: 'system:alert_engine',
            action: 'ALERT_WEBHOOK_DELIVERED',
            objectType: 'Alert',
            objectId: newAlert._id || newAlert.id,
            result: 'SUCCESS',
            details: auditDetails,
            createdAt: new Date(),
          });
        }
      } else {
        metrics.recordAlertDelivery(deliveryChannel, false);
        errorTracker.captureAlertDeliveryFailure(deliveryChannel, endpoint.url, webhookRes.error, input.organizationId);
        const failDetails = { ...auditDetails, error: webhookRes.error };
        if (isMongoActive()) {
          await AuditLog.create({
            organizationId: input.organizationId,
            actorId: 'system:alert_engine',
            action: 'ALERT_WEBHOOK_FAILED',
            objectType: 'Alert',
            objectId: newAlert._id.toString(),
            result: 'FAILURE',
            details: failDetails,
          });
        } else {
          memoryStore.auditLogs.push({
            organizationId: input.organizationId,
            actorId: 'system:alert_engine',
            action: 'ALERT_WEBHOOK_FAILED',
            objectType: 'Alert',
            objectId: newAlert._id || newAlert.id,
            result: 'FAILURE',
            details: failDetails,
            createdAt: new Date(),
          });
        }
      }
    } catch (whErr: any) {
      metrics.recordAlertDelivery(endpoint.format === 'SLACK' ? 'SLACK' : 'WEBHOOK', false);
      errorTracker.captureAlertDeliveryFailure(
        endpoint.format === 'SLACK' ? 'SLACK' : 'WEBHOOK',
        endpoint.url,
        whErr,
        input.organizationId
      );
      logger.warn('[AlertEngine] Webhook delivery encountered error', { error: whErr.message, url: endpoint.url });
    }
  }

  return {
    triggered: true,
    alert: newAlert,
  };
}
