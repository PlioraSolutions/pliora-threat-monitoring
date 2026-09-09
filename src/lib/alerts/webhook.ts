import crypto from 'crypto';
import { safeFetch } from '@/lib/security';
import { AlertType, AlertSeverity } from '@/types';

export interface WebhookAlertPayload {
  event: AlertType;
  severity: AlertSeverity;
  title: string;
  summary: string;
  targetName: string;
  riskScore?: number;
  findingTitle?: string;
  remediationSummary?: string;
  dashboardUrl?: string;
  timestamp: string;
}

export interface SendWebhookOptions {
  url: string;
  secret?: string;
  channel?: 'GENERIC' | 'SLACK';
}

export function formatSlackBlockKit(payload: WebhookAlertPayload) {
  const colorMap: Record<string, string> = {
    CRITICAL: '#ef4444',
    HIGH: '#f97316',
    MEDIUM: '#eab308',
    LOW: '#3b82f6',
    INFO: '#6b7280',
  };

  const color = colorMap[payload.severity] || '#6b7280';

  return {
    attachments: [
      {
        color,
        blocks: [
          {
            type: 'header',
            text: {
              type: 'plain_text',
              text: `🚨 ${payload.severity} Alert: ${payload.title}`,
              emoji: true,
            },
          },
          {
            type: 'section',
            fields: [
              {
                type: 'mrkdwn',
                text: `*Target:*\n\`${payload.targetName}\``,
              },
              {
                type: 'mrkdwn',
                text: `*Severity:*\n*${payload.severity}*${payload.riskScore ? ` (Score: ${payload.riskScore})` : ''}`,
              },
            ],
          },
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: `*Details:*\n${payload.summary}`,
            },
          },
          ...(payload.remediationSummary
            ? [
                {
                  type: 'section',
                  text: {
                    type: 'mrkdwn',
                    text: `*Recommended Action:*\n${payload.remediationSummary}`,
                  },
                },
              ]
            : []),
          {
            type: 'context',
            elements: [
              {
                type: 'mrkdwn',
                text: `PLIŌRA Threat Monitor • Event: \`${payload.event}\` • <!date^${Math.floor(
                  new Date(payload.timestamp).getTime() / 1000
                )}^{date_num} {time_secs}|${payload.timestamp}>`,
              },
            ],
          },
        ],
      },
    ],
  };
}

export async function sendWebhookAlert(
  payload: WebhookAlertPayload,
  options: SendWebhookOptions
): Promise<{ success: boolean; statusCode?: number; error?: string }> {
  try {
    const isSlack = options.channel === 'SLACK';
    const bodyContent = isSlack
      ? JSON.stringify(formatSlackBlockKit(payload))
      : JSON.stringify(payload);

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'Pliora-ThreatMonitor-Webhook/1.0 (+https://pliora.io)',
    };

    if (options.secret && !isSlack) {
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const signedPayload = `${timestamp}.${bodyContent}`;
      const signature = crypto
        .createHmac('sha256', options.secret)
        .update(signedPayload)
        .digest('hex');
      
      const sigHeader = `t=${timestamp},v1=${signature}`;
      headers['X-Pliora-Signature'] = sigHeader;
      headers['x-pliora-signature'] = sigHeader;
    }

    // Outbound webhook dispatch via safeFetch (SSRF-protected, timeout bounded)
    const response = await safeFetch(options.url, {
      method: 'POST',
      headers,
      body: bodyContent,
      timeoutMs: 5000,
    });

    if (response.ok) {
      return { success: true, statusCode: response.status };
    }

    return {
      success: false,
      statusCode: response.status,
      error: `Webhook destination returned HTTP status ${response.status}`,
    };
  } catch (err: any) {
    return {
      success: false,
      error: err.message || 'Network error during webhook dispatch',
    };
  }
}

/**
 * Helper to verify an incoming webhook payload using X-Pliora-Signature.
 * Signature format: "t={timestamp},v1={hmacHex}"
 */
export function verifyWebhookSignature(
  payloadString: string,
  signatureHeader: string,
  secret: string,
  toleranceSeconds: number = 300
): { valid: boolean; reason?: string } {
  try {
    const parts = Object.fromEntries(
      signatureHeader.split(',').map((part) => {
        const [k, ...v] = part.trim().split('=');
        return [k, v.join('=')];
      })
    );

    const timestamp = parts.t;
    const signature = parts.v1;

    if (!timestamp || !signature) {
      return { valid: false, reason: 'Malformed signature header' };
    }

    // Check timestamp tolerance if specified
    const tsNum = parseInt(timestamp, 10);
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - tsNum) > toleranceSeconds) {
      return { valid: false, reason: 'Timestamp outside tolerance window (replay protection)' };
    }

    const signedPayload = `${timestamp}.${payloadString}`;
    const expectedHmac = crypto
      .createHmac('sha256', secret)
      .update(signedPayload)
      .digest('hex');

    const signatureBuf = Buffer.from(signature, 'hex');
    const expectedBuf = Buffer.from(expectedHmac, 'hex');

    if (signatureBuf.length !== expectedBuf.length) {
      return { valid: false, reason: 'Signature length mismatch' };
    }

    const matches = crypto.timingSafeEqual(signatureBuf, expectedBuf);
    return { valid: matches, reason: matches ? undefined : 'HMAC signature mismatch' };
  } catch (err: any) {
    return { valid: false, reason: err.message };
  }
}

