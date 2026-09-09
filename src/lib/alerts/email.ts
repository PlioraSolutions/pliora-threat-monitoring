import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { User } from '@/models/User';
import { Organization } from '@/models/Organization';
import { OrgAlertSettings } from '@/types';

export interface EmailMessage {
  to: string[];
  subject: string;
  text: string;
  html: string;
  attachments?: import('@/types').EmailAttachment[];
}

export interface EmailDeliveryResult {
  success: boolean;
  provider: string;
  messageId?: string;
  error?: string;
}

export interface EmailDeliveryProvider {
  send(message: EmailMessage): Promise<EmailDeliveryResult>;
}

/**
 * Mock email provider used during local development and testing.
 * Records all dispatched messages in memoryStore.sentEmails for assertion.
 */
export class MockEmailProvider implements EmailDeliveryProvider {
  async send(message: EmailMessage): Promise<EmailDeliveryResult> {
    const messageId = `mock-mail-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const record = {
      messageId,
      to: message.to,
      subject: message.subject,
      text: message.text,
      html: message.html,
      attachments: message.attachments,
      sentAt: new Date(),
    };

    memoryStore.sentEmails.push(record);
    console.log(`[EmailProvider:Mock] Email delivered to [${message.to.join(', ')}]: "${message.subject}"`);

    return {
      success: true,
      provider: 'mock',
      messageId,
    };
  }
}

// Active provider instance (can be swapped with Resend/SMTP provider in production)
let currentEmailProvider: EmailDeliveryProvider = new MockEmailProvider();

export function setEmailProvider(provider: EmailDeliveryProvider): void {
  currentEmailProvider = provider;
}

export function getEmailProvider(): EmailDeliveryProvider {
  return currentEmailProvider;
}

/**
 * Resolves recipient email addresses for an organization (§3).
 * Invariant: Sends to all OWNER and ADMIN users by default; never sends to VIEWERs.
 */
export async function resolveAlertRecipients(
  organizationId: string,
  alertSettings?: OrgAlertSettings
): Promise<string[]> {
  const recipients = new Set<string>();
  const orgIdStr = organizationId.toString();

  // 1. Gather OWNER and ADMIN emails from User store if sendToAdmins is enabled (default true)
  const shouldSendToAdmins = alertSettings?.sendToAdmins !== false;

  if (shouldSendToAdmins) {
    if (isMongoActive()) {
      const adminUsers = await User.find({
        'organizationMemberships.organizationId': organizationId,
        'organizationMemberships.role': { $in: ['OWNER', 'ADMIN'] },
      });

      for (const u of adminUsers) {
        if (u.email) recipients.add(u.email.toLowerCase().trim());
      }
    } else {
      const allUsers = Array.from(memoryStore.users.values());
      for (const u of allUsers) {
        const mem = u.organizationMemberships?.find(
          (m: any) =>
            m.organizationId?.toString() === orgIdStr &&
            (m.role === 'OWNER' || m.role === 'ADMIN')
        );
        if (mem && u.email) {
          recipients.add(u.email.toLowerCase().trim());
        }
      }
    }
  }

  // 2. Include additional explicit recipient emails
  if (Array.isArray(alertSettings?.additionalEmails)) {
    for (const email of alertSettings.additionalEmails) {
      if (email && typeof email === 'string' && email.includes('@')) {
        recipients.add(email.toLowerCase().trim());
      }
    }
  }

  // 3. Fallback: If no users found, check Organization settings or owner
  if (recipients.size === 0) {
    let org: any = null;
    if (isMongoActive()) {
      org = await Organization.findById(organizationId);
    } else {
      org = memoryStore.organizations.get(orgIdStr);
    }

    if (org?.settings?.alertEmail) {
      recipients.add(org.settings.alertEmail.toLowerCase().trim());
    }
    if (Array.isArray(org?.alertSettings?.additionalEmails)) {
      for (const email of org.alertSettings.additionalEmails) {
        if (email && typeof email === 'string' && email.includes('@')) {
          recipients.add(email.toLowerCase().trim());
        }
      }
    }
    if (recipients.size === 0 && org?.ownerId) {
      const owner = isMongoActive()
        ? await User.findById(org.ownerId)
        : memoryStore.users.get(org.ownerId);
      if (owner?.email) {
        recipients.add(owner.email.toLowerCase().trim());
      }
    }
  }

  // 4. In memory mode, check if any registered user matches orgId in membership
  if (recipients.size === 0 && !isMongoActive()) {
    for (const u of Array.from(memoryStore.users.values())) {
      const isMember = u.organizationMemberships?.some(
        (m: any) => m.organizationId?.toString() === orgIdStr
      );
      if (isMember && u.email) {
        recipients.add(u.email.toLowerCase().trim());
        break;
      }
    }
  }

  return Array.from(recipients);
}
