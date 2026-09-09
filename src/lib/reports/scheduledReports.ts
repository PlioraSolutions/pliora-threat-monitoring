import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { Organization } from '@/models/Organization';
import { AuditLog } from '@/models/AuditLog';
import { assembleReportData } from './reportData';
import { renderReportPdf } from './pdfRenderer';
import { getEmailProvider, resolveAlertRecipients } from '@/lib/alerts/email';

export interface ScheduledReportDispatchResult {
  organizationId: string;
  triggered: boolean;
  success: boolean;
  recipients?: string[];
  reason?: string;
  error?: string;
}

/**
 * Executes a scheduled monthly report delivery for an organization (§4).
 * 
 * INVARIANT: Opt-in only (scheduledReports.enabled must be explicitly true).
 * Assembles data, renders the PDF in-process, and delivers it via existing email provider.
 */
export async function sendMonthlyScheduledReport(
  organizationId: string
): Promise<ScheduledReportDispatchResult> {
  const orgIdStr = organizationId.toString();

  // 1. Resolve Organization
  let org: any = null;
  if (isMongoActive()) {
    org = await Organization.findById(organizationId);
  } else {
    org = memoryStore.organizations.get(orgIdStr);
  }

  if (!org) {
    return {
      organizationId: orgIdStr,
      triggered: false,
      success: false,
      reason: 'Organization not found',
    };
  }

  // 2. Opt-in Guard: scheduledReports must be enabled (§4)
  if (!org.scheduledReports?.enabled) {
    return {
      organizationId: orgIdStr,
      triggered: false,
      success: false,
      reason: 'Scheduled reports are not enabled for this organization.',
    };
  }

  // 3. Resolve Recipients
  let recipients: string[] = [];
  if (org.scheduledReports.recipients && org.scheduledReports.recipients.length > 0) {
    recipients = org.scheduledReports.recipients;
  } else {
    recipients = await resolveAlertRecipients(orgIdStr);
  }

  if (recipients.length === 0) {
    return {
      organizationId: orgIdStr,
      triggered: true,
      success: false,
      reason: 'No eligible recipient email addresses configured.',
    };
  }

  try {
    // 4. Pure Data Assembly & PDF Render
    const reportData = await assembleReportData(orgIdStr, { actorId: 'system:scheduler' });
    const pdfBuffer = await renderReportPdf(reportData);

    const reportDateIso = reportData.metadata.generatedAt.split('T')[0];
    const filename = `security-report-${reportData.organization.slug}-${reportDateIso}.pdf`;

    // 5. Render Plain-Text and HTML Notification
    const subject = `[${reportData.branding.brandName}] Monthly Security Risk Assessment — ${reportData.organization.name}`;
    const textBody = `Hello,

Your monthly Executive Security Risk Assessment for ${reportData.organization.name} is ready.

Current Security Posture:
- Risk Score: ${reportData.riskScore.score} / 100
- Security Posture Grade: ${reportData.riskScore.grade} (${reportData.riskScore.securityPosture}/100)
- Confirmed Exposures: ${reportData.executiveSummary.totalConfirmedFindings}

Executive Summary:
${reportData.executiveSummary.summaryText}

Please find the complete, publication-ready PDF report attached to this email.

Best regards,
${reportData.branding.brandName} Security Automation`;

    const htmlBody = `<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #0f172a; line-height: 1.5; padding: 20px;">
  <div style="max-width: 600px; margin: 0 auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 24px;">
    <h2 style="margin-top: 0; color: #0f172a;">${reportData.branding.brandName}</h2>
    <p style="font-size: 14px; color: #64748b;">Monthly Executive Security Risk Assessment • <strong>${reportData.organization.name}</strong></p>
    
    <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 16px; margin: 20px 0;">
      <p style="margin: 0 0 8px 0; font-size: 13px;"><strong>Risk Score:</strong> ${reportData.riskScore.score}/100</p>
      <p style="margin: 0 0 8px 0; font-size: 13px;"><strong>Posture Grade:</strong> Grade ${reportData.riskScore.grade}</p>
      <p style="margin: 0; font-size: 13px;"><strong>Confirmed Exposures:</strong> ${reportData.executiveSummary.totalConfirmedFindings}</p>
    </div>

    <h3 style="font-size: 14px; color: #334155;">Leadership Summary</h3>
    <p style="font-size: 13px; color: #475569;">${reportData.executiveSummary.summaryText}</p>

    <div style="margin-top: 24px; padding-top: 16px; border-top: 1px solid #e2e8f0; font-size: 12px; color: #64748b;">
      📎 Your complete executive assessment is attached as <strong>${filename}</strong> (${Math.round(pdfBuffer.length / 1024)} KB).
    </div>
  </div>
</body>
</html>`;

    // 6. Deliver via Existing Email Provider
    const emailResult = await getEmailProvider().send({
      to: recipients,
      subject,
      text: textBody,
      html: htmlBody,
      attachments: [
        {
          filename,
          content: pdfBuffer,
          contentType: 'application/pdf',
        },
      ],
    });

    if (!emailResult.success) {
      throw new Error(emailResult.error || 'Failed to dispatch email with report attachment');
    }

    // 7. Update lastSentAt
    if (org.scheduledReports) {
      org.scheduledReports.lastSentAt = new Date();
    } else {
      org.scheduledReports = { enabled: true, frequency: 'MONTHLY', lastSentAt: new Date() };
    }

    if (isMongoActive()) {
      await org.save();
    } else {
      memoryStore.organizations.set(orgIdStr, org);
    }

    // 8. Record Audit Log (§5)
    const auditEntry = {
      organizationId: org._id || org.id,
      actorId: 'system:scheduler',
      action: 'REPORT_GENERATED',
      objectType: 'Organization',
      objectId: (org._id || org.id).toString(),
      result: 'SUCCESS' as const,
      details: {
        reportType: 'EXECUTIVE_SUMMARY',
        format: 'PDF',
        trigger: 'SCHEDULED',
        recipients,
        whiteLabel: reportData.branding.isWhiteLabel,
        riskScore: reportData.riskScore.score,
        grade: reportData.riskScore.grade,
      },
    };

    if (isMongoActive()) {
      await AuditLog.create(auditEntry);
    } else {
      memoryStore.auditLogs.push({
        ...auditEntry,
        createdAt: new Date(),
      });
    }

    return {
      organizationId: orgIdStr,
      triggered: true,
      success: true,
      recipients,
    };
  } catch (err: any) {
    return {
      organizationId: orgIdStr,
      triggered: true,
      success: false,
      recipients,
      error: err.message,
    };
  }
}

/**
 * Batch processor to dispatch scheduled monthly reports across all opt-in organizations.
 */
export async function processAllScheduledReports(): Promise<ScheduledReportDispatchResult[]> {
  let eligibleOrgs: any[] = [];

  if (isMongoActive()) {
    eligibleOrgs = await Organization.find({
      'scheduledReports.enabled': true,
    });
  } else {
    eligibleOrgs = Array.from(memoryStore.organizations.values()).filter(
      (o) => o.scheduledReports?.enabled === true
    );
  }

  const results: ScheduledReportDispatchResult[] = [];
  for (const org of eligibleOrgs) {
    const res = await sendMonthlyScheduledReport(org._id || org.id);
    results.push(res);
  }

  return results;
}
