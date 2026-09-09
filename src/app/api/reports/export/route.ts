import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { assembleReportData } from '@/lib/reports/reportData';
import { renderReportPdf } from '@/lib/reports/pdfRenderer';

export async function GET(request: NextRequest) {
  try {
    const { user, organization: org } = await requireAuth(request);
    const { searchParams } = new URL(request.url);
    const format = searchParams.get('format') || 'html';

    // Assemble report data through the single source-of-truth engine (§1)
    const reportData = await assembleReportData(org._id, {
      actorId: (user._id || user.id)?.toString(),
      agencyOrgId: user.isAgencyDelegate ? user.agencyOrgId : undefined,
    });

    if (format === 'pdf') {
      const pdfBuffer = await renderReportPdf(reportData);
      const filename = `pliora-security-report-${reportData.organization.slug}-${new Date().toISOString().split('T')[0]}.pdf`;
      return new NextResponse(new Uint8Array(pdfBuffer), {
        status: 200,
        headers: {
          'Content-Type': 'application/pdf',
          'Content-Disposition': `attachment; filename="${filename}"`,
          'Content-Length': pdfBuffer.length.toString(),
        },
      });
    }

    if (format === 'json') {
      return NextResponse.json({
        success: true,
        data: {
          organization: reportData.organization.name,
          reportDate: reportData.metadata.reportDateFormatted,
          brandName: reportData.branding.brandName,
          riskScore: reportData.riskScore.score,
          securityPosture: reportData.riskScore.securityPosture,
          grade: reportData.riskScore.grade,
          executiveSummary: reportData.executiveSummary.summaryText,
          overallPosture: reportData.executiveSummary.overallPosture,
          keyRisks: reportData.executiveSummary.keyRisks,
          priorityActions: reportData.executiveSummary.priorityActions,
          activeFindings: reportData.topFindings,
        },
      });
    }

    // Generate print-ready HTML designed for direct browser print / PDF export
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Executive Security Report — ${org.name}</title>
  <style>
    @page { size: letter; margin: 20mm; }
    @media print {
      body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      .no-print { display: none; }
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      color: #0f172a;
      line-height: 1.5;
      margin: 0;
      padding: 24px;
      background: #ffffff;
    }
    .header {
      border-bottom: 2px solid #e2e8f0;
      padding-bottom: 16px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
    }
    .brand { font-size: 20px; font-weight: 800; color: #0f172a; letter-spacing: -0.5px; }
    .subtitle { font-size: 13px; color: #64748b; margin-top: 4px; }
    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 6px;
      font-weight: 700;
      font-size: 12px;
      text-transform: uppercase;
    }
    .badge-f { background: #fee2e2; color: #b91c1c; }
    .badge-a { background: #dcfce7; color: #15803d; }
    .badge-b { background: #e0f2fe; color: #0369a1; }
    .score-box {
      display: flex;
      gap: 16px;
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 10px;
      padding: 16px;
      margin-bottom: 24px;
    }
    .metric { flex: 1; text-align: center; }
    .metric-value { font-size: 28px; font-weight: 800; }
    .metric-label { font-size: 12px; color: #64748b; font-weight: 600; text-transform: uppercase; }
    h2 { font-size: 16px; font-weight: 700; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; margin-top: 24px; margin-bottom: 12px; }
    p { font-size: 14px; color: #334155; }
    ul { padding-left: 20px; margin: 8px 0; }
    li { font-size: 14px; margin-bottom: 6px; color: #334155; }
    .table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
    .table th { text-align: left; background: #f1f5f9; padding: 8px 12px; border-bottom: 1px solid #cbd5e1; }
    .table td { padding: 8px 12px; border-bottom: 1px solid #e2e8f0; }
    .footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #94a3b8; text-align: center; }
    .print-btn {
      background: #0f172a;
      color: #ffffff;
      padding: 8px 16px;
      border: none;
      border-radius: 6px;
      font-weight: 600;
      cursor: pointer;
    }
  </style>
</head>
<body>
  <div class="header">
    <div>
      <div class="brand">${reportData.branding.brandName}</div>
      <div class="subtitle">Executive Security Risk Assessment • Organization: <strong>${reportData.organization.name}</strong></div>
    </div>
    <div style="text-align: right;">
      <div style="font-size: 12px; color: #64748b;">Generated: ${reportData.metadata.reportDateFormatted}</div>
      <button class="no-print print-btn" onclick="window.print()" style="margin-top: 8px;">Export / Print PDF</button>
    </div>
  </div>

  <div class="score-box">
    <div class="metric">
      <div class="metric-value" style="color: ${reportData.riskScore.score > 60 ? '#dc2626' : reportData.riskScore.score > 30 ? '#d97706' : '#16a34a'};">
        ${reportData.riskScore.score} <span style="font-size: 16px; font-weight: normal;">/ 100</span>
      </div>
      <div class="metric-label">External Risk Score</div>
    </div>
    <div class="metric">
      <div class="metric-value">
        <span class="badge ${reportData.riskScore.grade === 'F' ? 'badge-f' : reportData.riskScore.grade === 'A' ? 'badge-a' : 'badge-b'}">
          Grade ${reportData.riskScore.grade}
        </span>
      </div>
      <div class="metric-label">Security Posture</div>
    </div>
    <div class="metric">
      <div class="metric-value" style="color: #0284c7;">${reportData.executiveSummary.totalConfirmedFindings}</div>
      <div class="metric-label">Confirmed Exposures</div>
    </div>
  </div>

  <h2>1. Executive Leadership Summary</h2>
  <p>${reportData.executiveSummary.summaryText}</p>

  <h2>2. Priority Action Checklist</h2>
  <ul>
    ${reportData.executiveSummary.priorityActions.map((action: any) => `<li><strong>•</strong> ${typeof action === 'string' ? action : action.title || JSON.stringify(action)}</li>`).join('')}
  </ul>

  <h2>3. Top Prioritized Exposures</h2>
  ${reportData.topFindings.length === 0 ? '<p>No active Critical or High severity exposures detected.</p>' : `
  <table class="table">
    <thead>
      <tr>
        <th>Asset / Endpoint</th>
        <th>Severity</th>
        <th>Confidence</th>
        <th>Finding Title</th>
      </tr>
    </thead>
    <tbody>
      ${reportData.topFindings.map((f: any) => `
      <tr>
        <td><code>${f.assetFqdn || reportData.organization.name}</code></td>
        <td><strong>${f.severity}</strong></td>
        <td>${f.confidence}</td>
        <td>${f.title}</td>
      </tr>`).join('')}
    </tbody>
  </table>
  `}

  <div class="footer">
    ${reportData.branding.footerText}
  </div>
</body>
</html>`;

    return new NextResponse(html, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
      },
    });
  } catch (error: any) {
    const status = error.status || 500;
    return NextResponse.json(
      { success: false, error: { code: 'REPORT_EXPORT_ERROR', message: error.message } },
      { status }
    );
  }
}
