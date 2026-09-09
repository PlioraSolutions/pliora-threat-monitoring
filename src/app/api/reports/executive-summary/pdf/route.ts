import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { AuditLog } from '@/models/AuditLog';
import { assembleReportData } from '@/lib/reports/reportData';
import { renderReportPdf } from '@/lib/reports/pdfRenderer';

async function handlePdfExport(request: NextRequest) {
  try {
    const { user, organization: org } = await requireAuth(request, { allowDevDemoFallback: false });

    // 1. Pure Data Assembly (§1)
    const reportData = await assembleReportData(org._id, {
      actorId: (user._id || user.id)?.toString(),
    });

    // 2. Server-side PDF Rendering (§2 & §3)
    const pdfBuffer = await renderReportPdf(reportData);

    // 3. Record Audit Log (§5)
    const auditEntry = {
      organizationId: org._id,
      actorId: (user._id || user.id)?.toString() || 'system',
      action: 'REPORT_GENERATED',
      objectType: 'Organization',
      objectId: org._id?.toString(),
      result: 'SUCCESS',
      details: {
        reportType: 'EXECUTIVE_SUMMARY',
        format: 'PDF',
        trigger: 'ON_DEMAND',
        whiteLabel: reportData.branding.isWhiteLabel,
        actorEmail: user.email,
        reportDate: reportData.metadata.reportDateFormatted,
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

    const filename = `pliora-security-report-${reportData.organization.slug}-${new Date().toISOString().split('T')[0]}.pdf`;

    return new NextResponse(new Uint8Array(pdfBuffer), {
      status: 200,
      headers: {
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename="${filename}"`,
        'Content-Length': pdfBuffer.length.toString(),
      },
    });
  } catch (error: any) {
    const status = error.status || 500;
    return NextResponse.json(
      {
        success: false,
        error: {
          code: 'REPORT_PDF_EXPORT_ERROR',
          message: error.message || 'Failed to generate PDF report.',
        },
      },
      { status }
    );
  }
}

export async function GET(request: NextRequest) {
  return handlePdfExport(request);
}

export async function POST(request: NextRequest) {
  return handlePdfExport(request);
}
