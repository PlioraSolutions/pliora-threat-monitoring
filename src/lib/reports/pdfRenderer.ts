import PDFDocument from 'pdfkit';
import { AssembledReportData } from './reportData';

/**
 * Server-Side PDF Renderer (§2 & §3):
 * Generates an executive security risk report PDF matching dashboard hierarchy and styling.
 * Supports default PLIŌRA branding or customer/agency white-label customization.
 * 
 * INVARIANT: Zero raw technical evidence or password exposures. Clean, executive-ready formatting.
 */
function sanitizeForPdf(text: string): string {
  if (!text) return '';
  return text
    .replace(/Ō/g, 'O')
    .replace(/ō/g, 'o')
    .replace(/—/g, ' - ')
    .replace(/–/g, '-')
    .replace(/“/g, '"')
    .replace(/”/g, '"')
    .replace(/‘/g, "'")
    .replace(/’/g, "'");
}

export async function renderReportPdf(data: AssembledReportData): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    try {
      const sanitizedBrand = sanitizeForPdf(data.branding.brandName);
      const sanitizedOrgName = sanitizeForPdf(data.organization.name);
      const sanitizedFooter = sanitizeForPdf(data.branding.footerText);

      const doc = new PDFDocument({
        size: 'LETTER',
        margins: { top: 45, bottom: 55, left: 45, right: 45 },
        bufferPages: true,
        info: {
          Title: `Executive Security Report - ${sanitizedOrgName}`,
          Author: sanitizedBrand,
          Subject: 'External Attack Surface & Threat Monitoring Assessment',
          CreationDate: new Date(data.metadata.generatedAt),
        },
      });

      const chunks: Buffer[] = [];
      doc.on('data', (chunk) => chunks.push(chunk));
      doc.on('end', () => resolve(Buffer.concat(chunks)));
      doc.on('error', (err) => reject(err));

      const pageWidth = 612;
      const margin = 45;
      const contentWidth = pageWidth - margin * 2; // 522 pt

      // =======================================================================
      // 1. Header & Title Block
      // =======================================================================
      doc.font('Helvetica-Bold').fontSize(18).fillColor('#0f172a');
      doc.text(sanitizedBrand, margin, 45);

      doc.font('Helvetica').fontSize(9).fillColor('#64748b');
      doc.text(sanitizeForPdf(data.metadata.reportingPeriod), margin, 48, { align: 'right', width: contentWidth });

      doc.font('Helvetica-Bold').fontSize(12).fillColor('#334155');
      doc.text(`Executive Security Risk Assessment`, margin, 70);

      doc.font('Helvetica').fontSize(10).fillColor('#64748b');
      doc.text(`Target Organization: `, margin, 87, { continued: true });
      doc.font('Helvetica-Bold').fillColor('#0f172a').text(data.organization.name);

      // Divider line
      doc.strokeColor('#e2e8f0').lineWidth(1.5).moveTo(margin, 105).lineTo(pageWidth - margin, 105).stroke();

      // =======================================================================
      // 2. Executive Metric Hero (Score Box)
      // =======================================================================
      const heroY = 118;
      const heroHeight = 72;

      // Box background
      doc.roundedRect(margin, heroY, contentWidth, heroHeight, 8).fillAndStroke('#f8fafc', '#e2e8f0');

      const colWidth = contentWidth / 3;

      // Col 1: Risk Score
      const scoreColor = data.riskScore.score > 60 ? '#dc2626' : data.riskScore.score > 30 ? '#d97706' : '#16a34a';
      doc.font('Helvetica-Bold').fontSize(22).fillColor(scoreColor);
      doc.text(`${data.riskScore.score}`, margin, heroY + 14, { width: colWidth, align: 'center', continued: true });
      doc.font('Helvetica').fontSize(11).fillColor('#64748b').text(' / 100');

      doc.font('Helvetica-Bold').fontSize(8).fillColor('#64748b');
      doc.text('EXTERNAL RISK SCORE', margin, heroY + 44, { width: colWidth, align: 'center' });

      // Col 2: Posture Grade
      const gradeColor =
        data.riskScore.grade === 'A' ? '#16a34a' :
        data.riskScore.grade === 'B' ? '#0284c7' :
        data.riskScore.grade === 'C' ? '#d97706' : '#dc2626';

      doc.font('Helvetica-Bold').fontSize(22).fillColor(gradeColor);
      doc.text(`Grade ${data.riskScore.grade}`, margin + colWidth, heroY + 14, { width: colWidth, align: 'center' });

      doc.font('Helvetica-Bold').fontSize(8).fillColor('#64748b');
      doc.text(`SECURITY POSTURE (${data.riskScore.securityPosture}/100)`, margin + colWidth, heroY + 44, {
        width: colWidth,
        align: 'center',
      });

      // Col 3: Confirmed Exposures
      doc.font('Helvetica-Bold').fontSize(22).fillColor('#0f172a');
      doc.text(`${data.executiveSummary.totalConfirmedFindings}`, margin + colWidth * 2, heroY + 14, {
        width: colWidth,
        align: 'center',
      });

      doc.font('Helvetica-Bold').fontSize(8).fillColor('#64748b');
      doc.text('CONFIRMED EXPOSURES', margin + colWidth * 2, heroY + 44, { width: colWidth, align: 'center' });

      // =======================================================================
      // 3. Section 1: Executive Leadership Summary
      // =======================================================================
      let currentY = heroY + heroHeight + 20;

      doc.font('Helvetica-Bold').fontSize(12).fillColor('#0f172a');
      doc.text('1. Executive Leadership Summary', margin, currentY);
      currentY += 18;

      doc.font('Helvetica').fontSize(9.5).fillColor('#334155').lineGap(3);
      doc.text(data.executiveSummary.summaryText, margin, currentY, { width: contentWidth });
      currentY = doc.y + 10;

      if (data.executiveSummary.overallPosture) {
        doc.font('Helvetica-Bold').fontSize(9).fillColor('#475569');
        doc.text('Posture Assessment: ', margin, currentY, { continued: true });
        doc.font('Helvetica').fillColor('#334155').text(data.executiveSummary.overallPosture);
        currentY = doc.y + 16;
      }

      // =======================================================================
      // 4. Section 2: Security Posture Drift & Trend
      // =======================================================================
      doc.font('Helvetica-Bold').fontSize(12).fillColor('#0f172a');
      doc.text('2. Security Posture Drift & Historical Trend', margin, currentY);
      currentY += 18;

      const trendLabel =
        data.trend.trendDirection === 'IMPROVING' ? '▲ IMPROVING (Risk decreased over period)' :
        data.trend.trendDirection === 'DEGRADING' ? '▼ DEGRADING (Exposure increased over period)' :
        '■ STABLE (Consistent risk profile)';

      doc.font('Helvetica-Bold').fontSize(9).fillColor('#475569');
      doc.text(`Trajectory: `, margin, currentY, { continued: true });
      doc.font('Helvetica-Bold').fillColor(
        data.trend.trendDirection === 'IMPROVING' ? '#16a34a' :
        data.trend.trendDirection === 'DEGRADING' ? '#dc2626' : '#64748b'
      ).text(trendLabel);
      currentY = doc.y + 6;

      if (data.trend.history && data.trend.history.length > 0) {
        doc.font('Helvetica').fontSize(8.5).fillColor('#64748b');
        const snapshotsText = data.trend.history
          .slice(-6)
          .map((pt) => `${pt.date}: ${pt.score} (${pt.grade})`)
          .join('   →   ');
        doc.text(`Recent Snapshots: ${snapshotsText}`, margin, currentY, { width: contentWidth });
        currentY = doc.y + 16;
      } else {
        doc.font('Helvetica-Oblique').fontSize(8.5).fillColor('#94a3b8');
        doc.text('Baseline evaluation established. Subsequent automated cycles will track score drift.', margin, currentY);
        currentY = doc.y + 16;
      }

      // =======================================================================
      // 5. Section 3: Priority Action Checklist
      // =======================================================================
      doc.font('Helvetica-Bold').fontSize(12).fillColor('#0f172a');
      doc.text('3. Priority Action Checklist', margin, currentY);
      currentY += 18;

      if (data.executiveSummary.priorityActions && data.executiveSummary.priorityActions.length > 0) {
        for (const action of data.executiveSummary.priorityActions.slice(0, 4)) {
          doc.font('Helvetica-Bold').fontSize(9).fillColor('#0284c7');
          doc.text('• ', margin, currentY, { continued: true });
          doc.font('Helvetica').fontSize(9).fillColor('#1e293b').lineGap(2);
          doc.text(action, { width: contentWidth - 15 });
          currentY = doc.y + 4;
        }
      } else {
        doc.font('Helvetica').fontSize(9).fillColor('#64748b');
        doc.text('No immediate urgent remediation actions identified.', margin, currentY);
        currentY = doc.y + 6;
      }

      currentY += 12;

      // =======================================================================
      // Check page height before section 4 (Add page if needed)
      // =======================================================================
      if (currentY > 580) {
        doc.addPage();
        currentY = 45;
      }

      // =======================================================================
      // 6. Section 4: Top Prioritized Exposures
      // =======================================================================
      doc.font('Helvetica-Bold').fontSize(12).fillColor('#0f172a');
      doc.text('4. Top Prioritized Exposures', margin, currentY);
      currentY += 18;

      if (data.topFindings.length === 0) {
        doc.font('Helvetica').fontSize(9).fillColor('#64748b');
        doc.text('Zero open security findings detected across monitored perimeter.', margin, currentY);
        currentY = doc.y + 14;
      } else {
        // Table Header
        const colX = {
          asset: margin,
          sev: margin + 140,
          conf: margin + 205,
          title: margin + 275,
          score: margin + 480,
        };

        doc.rect(margin, currentY, contentWidth, 18).fill('#f1f5f9');
        doc.font('Helvetica-Bold').fontSize(7.5).fillColor('#475569');
        doc.text('ASSET / ENDPOINT', colX.asset + 4, currentY + 5);
        doc.text('SEVERITY', colX.sev, currentY + 5);
        doc.text('CONFIDENCE', colX.conf, currentY + 5);
        doc.text('FINDING CODE & TITLE', colX.title, currentY + 5);
        doc.text('SCORE', colX.score, currentY + 5, { width: 35, align: 'right' });
        currentY += 20;

        for (const finding of data.topFindings) {
          // Check if row fits on current page
          if (currentY > 700) {
            doc.addPage();
            currentY = 45;
          }

          const sevColor =
            finding.severity === 'CRITICAL' ? '#dc2626' :
            finding.severity === 'HIGH' ? '#ea580c' :
            finding.severity === 'MEDIUM' ? '#d97706' : '#2563eb';

          // Asset FQDN
          doc.font('Helvetica').fontSize(8).fillColor('#1e293b');
          const truncatedAsset = finding.assetFqdn.length > 26 ? finding.assetFqdn.substring(0, 24) + '…' : finding.assetFqdn;
          doc.text(truncatedAsset, colX.asset + 4, currentY);

          // Severity
          doc.font('Helvetica-Bold').fontSize(7.5).fillColor(sevColor);
          doc.text(finding.severity, colX.sev, currentY);

          // Confidence
          doc.font('Helvetica').fontSize(7.5).fillColor('#64748b');
          doc.text(finding.confidence, colX.conf, currentY);

          // Title
          doc.font('Helvetica-Bold').fontSize(8).fillColor('#0f172a');
          const truncatedTitle = finding.title.length > 42 ? finding.title.substring(0, 40) + '…' : finding.title;
          doc.text(truncatedTitle, colX.title, currentY);

          // Risk Score
          doc.font('Helvetica-Bold').fontSize(8).fillColor(sevColor);
          doc.text(`${finding.riskScore}`, colX.score, currentY, { width: 35, align: 'right' });

          currentY += 12;

          // Plain-language summary snippet
          if (finding.summary) {
            doc.font('Helvetica').fontSize(7.5).fillColor('#475569').lineGap(1);
            const truncatedSummary = finding.summary.length > 115 ? finding.summary.substring(0, 112) + '…' : finding.summary;
            doc.text(truncatedSummary, colX.asset + 4, currentY, { width: contentWidth - 8 });
            currentY = doc.y + 4;
          }

          // Subtle row line
          doc.strokeColor('#e2e8f0').lineWidth(0.5).moveTo(margin, currentY).lineTo(pageWidth - margin, currentY).stroke();
          currentY += 6;
        }
      }

      currentY += 10;

      // =======================================================================
      // 7. Section 5: Assessment Scope
      // =======================================================================
      if (currentY > 660) {
        doc.addPage();
        currentY = 45;
      }

      doc.font('Helvetica-Bold').fontSize(12).fillColor('#0f172a');
      doc.text('5. Scope of Monitored Assets', margin, currentY);
      currentY += 16;

      doc.font('Helvetica').fontSize(8.5).fillColor('#475569');
      doc.text(`This evaluation covers ${data.scope.totalAssets} monitored attack surface asset${data.scope.totalAssets === 1 ? '' : 's'}:`, margin, currentY);
      currentY = doc.y + 4;

      const assetListText = data.scope.assets.map((a) => a.fqdn).slice(0, 12).join(', ');
      const overflowCount = Math.max(0, data.scope.assets.length - 12);
      doc.font('Helvetica-Oblique').fontSize(8).fillColor('#64748b');
      doc.text(`${assetListText}${overflowCount > 0 ? ` (+${overflowCount} additional assets)` : ''}`, margin, currentY, {
        width: contentWidth,
      });

      // =======================================================================
      // 8. Dynamic Page Footers & Numbers (Buffer Pass)
      // =======================================================================
      const range = doc.bufferedPageRange();
      for (let i = range.start; i < range.start + range.count; i++) {
        doc.switchToPage(i);

        // Footer divider line
        doc.strokeColor('#e2e8f0').lineWidth(0.5).moveTo(margin, 742).lineTo(pageWidth - margin, 742).stroke();

        doc.font('Helvetica').fontSize(7.5).fillColor('#94a3b8');
        doc.text(
          `${sanitizedFooter}   •   Page ${i + 1} of ${range.count}`,
          margin,
          748,
          { align: 'center', width: contentWidth }
        );
      }

      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}
