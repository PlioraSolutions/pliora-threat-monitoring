import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { Finding } from '@/models/Finding';
import { Evidence } from '@/models/Evidence';
import { AuditLog } from '@/models/AuditLog';
import { CalibrationFeedback } from '@/models/CalibrationFeedback';
import { computeOrgRiskScore, recordRiskScoreSnapshot } from '@/lib/risk/orgScore';
import { FindingStatus } from '@/types';

interface RouteContext {
  params: Promise<{ id: string }>;
}

const ALLOWED_TRANSITIONS: Record<FindingStatus, FindingStatus[]> = {
  OPEN: ['ACCEPTED_RISK', 'RESOLVED', 'FALSE_POSITIVE'],
  ACCEPTED_RISK: ['OPEN', 'RESOLVED'],
  RESOLVED: ['OPEN'],
  FALSE_POSITIVE: ['OPEN'],
};

export async function GET(request: NextRequest, context: RouteContext) {
  try {
    const { organization: org } = await requireAuth(request);
    const { id } = await context.params;

    let finding: any = null;
    let evidence: any = null;

    if (isMongoActive()) {
      finding = await Finding.findOne({ _id: id, organizationId: org._id }).lean();
      if (!finding) {
        // Return 404 (not 403) to prevent ID leaking across tenants
        return NextResponse.json(
          { success: false, error: { code: 'NOT_FOUND', message: 'Finding not found.' } },
          { status: 404 }
        );
      }

      if (finding.evidenceId) {
        evidence = await Evidence.findOne({
          _id: finding.evidenceId,
          organizationId: org._id,
        }).lean();
      }
    } else {
      // Find in memory store
      const allFindings = Array.from(memoryStore.findings.values());
      finding = allFindings.find(
        (f) =>
          (f._id?.toString() === id || f.id === id) &&
          f.organizationId?.toString() === org._id.toString()
      );

      if (!finding) {
        return NextResponse.json(
          { success: false, error: { code: 'NOT_FOUND', message: 'Finding not found.' } },
          { status: 404 }
        );
      }

      if (finding.evidenceId) {
        const allEvidence = Array.from(memoryStore.evidence.values());
        evidence = allEvidence.find(
          (e) =>
            (e._id?.toString() === finding.evidenceId.toString() ||
              e.scanId?.toString() === finding.evidenceId.toString()) &&
            e.organizationId?.toString() === org._id.toString()
        );
      }
    }

    return NextResponse.json({
      success: true,
      data: {
        ...finding,
        evidence: evidence ? {
          checkType: evidence.checkType,
          rawObservation: evidence.rawObservation,
          contentHash: evidence.contentHash,
          observedAt: evidence.observedAt || evidence.createdAt,
        } : null,
      },
    });
  } catch (error: any) {
    const status = error.status || 500;
    return NextResponse.json(
      { success: false, error: { code: error.status === 401 ? 'UNAUTHORIZED' : 'FINDING_FETCH_ERROR', message: error.message } },
      { status }
    );
  }
}

export async function PATCH(request: NextRequest, context: RouteContext) {
  try {
    const { user, organization: org } = await requireAuth(request);
    const { id } = await context.params;

    // 1. Role Authorization Check
    const membership = user.organizationMemberships?.find(
      (m: any) => m.organizationId?.toString() === org._id?.toString()
    );
    const role = membership?.role || 'VIEWER';

    if (role === 'VIEWER' || user.isAgencyDelegate) {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'INSUFFICIENT_PERMISSIONS',
            message: 'Viewer or agency delegate role has read-only access and cannot modify finding triage status.',
          },
        },
        { status: 403 }
      );
    }

    const body = await request.json();
    const newStatus: FindingStatus = body.status;
    const notes: string | undefined = body.notes;
    const reason: string | undefined = body.reason;

    if (!newStatus || !['OPEN', 'ACCEPTED_RISK', 'RESOLVED', 'FALSE_POSITIVE'].includes(newStatus)) {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'INVALID_STATUS',
            message: 'Target status must be one of OPEN, ACCEPTED_RISK, RESOLVED, FALSE_POSITIVE.',
          },
        },
        { status: 400 }
      );
    }

    let finding: any = null;

    if (isMongoActive()) {
      finding = await Finding.findOne({ _id: id, organizationId: org._id });
      if (!finding) {
        return NextResponse.json(
          { success: false, error: { code: 'NOT_FOUND', message: 'Finding not found.' } },
          { status: 404 }
        );
      }
    } else {
      const allFindings = Array.from(memoryStore.findings.values());
      finding = allFindings.find(
        (f) =>
          (f._id?.toString() === id || f.id === id) &&
          f.organizationId?.toString() === org._id.toString()
      );
      if (!finding) {
        return NextResponse.json(
          { success: false, error: { code: 'NOT_FOUND', message: 'Finding not found.' } },
          { status: 404 }
        );
      }
    }

    const currentStatus: FindingStatus = finding.status;

    // No-op if status is unchanged
    if (currentStatus === newStatus) {
      return NextResponse.json({ success: true, data: finding });
    }

    // 2. State Machine Validation
    const allowedTargets = ALLOWED_TRANSITIONS[currentStatus] || [];
    if (!allowedTargets.includes(newStatus)) {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'INVALID_STATUS_TRANSITION',
            message: `Cannot transition finding status from "${currentStatus}" to "${newStatus}". Allowed targets: ${allowedTargets.join(', ')}.`,
          },
        },
        { status: 400 }
      );
    }

    // 3. Apply Transition & Audit
    finding.status = newStatus;
    finding.updatedAt = new Date();

    if (isMongoActive()) {
      await finding.save();

      await AuditLog.create({
        organizationId: org._id,
        actorId: user._id.toString(),
        action: 'FINDING_STATUS_CHANGED',
        objectType: 'Finding',
        objectId: finding._id.toString(),
        result: 'SUCCESS',
        details: {
          previousStatus: currentStatus,
          newStatus,
          findingCode: finding.findingCode,
          notes,
          reason,
        },
      });

      await CalibrationFeedback.create({
        organizationId: org._id,
        findingId: finding._id,
        findingCode: finding.findingCode,
        category: finding.category,
        severityAtTriage: finding.severity,
        confidenceAtTriage: finding.confidence,
        action: newStatus === 'OPEN' ? 'REOPENED' : newStatus,
        actorId: user._id.toString(),
        notes,
        reason,
      });
    } else {
      memoryStore.auditLogs.push({
        organizationId: org._id,
        actorId: user._id.toString(),
        action: 'FINDING_STATUS_CHANGED',
        objectType: 'Finding',
        objectId: finding._id?.toString() || id,
        result: 'SUCCESS',
        details: {
          previousStatus: currentStatus,
          newStatus,
          findingCode: finding.findingCode,
          notes,
          reason,
        },
        createdAt: new Date(),
      });

      memoryStore.calibrationFeedback.push({
        organizationId: org._id,
        findingId: finding._id || id,
        findingCode: finding.findingCode,
        category: finding.category,
        severityAtTriage: finding.severity,
        confidenceAtTriage: finding.confidence,
        action: newStatus === 'OPEN' ? 'REOPENED' : newStatus,
        actorId: user._id.toString(),
        notes,
        reason,
        createdAt: new Date(),
      });
    }

    // 4. Recompute Organization Risk Score & Save Snapshot
    const orgScore = await computeOrgRiskScore(org._id.toString());
    await recordRiskScoreSnapshot(
      org._id.toString(),
      orgScore,
      'FINDING_MUTATED'
    );

    return NextResponse.json({
      success: true,
      data: finding,
      orgRiskScore: {
        score: orgScore.score,
        securityPosture: orgScore.securityPosture,
        grade: orgScore.grade,
        factors: orgScore.factors,
      },
    });
  } catch (error: any) {
    const status = error.status || 500;
    const errorCode = error.status === 401 ? 'UNAUTHORIZED' : (error.status === 403 ? 'FORBIDDEN' : 'FINDING_UPDATE_ERROR');
    return NextResponse.json(
      { success: false, error: { code: errorCode, message: error.message } },
      { status }
    );
  }
}
