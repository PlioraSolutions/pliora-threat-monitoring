import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { Threat } from '@/models/Threat';
import { Evidence } from '@/models/Evidence';
import { AuditLog } from '@/models/AuditLog';
import { ThreatStatus } from '@/types';

interface RouteContext {
  params: Promise<{ id: string }>;
}

const ALLOWED_THREAT_TRANSITIONS: Record<ThreatStatus, ThreatStatus[]> = {
  OPEN: ['MONITORING', 'ACCEPTED_RISK', 'RESOLVED'],
  MONITORING: ['OPEN', 'ACCEPTED_RISK', 'RESOLVED'],
  ACCEPTED_RISK: ['OPEN', 'RESOLVED'],
  RESOLVED: ['OPEN'],
};

export async function GET(request: NextRequest, context: RouteContext) {
  try {
    const { organization: org } = await requireAuth(request);
    const { id } = await context.params;

    let threat: any = null;
    let evidence: any = null;

    if (isMongoActive()) {
      threat = await Threat.findOne({ _id: id, organizationId: org._id }).lean();
      if (!threat) {
        // Return 404 (not 403) to prevent ID enumeration across tenants
        return NextResponse.json(
          { success: false, error: { code: 'NOT_FOUND', message: 'Threat not found.' } },
          { status: 404 }
        );
      }

      if (threat.evidenceId) {
        evidence = await Evidence.findOne({
          _id: threat.evidenceId,
          organizationId: org._id,
        }).lean();
      }
    } else {
      const orgIdStr = org._id?.toString();
      const allThreats = Array.from(memoryStore.threats.values());
      threat = allThreats.find(
        (t) =>
          (t._id?.toString() === id || t.id === id) &&
          t.organizationId?.toString() === orgIdStr
      );

      if (!threat) {
        return NextResponse.json(
          { success: false, error: { code: 'NOT_FOUND', message: 'Threat not found.' } },
          { status: 404 }
        );
      }

      if (threat.evidenceId) {
        const allEvidence = Array.from(memoryStore.evidence.values());
        evidence = allEvidence.find(
          (e) =>
            (e._id?.toString() === threat.evidenceId.toString() ||
              e.contentHash === threat.evidenceId.toString()) &&
            e.organizationId?.toString() === orgIdStr
        );
      }
    }

    return NextResponse.json({
      success: true,
      data: {
        ...threat,
        evidence: evidence
          ? {
              checkType: evidence.checkType,
              rawObservation: evidence.rawObservation,
              contentHash: evidence.contentHash,
              observedAt: evidence.observedAt || evidence.createdAt,
            }
          : null,
      },
    });
  } catch (error: any) {
    const status = error.status || 500;
    return NextResponse.json(
      { success: false, error: { code: error.status === 401 ? 'UNAUTHORIZED' : 'THREAT_FETCH_ERROR', message: error.message } },
      { status }
    );
  }
}

export async function PATCH(request: NextRequest, context: RouteContext) {
  try {
    const { user, organization: org } = await requireAuth(request);
    const { id } = await context.params;

    // 1. Role Authorization Check: VIEWER cannot mutate
    const membership = user.organizationMemberships?.find(
      (m: any) => m.organizationId?.toString() === org._id?.toString()
    );
    const role = membership?.role || 'VIEWER';

    if (role === 'VIEWER') {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'INSUFFICIENT_PERMISSIONS',
            message: 'Viewer role has read-only access and cannot modify threat triage status.',
          },
        },
        { status: 403 }
      );
    }

    const body = await request.json();
    const newStatus: ThreatStatus = body.status;
    const notes: string | undefined = body.notes;

    if (!newStatus || !['OPEN', 'MONITORING', 'ACCEPTED_RISK', 'RESOLVED'].includes(newStatus)) {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'INVALID_STATUS',
            message: 'Target status must be one of OPEN, MONITORING, ACCEPTED_RISK, RESOLVED.',
          },
        },
        { status: 400 }
      );
    }

    let threat: any = null;

    if (isMongoActive()) {
      threat = await Threat.findOne({ _id: id, organizationId: org._id });
      if (!threat) {
        return NextResponse.json(
          { success: false, error: { code: 'NOT_FOUND', message: 'Threat not found.' } },
          { status: 404 }
        );
      }
    } else {
      const orgIdStr = org._id?.toString();
      const allThreats = Array.from(memoryStore.threats.values());
      threat = allThreats.find(
        (t) =>
          (t._id?.toString() === id || t.id === id) &&
          t.organizationId?.toString() === orgIdStr
      );
      if (!threat) {
        return NextResponse.json(
          { success: false, error: { code: 'NOT_FOUND', message: 'Threat not found.' } },
          { status: 404 }
        );
      }
    }

    const currentStatus: ThreatStatus = threat.status;

    // No-op if status is unchanged
    if (currentStatus === newStatus) {
      return NextResponse.json({ success: true, data: threat });
    }

    // 2. State Machine Validation
    const allowedTargets = ALLOWED_THREAT_TRANSITIONS[currentStatus] || [];
    if (!allowedTargets.includes(newStatus)) {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'INVALID_STATUS_TRANSITION',
            message: `Cannot transition threat status from "${currentStatus}" to "${newStatus}". Allowed targets: ${allowedTargets.join(', ')}.`,
          },
        },
        { status: 400 }
      );
    }

    // 3. Mutate and Persist
    threat.status = newStatus;
    threat.updatedAt = new Date();

    if (isMongoActive()) {
      await threat.save();

      await AuditLog.create({
        organizationId: org._id,
        actorId: user._id,
        action: 'THREAT_STATUS_UPDATED',
        objectType: 'Threat',
        objectId: threat._id.toString(),
        result: 'SUCCESS',
        details: {
          indicator: threat.indicator,
          fromStatus: currentStatus,
          toStatus: newStatus,
          notes,
        },
      });
    } else {
      const storeKey = `${org._id}:${threat.dedupKey}`;
      memoryStore.threats.set(storeKey, threat);

      memoryStore.auditLogs.push({
        organizationId: org._id,
        actorId: user._id,
        action: 'THREAT_STATUS_UPDATED',
        objectType: 'Threat',
        objectId: threat._id || threat.id,
        result: 'SUCCESS',
        details: {
          indicator: threat.indicator,
          fromStatus: currentStatus,
          toStatus: newStatus,
          notes,
        },
        createdAt: new Date(),
      });
    }

    return NextResponse.json({
      success: true,
      data: threat,
      meta: {
        previousStatus: currentStatus,
        newStatus,
      },
    });
  } catch (error: any) {
    const status = error.status || 500;
    return NextResponse.json(
      { success: false, error: { code: 'THREAT_UPDATE_ERROR', message: error.message } },
      { status }
    );
  }
}
