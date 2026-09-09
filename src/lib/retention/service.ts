import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { Evidence } from '@/models/Evidence';
import { Asset } from '@/models/Asset';
import { Scan } from '@/models/Scan';
import { Alert } from '@/models/Alert';
import { Organization } from '@/models/Organization';
import { AuditLog } from '@/models/AuditLog';
import { env } from '@/lib/env';
import { logger } from '@/lib/observability/logger';

export interface RetentionCleanupSummary {
  timestamp: string;
  evidencePruned: number;
  evidenceCutoff: string;
  cancelledOrgsPruned: number;
  assetsDeleted: number;
}

export class RetentionService {
  private evidenceRetentionDays: number;
  private cancelledOrgRetentionDays: number;

  constructor(evidenceRetentionDays?: number, cancelledOrgRetentionDays?: number) {
    this.evidenceRetentionDays = evidenceRetentionDays || env.EVIDENCE_RETENTION_DAYS || 90;
    this.cancelledOrgRetentionDays = cancelledOrgRetentionDays || env.CANCELLED_ORG_RETENTION_DAYS || 30;
  }

  /**
   * Prunes raw observation Evidence records older than the configured retention period (default: 90 days).
   * Minimizes database storage costs while preserving findings, scores, and audit provenance.
   */
  async pruneExpiredEvidence(days?: number): Promise<{ prunedCount: number; cutoffDate: Date }> {
    const retentionDays = days ?? this.evidenceRetentionDays;
    const cutoffDate = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);
    let prunedCount = 0;

    if (isMongoActive()) {
      const res = await Evidence.deleteMany({
        $or: [
          { observedAt: { $lt: cutoffDate } },
          { createdAt: { $lt: cutoffDate } },
        ],
      });
      prunedCount = res.deletedCount || 0;
    } else {
      for (const [id, ev] of Array.from(memoryStore.evidence.entries())) {
        const obsDate = ev.observedAt || ev.createdAt;
        if (obsDate && new Date(obsDate) < cutoffDate) {
          memoryStore.evidence.delete(id);
          prunedCount++;
        }
      }
    }

    logger.info(`[RetentionService] Pruned ${prunedCount} expired evidence records older than ${retentionDays} days.`, {
      prunedCount,
      cutoffDate: cutoffDate.toISOString(),
    });

    return { prunedCount, cutoffDate };
  }

  /**
   * Cleans up assets, scans, and alerts for cancelled organizations whose post-cancellation grace period
   * has expired (default: 30 days post-cancellation).
   */
  async pruneCancelledTenantData(days?: number): Promise<{ prunedOrgs: string[]; assetsDeleted: number }> {
    const graceDays = days ?? this.cancelledOrgRetentionDays;
    const cutoffDate = new Date(Date.now() - graceDays * 24 * 60 * 60 * 1000);
    const prunedOrgs: string[] = [];
    let assetsDeleted = 0;

    if (isMongoActive()) {
      const candidateOrgs = await Organization.find({
        subscriptionStatus: 'CANCELED',
        currentPeriodEnd: { $lt: cutoffDate },
      });

      for (const org of candidateOrgs) {
        const orgId = org._id;
        const assetRes = await Asset.deleteMany({ organizationId: orgId });
        await Scan.deleteMany({ organizationId: orgId });
        await Alert.deleteMany({ organizationId: orgId });
        assetsDeleted += assetRes.deletedCount || 0;
        prunedOrgs.push(orgId.toString());

        await AuditLog.create({
          organizationId: orgId,
          actorId: 'system:retention_service',
          action: 'CANCELLED_TENANT_DATA_PRUNED',
          objectType: 'Organization',
          objectId: orgId.toString(),
          result: 'SUCCESS',
          details: { assetsDeleted: assetRes.deletedCount, cutoffDate: cutoffDate.toISOString() },
        });
      }
    } else {
      for (const [orgId, org] of Array.from(memoryStore.organizations.entries())) {
        if (org.subscriptionStatus === 'CANCELED' && org.currentPeriodEnd && new Date(org.currentPeriodEnd) < cutoffDate) {
          // Delete assets
          for (const [assetId, asset] of Array.from(memoryStore.assets.entries())) {
            if (asset.organizationId?.toString() === orgId.toString()) {
              memoryStore.assets.delete(assetId);
              assetsDeleted++;
            }
          }
          // Delete scans
          for (const [scanId, scan] of Array.from(memoryStore.scans.entries())) {
            if (scan.organizationId?.toString() === orgId.toString()) {
              memoryStore.scans.delete(scanId);
            }
          }
          // Delete alerts
          for (const [alertId, alert] of Array.from(memoryStore.alerts.entries())) {
            if (alert.organizationId?.toString() === orgId.toString()) {
              memoryStore.alerts.delete(alertId);
            }
          }

          prunedOrgs.push(orgId);
          memoryStore.auditLogs.push({
            organizationId: orgId,
            actorId: 'system:retention_service',
            action: 'CANCELLED_TENANT_DATA_PRUNED',
            objectType: 'Organization',
            objectId: orgId,
            result: 'SUCCESS',
            details: { assetsDeleted, cutoffDate: cutoffDate.toISOString() },
            createdAt: new Date(),
          });
        }
      }
    }

    return { prunedOrgs, assetsDeleted };
  }

  /**
   * Executes full retention cycle and records audit log.
   */
  async runRetentionCleanup(): Promise<RetentionCleanupSummary> {
    const evidenceRes = await this.pruneExpiredEvidence();
    const tenantRes = await this.pruneCancelledTenantData();

    const summary: RetentionCleanupSummary = {
      timestamp: new Date().toISOString(),
      evidencePruned: evidenceRes.prunedCount,
      evidenceCutoff: evidenceRes.cutoffDate.toISOString(),
      cancelledOrgsPruned: tenantRes.prunedOrgs.length,
      assetsDeleted: tenantRes.assetsDeleted,
    };

    logger.info('[RetentionService] Full retention cycle completed.', summary);
    return summary;
  }
}

export const retentionService = new RetentionService();
