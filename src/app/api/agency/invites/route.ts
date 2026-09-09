import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { Organization } from '@/models/Organization';
import { User } from '@/models/User';
import { AgencyClientLink } from '@/models/AgencyClientLink';
import { AuditLog } from '@/models/AuditLog';

export async function POST(request: NextRequest) {
  try {
    const { user, organization: agencyOrg } = await requireAuth(request);

    // 1. Verify agency account type (§2)
    if (agencyOrg.accountType !== 'AGENCY') {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'FORBIDDEN',
            message: 'Only organizations with accountType AGENCY can issue client invitations.',
          },
        },
        { status: 403 }
      );
    }

    // 2. Role check (OWNER or ADMIN)
    const membership = user.organizationMemberships?.find(
      (m: any) => m.organizationId?.toString() === agencyOrg._id?.toString()
    );
    const role = membership?.role || user.role || 'VIEWER';
    if (role !== 'OWNER' && role !== 'ADMIN') {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'INSUFFICIENT_PERMISSIONS',
            message: 'Only agency Owners and Admins can send client link invitations.',
          },
        },
        { status: 403 }
      );
    }

    const body = await request.json();
    const { delegateBranding } = body;
    let targetIdentifier = body.clientOrgSlugOrId || body.clientOrgId;

    if (!targetIdentifier && body.clientOrgEmail) {
      const emailTarget = String(body.clientOrgEmail).trim().toLowerCase();
      if (isMongoActive()) {
        const targetUser = await User.findOne({ email: emailTarget });
        if (targetUser) {
          targetIdentifier =
            targetUser.activeOrganizationId?.toString() ||
            targetUser.organizationMemberships?.[0]?.organizationId?.toString();
        }
      } else {
        const targetUser = Array.from(memoryStore.users.values()).find(
          (u: any) => u.email?.trim().toLowerCase() === emailTarget
        );
        if (targetUser) {
          targetIdentifier =
            targetUser.organizationMemberships?.[0]?.organizationId?.toString() ||
            targetUser.organizationId?.toString();
        }
      }
      if (!targetIdentifier) {
        // Look up by alertEmail or slug
        if (isMongoActive()) {
          const orgByEmail = await Organization.findOne({
            $or: [{ 'settings.alertEmail': emailTarget }, { slug: emailTarget }],
          });
          if (orgByEmail) targetIdentifier = orgByEmail._id.toString();
        } else {
          const orgByEmail = Array.from(memoryStore.organizations.values()).find(
            (o: any) => o.settings?.alertEmail?.toLowerCase() === emailTarget || o.slug === emailTarget
          );
          if (orgByEmail) targetIdentifier = orgByEmail._id?.toString() || orgByEmail.id;
        }
      }
    }

    if (!targetIdentifier || typeof targetIdentifier !== 'string') {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'VALIDATION_FAILED',
            message: 'clientOrgSlugOrId or clientOrgEmail is required.',
          },
        },
        { status: 400 }
      );
    }

    // 3. Resolve target client organization
    let clientOrg: any = null;
    if (isMongoActive()) {
      clientOrg = await Organization.findOne({
        $or: [{ _id: targetIdentifier }, { slug: targetIdentifier.trim().toLowerCase() }],
      });
    } else {
      clientOrg =
        memoryStore.organizations.get(targetIdentifier) ||
        Array.from(memoryStore.organizations.values()).find(
          (o: any) =>
            o.slug === targetIdentifier.trim().toLowerCase() ||
            o._id?.toString() === targetIdentifier ||
            o.id === targetIdentifier
        );
    }

    if (!clientOrg) {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'CLIENT_ORG_NOT_FOUND',
            message: `Target client organization "${targetIdentifier}" could not be found.`,
          },
        },
        { status: 404 }
      );
    }

    const agencyOrgIdStr = (agencyOrg._id || agencyOrg.id).toString();
    const clientOrgIdStr = (clientOrg._id || clientOrg.id).toString();

    if (agencyOrgIdStr === clientOrgIdStr) {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'INVALID_TARGET',
            message: 'An agency cannot create a client link to itself.',
          },
        },
        { status: 400 }
      );
    }

    // 4. Check for existing link
    let existingLink: any = null;
    if (isMongoActive()) {
      existingLink = await AgencyClientLink.findOne({
        agencyOrgId: agencyOrg._id,
        clientOrgId: clientOrg._id,
      });
    } else {
      const links = Array.from(memoryStore.agencyClientLinks.values());
      existingLink = links.find(
        (l: any) =>
          l.agencyOrgId?.toString() === agencyOrgIdStr &&
          l.clientOrgId?.toString() === clientOrgIdStr
      );
    }

    if (existingLink && existingLink.status === 'ACTIVE') {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'LINK_ALREADY_ACTIVE',
            message: 'An active link already exists between this agency and client.',
          },
        },
        { status: 409 }
      );
    }

    // 5. Create or reset to PENDING (§1: client-approved trust model)
    const linkId = existingLink?._id?.toString() || `link_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    const linkData: any = {
      _id: linkId,
      agencyOrgId: agencyOrg._id || agencyOrg.id,
      clientOrgId: clientOrg._id || clientOrg.id,
      status: 'PENDING',
      scopes: ['READ_ONLY'],
      delegateBranding: Boolean(delegateBranding),
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    if (isMongoActive()) {
      if (existingLink) {
        existingLink.status = 'PENDING';
        existingLink.scopes = ['READ_ONLY'];
        existingLink.delegateBranding = Boolean(delegateBranding);
        existingLink.revokedAt = undefined;
        existingLink.revokedByUserId = undefined;
        await existingLink.save();
      } else {
        await AgencyClientLink.create({
          agencyOrgId: agencyOrg._id,
          clientOrgId: clientOrg._id,
          status: 'PENDING',
          scopes: ['READ_ONLY'],
          delegateBranding: Boolean(delegateBranding),
        });
      }
    } else {
      memoryStore.agencyClientLinks.set(linkId, linkData);
    }

    // 6. AuditLog on agency
    const auditData = {
      organizationId: agencyOrg._id || agencyOrg.id,
      actorId: user.email || user._id,
      action: 'AGENCY_LINK_INVITED',
      objectType: 'AgencyClientLink',
      objectId: linkId,
      result: 'SUCCESS',
      details: {
        clientOrgId: clientOrgIdStr,
        clientName: clientOrg.name,
        delegateBranding: Boolean(delegateBranding),
      },
      createdAt: new Date(),
    };

    if (isMongoActive()) {
      await AuditLog.create(auditData).catch(() => {});
    } else {
      memoryStore.auditLogs.push(auditData);
    }

    return NextResponse.json(
      {
        success: true,
        data: {
          linkId,
          agencyOrgId: agencyOrgIdStr,
          clientOrgId: clientOrgIdStr,
          clientOrgName: clientOrg.name,
          status: 'PENDING',
          scopes: ['READ_ONLY'],
          delegateBranding: Boolean(delegateBranding),
        },
      },
      { status: 201 }
    );
  } catch (error: any) {
    const status = error.status || 500;
    return NextResponse.json(
      { success: false, error: { code: 'AGENCY_INVITE_ERROR', message: error.message } },
      { status }
    );
  }
}
