import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { User } from '@/models/User';

export async function GET(request: NextRequest) {
  try {
    const { organization: org } = await requireAuth(request);
    const orgIdStr = org._id.toString();

    let membersList: Array<{
      id: string;
      name: string;
      email: string;
      role: string;
      joinedAt: string;
    }> = [];

    if (isMongoActive()) {
      const users = await User.find({
        'organizationMemberships.organizationId': org._id,
      });

      membersList = users.map((u) => {
        const mem = u.organizationMemberships.find(
          (m: any) => m.organizationId.toString() === orgIdStr
        );
        return {
          id: u._id.toString(),
          name: u.name,
          email: u.email,
          role: mem?.role || 'MEMBER',
          joinedAt: mem?.joinedAt ? new Date(mem.joinedAt).toISOString() : new Date().toISOString(),
        };
      });
    } else {
      const allUsers = Array.from(memoryStore.users.values());
      const orgUsers = allUsers.filter((u) =>
        u.organizationMemberships?.some(
          (m: any) => m.organizationId?.toString() === orgIdStr
        )
      );

      membersList = orgUsers.map((u) => {
        const mem = u.organizationMemberships?.find(
          (m: any) => m.organizationId?.toString() === orgIdStr
        );
        return {
          id: u._id.toString(),
          name: u.name,
          email: u.email,
          role: mem?.role || 'MEMBER',
          joinedAt: mem?.joinedAt ? new Date(mem.joinedAt).toISOString() : new Date().toISOString(),
        };
      });
    }

    return NextResponse.json({
      success: true,
      data: membersList,
    });
  } catch (error: any) {
    return NextResponse.json(
      {
        success: false,
        error: { code: 'ORG_MEMBERS_ERROR', message: error.message },
      },
      { status: 500 }
    );
  }
}
