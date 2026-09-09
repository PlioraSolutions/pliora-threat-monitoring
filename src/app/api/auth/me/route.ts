import { NextRequest, NextResponse } from 'next/server';
import { getAuthenticatedSession } from '@/lib/auth';

export async function GET(request: NextRequest) {
  const session = await getAuthenticatedSession(request);
  if (!session) {
    return NextResponse.json(
      { success: false, error: { code: 'UNAUTHORIZED', message: 'Not authenticated.' } },
      { status: 401 }
    );
  }

  const { user, organization } = session;

  const membership = user.organizationMemberships?.find(
    (m: any) => m.organizationId?.toString() === organization._id?.toString()
  );
  const role = membership?.role || 'MEMBER';

  return NextResponse.json({
    success: true,
    data: {
      user: {
        id: user._id.toString(),
        email: user.email,
        name: user.name,
        role,
        globalRole: user.globalRole,
      },
      organization: {
        id: organization._id.toString(),
        name: organization.name,
        slug: organization.slug,
        plan: organization.plan,
        scanQuotas: organization.scanQuotas,
        settings: organization.settings,
      },
    },
  });
}
