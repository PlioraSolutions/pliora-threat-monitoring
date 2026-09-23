import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { connectToDatabase, isMongoActive } from '@/lib/db';
import { User } from '@/models/User';
import { Organization } from '@/models/Organization';
import { verifyPassword, createSessionToken, SESSION_COOKIE_NAME } from '@/lib/auth';
import { memoryStore } from '@/lib/store';
import { ensureDemoAccountInMongo } from '@/lib/seedDemo';

const loginSchema = z.object({
  email: z.string().trim().toLowerCase().email('Invalid email address'),
  password: z.string().min(1, 'Password is required'),
});

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const parsed = loginSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'VALIDATION_FAILED',
            message: parsed.error.errors.map((e) => e.message).join(', '),
          },
        },
        { status: 400 }
      );
    }

    const { email, password } = parsed.data;
    await connectToDatabase();

    let user: any = null;
    let org: any = null;

    if (isMongoActive()) {
      user = await User.findOne({ email });
      if (!user && email === 'demo@pliora.io') {
        const seeded = await ensureDemoAccountInMongo();
        if (seeded) {
          user = seeded.user;
          org = seeded.org;
        }
      } else if (user) {
        org = await Organization.findById(user.activeOrganizationId);
      }
    } else {
      user = memoryStore.users.get(email);
      if (user) {
        org = memoryStore.organizations.get(user.activeOrganizationId.toString());
      }
    }

    // Secondary safety fallback: if user is demo@pliora.io and not found in DB, pull from memoryStore
    if (!user && email === 'demo@pliora.io') {
      user = memoryStore.users.get(email);
      if (user) {
        org = memoryStore.organizations.get(user.activeOrganizationId.toString());
      }
    }

    if (!user) {
      console.log('[LOGIN DEBUG] returning 401 — user not found');
      return NextResponse.json(
        { success: false, error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password.' } },
        { status: 401 }
      );
    }

    const isMatch = await verifyPassword(password, user.passwordHash);
    console.log('[LOGIN DEBUG] password match:', isMatch);
    if (!isMatch) {
      return NextResponse.json(
        { success: false, error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password.' } },
        { status: 401 }
      );
    }

    const membership = user.organizationMemberships?.find(
      (m: any) => m.organizationId.toString() === org?._id?.toString()
    );
    const role = membership?.role || 'MEMBER';

    const token = createSessionToken({
      userId: user._id.toString(),
      email: user.email,
      organizationId: org ? org._id.toString() : user.activeOrganizationId.toString(),
      role,
    });

    const response = NextResponse.json({
      success: true,
      data: {
        user: {
          id: user._id.toString(),
          email: user.email,
          name: user.name,
          role,
        },
        organization: org
          ? {
              id: org._id.toString(),
              name: org.name,
              slug: org.slug,
              plan: org.plan,
            }
          : null,
        token,
      },
    });

    response.cookies.set({
      name: SESSION_COOKIE_NAME,
      value: token,
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
      maxAge: 7 * 24 * 60 * 60,
    });

    return response;
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { code: 'LOGIN_FAILED', message: error.message } },
      { status: 500 }
    );
  }
}
