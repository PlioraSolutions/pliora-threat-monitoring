import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { connectToDatabase, isMongoActive } from '@/lib/db';
import { User } from '@/models/User';
import { Organization } from '@/models/Organization';
import { hashPassword, createSessionToken, SESSION_COOKIE_NAME } from '@/lib/auth';
import { memoryStore } from '@/lib/store';

const registerSchema = z
  .object({
    email: z.string().trim().toLowerCase().email('Invalid email address'),
    password: z.string().min(8, 'Password must be at least 8 characters'),
    name: z.string().trim().min(2, 'Name must be at least 2 characters'),
    orgName: z.string().trim().min(2).optional(),
    organizationName: z.string().trim().min(2).optional(),
    accountType: z.enum(['STANDARD', 'AGENCY']).optional().default('STANDARD'),
  })
  .refine((data) => Boolean(data.orgName || data.organizationName), {
    message: 'Organization name must be at least 2 characters',
    path: ['orgName'],
  });

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const parsed = registerSchema.safeParse(body);
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

    const { email, password, name } = parsed.data;
    const orgName = parsed.data.orgName || parsed.data.organizationName || 'Default Organization';
    await connectToDatabase();

    // Check existing email
    if (isMongoActive()) {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return NextResponse.json(
          { success: false, error: { code: 'EMAIL_IN_USE', message: 'Email is already registered.' } },
          { status: 409 }
        );
      }
    } else {
      if (memoryStore.users.has(email)) {
        return NextResponse.json(
          { success: false, error: { code: 'EMAIL_IN_USE', message: 'Email is already registered.' } },
          { status: 409 }
        );
      }
    }

    const passwordHash = await hashPassword(password);
    const slugSuffix = Math.random().toString(36).substring(2, 6);
    const orgSlug = orgName
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '') + '-' + slugSuffix;

    let org: any;
    let user: any;

    if (isMongoActive()) {
      org = await Organization.create({
        name: orgName,
        slug: orgSlug,
        ownerId: 'pending',
        plan: 'FREE',
        accountType: parsed.data.accountType || 'STANDARD',
        scanQuotas: {
          maxMonitoredDomains: 3,
          dailyScanLimit: 10,
          concurrentScans: 2,
        },
        settings: {
          alertEmail: email,
          notifyOnNewSubdomain: true,
          notifyOnHighCritical: true,
        },
      });

      user = await User.create({
        email,
        passwordHash,
        name,
        globalRole: 'USER',
        organizationMemberships: [
          {
            organizationId: org._id,
            role: 'OWNER',
            joinedAt: new Date(),
          },
        ],
        activeOrganizationId: org._id,
        lastLoginAt: new Date(),
      });

      org.ownerId = user._id.toString();
      await org.save();
    } else {
      const orgId = 'org-' + Date.now();
      const userId = 'user-' + Date.now();

      org = {
        _id: orgId,
        name: orgName,
        slug: orgSlug,
        ownerId: userId,
        plan: 'FREE',
        accountType: parsed.data.accountType || 'STANDARD',
        scanQuotas: {
          maxMonitoredDomains: 3,
          dailyScanLimit: 10,
          concurrentScans: 2,
        },
        settings: {
          alertEmail: email,
          notifyOnNewSubdomain: true,
          notifyOnHighCritical: true,
        },
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      memoryStore.organizations.set(orgId, org);
      memoryStore.organizations.set(orgSlug, org);

      user = {
        _id: userId,
        email,
        passwordHash,
        name,
        globalRole: 'USER',
        organizationMemberships: [
          {
            organizationId: orgId,
            role: 'OWNER',
            joinedAt: new Date(),
          },
        ],
        activeOrganizationId: orgId,
        lastLoginAt: new Date(),
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      memoryStore.users.set(userId, user);
      memoryStore.users.set(email, user);
    }

    const token = createSessionToken({
      userId: user._id.toString(),
      email: user.email,
      organizationId: org._id.toString(),
      role: 'OWNER',
    });

    const response = NextResponse.json(
      {
        success: true,
        data: {
          user: {
            id: user._id.toString(),
            email: user.email,
            name: user.name,
            role: 'OWNER',
          },
          organization: {
            id: org._id.toString(),
            name: org.name,
            slug: org.slug,
            plan: org.plan,
          },
          token,
        },
      },
      { status: 201 }
    );

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
      { success: false, error: { code: 'REGISTER_FAILED', message: error.message } },
      { status: 500 }
    );
  }
}
