import { NextRequest, NextResponse } from 'next/server';
import { getSessionOrganization } from '@/lib/session';
import { Scan } from '@/models/Scan';

export async function GET(
  request: NextRequest,
  context: { params: Promise<{ id: string }> | { id: string } }
) {
  try {
    const org = await getSessionOrganization();
    const resolvedParams = await Promise.resolve(context.params);
    const scanId = resolvedParams.id;

    const scan = await Scan.findOne({
      _id: scanId,
      organizationId: org._id,
    }).populate('targetAssetId', 'fqdn rootDomain type verificationStatus');

    if (!scan) {
      return NextResponse.json(
        { success: false, error: { code: 'NOT_FOUND', message: 'Scan not found.' } },
        { status: 404 }
      );
    }

    return NextResponse.json({
      success: true,
      data: scan,
    });
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { code: 'SCAN_FETCH_ERROR', message: error.message } },
      { status: 500 }
    );
  }
}
