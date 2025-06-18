import { NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';
import { processRefund, getUserFromDB } from '../../../../utils/authHelpers';

export async function POST(request) {
  try {
    /* ------------------------------------------------------------------
     * 1. Basic request validation
     * ----------------------------------------------------------------*/
    if (request.headers.get('content-type') !== 'application/json') {
      return NextResponse.json(
        { error: 'Invalid content type' },
        { status: 400 }
      );
    }

    /* ------------------------------------------------------------------
     * 2. CSRF mitigation – ensure browser requests originate from same site
     * ----------------------------------------------------------------*/
    const originHeader = request.headers.get('origin') || request.headers.get('referer');
    if (originHeader) {
      const { protocol, host } = new URL(request.url);
      const expectedOrigin = `${protocol}//${host}`;
      if (!originHeader.startsWith(expectedOrigin)) {
        return NextResponse.json(
          { error: 'CSRF validation failed' },
          { status: 403 }
        );
      }
    }

    /* ------------------------------------------------------------------
     * 3. Authentication
     * ----------------------------------------------------------------*/
    const secret = process.env.JWT_SECRET;
    if (!secret) {
      return NextResponse.json(
        { error: 'Server misconfiguration' },
        { status: 500 }
      );
    }

    const authCookie = request.cookies.get('auth')?.value;
    if (!authCookie) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    let decoded;
    try {
      decoded = jwt.verify(authCookie, secret, { algorithms: ['HS256'] });
    } catch (err) {
      return NextResponse.json(
        { error: 'Invalid or expired token' },
        { status: 401 }
      );
    }

    /* ------------------------------------------------------------------
     * 4. Authorization – admin role required
     * ----------------------------------------------------------------*/
    const user = await getUserFromDB(decoded.userId);
    if (!user?.isAdmin) {
      return NextResponse.json(
        { error: 'Admin required' },
        { status: 403 }
      );
    }

    /* ------------------------------------------------------------------
     * 5. Parse & validate payload
     * ----------------------------------------------------------------*/
    const { orderId, amount, reason } = await request.json();

    if (
      !orderId || typeof orderId !== 'string' || !orderId.trim() ||
      typeof amount !== 'number' || Number.isNaN(amount) || amount <= 0 ||
      !reason || typeof reason !== 'string' || !reason.trim()
    ) {
      return NextResponse.json(
        { error: 'Invalid payload' },
        { status: 400 }
      );
    }

    /* ------------------------------------------------------------------
     * 6. Execute business logic
     * ----------------------------------------------------------------*/
    const refund = processRefund(orderId.trim(), amount, reason.trim());

    // Prevent internal data leakage – return minimal information
    return NextResponse.json({ success: true, refundId: refund.refundId });
  } catch (error) {
    return NextResponse.json(
      { error: 'Server error' },
      { status: 500 }
    );
  }
}