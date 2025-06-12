import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';
import { processRefund, getUserFromDB } from '../../../../utils/authHelpers';

export async function POST(request) {
  try {
    /* ------------------------------------------------------------------
     * Basic CSRF defence – ensure the request originates from the same
     * site.  We accept the request when either the Origin or Referer
     * header matches the expected origin.  This blocks cross-site form
     * submissions while keeping same-site calls untouched.
     * ----------------------------------------------------------------*/
    const originHeader  = request.headers.get('origin')   || '';
    const refererHeader = request.headers.get('referer')  || '';
    const hostHeader    = request.headers.get('host')     || '';

    // Prefer an explicit env value but fall back to the current host.
    const allowedOrigin =
      process.env.NEXT_PUBLIC_SITE_URL ||
      process.env.SITE_URL ||
      (hostHeader ? `https://${hostHeader}` : '');

    const isSameOrigin = (url) => {
      if (!url) return false;
      try {
        const parsed = new URL(url);
        return parsed.origin === allowedOrigin;
      } catch {
        return false;
      }
    };

    if (!(isSameOrigin(originHeader) || isSameOrigin(refererHeader))) {
      return NextResponse.json(
        { error: 'Invalid origin' },
        { status: 403 }
      );
    }

    /* ------------------------------------------------------------------
     * Authenticate the caller – reuse the cookie/JWT admin check used by
     * other admin endpoints to guarantee only authorised admins can
     * trigger a refund.
     * ----------------------------------------------------------------*/
    const authCookie = request.cookies.get('auth')?.value;
    if (!authCookie) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const decoded    = jwt.verify(authCookie, process.env.JWT_SECRET);
    const adminUser  = await getUserFromDB(decoded.userId);

    if (!adminUser.isAdmin) {
      return NextResponse.json(
        { error: 'Admin required' },
        { status: 403 }
      );
    }

    /* ------------------------------------------------------------------
     * Business logic – this part remains unchanged.
     * ----------------------------------------------------------------*/
    const { orderId, amount, reason } = await request.json();
    const result = processRefund(orderId, amount, reason);

    return NextResponse.json(result);
  } catch (error) {
    return NextResponse.json(
      { error: 'Server error' },
      { status: 500 }
    );
  }
}