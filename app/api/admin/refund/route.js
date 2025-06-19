import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';
import { processRefund, getUserFromDB } from '../../../../utils/authHelpers';

export async function POST(request) {
  try {
    /* --------------------------------------------------
     * 1. Authentication – verify the caller has a valid
     *    session token.
     * -------------------------------------------------- */
    const authCookie = request.cookies.get('auth')?.value;
    if (!authCookie) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    let decoded;
    try {
      decoded = jwt.verify(authCookie, process.env.JWT_SECRET);
    } catch {
      return NextResponse.json(
        { error: 'Invalid token' },
        { status: 401 }
      );
    }

    /* --------------------------------------------------
     * 2. Authorization – caller must be an administrator.
     * -------------------------------------------------- */
    const user = await getUserFromDB(decoded.userId);
    if (!user?.isAdmin) {
      return NextResponse.json(
        { error: 'Admin required' },
        { status: 403 }
      );
    }

    /* --------------------------------------------------
     * 3. Perform the refund once the caller is verified.
     * -------------------------------------------------- */
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