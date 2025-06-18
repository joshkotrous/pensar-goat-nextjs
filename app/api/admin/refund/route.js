import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';
import { processRefund, getUserFromDB } from '../../../../utils/authHelpers';

export async function POST(request) {
  try {
    /* 1. Authenticate caller */
    const authCookie = request.cookies.get('auth')?.value;
    if (!authCookie) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    /* 2. Verify token & authorise admin */
    const decoded = jwt.verify(authCookie, process.env.JWT_SECRET);
    const user = await getUserFromDB(decoded.userId);

    if (!user.isAdmin) {
      return NextResponse.json(
        { error: 'Admin required' },
        { status: 403 }
      );
    }

    /* 3. Process refund */
    const { orderId, amount, reason } = await request.json();
    const result = processRefund(orderId, amount, reason);

    return NextResponse.json(result);
  } catch (error) {
    /* Distinguish auth errors from server errors */
    const status =
      error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError'
        ? 401
        : 500;
    return NextResponse.json(
      { error: status === 401 ? 'Invalid token' : 'Server error' },
      { status }
    );
  }
}