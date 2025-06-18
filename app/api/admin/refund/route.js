import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';
import { processRefund, getUserFromDB } from '../../../../utils/authHelpers';

export async function POST(request) {
  try {
    /*
      Authenticate caller using the same mechanism as other admin endpoints
    */
    const authCookie = request.cookies.get('auth')?.value;
    if (!authCookie) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const decoded = jwt.verify(authCookie, process.env.JWT_SECRET);
    const adminUser = await getUserFromDB(decoded.userId);

    if (!adminUser?.isAdmin) {
      return NextResponse.json(
        { error: 'Admin required' },
        { status: 403 }
      );
    }

    /*
      Request is authenticated and authorized — continue with refund logic
    */
    const { orderId, amount, reason } = await request.json();

    if (!orderId || !amount) {
      return NextResponse.json(
        { error: 'orderId and amount are required' },
        { status: 400 }
      );
    }

    const result = processRefund(orderId, amount, reason);
    return NextResponse.json(result);
  } catch (error) {
    const isJwtError =
      error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError';
    return NextResponse.json(
      { error: isJwtError ? 'Invalid token' : 'Server error' },
      { status: isJwtError ? 401 : 500 }
    );
  }
}