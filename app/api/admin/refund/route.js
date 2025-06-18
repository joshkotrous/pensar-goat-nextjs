import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';
import { processRefund, getUserFromDB } from '../../../../utils/authHelpers';

export async function POST(request) {
  try {
    // Require JSON payload
    if (request.headers.get('content-type') !== 'application/json') {
      return NextResponse.json(
        { error: 'Invalid content type' },
        { status: 400 }
      );
    }

    const { orderId, amount, reason } = await request.json();

    // Basic payload validation to avoid malformed requests
    if (!orderId || !amount || Number.isNaN(Number(amount)) || Number(amount) <= 0) {
      return NextResponse.json(
        { error: 'Invalid payload' },
        { status: 400 }
      );
    }

    // Authenticate caller
    const authCookie = request.cookies.get('auth')?.value;
    if (!authCookie) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const decoded = jwt.verify(authCookie, process.env.JWT_SECRET);
    const user = await getUserFromDB(decoded.userId);

    if (!user.isAdmin) {
      return NextResponse.json(
        { error: 'Admin required' },
        { status: 403 }
      );
    }

    const result = processRefund(orderId, amount, reason);

    return NextResponse.json(result);
  } catch (error) {
    const status = (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') ? 401 : 500;
    const message = status === 401 ? 'Invalid token' : 'Server error';
    return NextResponse.json(
      { error: message },
      { status }
    );
  }
}