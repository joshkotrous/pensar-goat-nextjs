import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';
import { processRefund, getUserFromDB } from '../../../../utils/authHelpers';

export async function POST(request) {
  try {
    // Retrieve and validate authentication cookie
    const authCookie = request.cookies.get('auth')?.value;
    if (!authCookie) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    // Verify JWT and ensure the user is an admin
    const decoded = jwt.verify(authCookie, process.env.JWT_SECRET);
    const adminUser = await getUserFromDB(decoded.userId);
    if (!adminUser?.isAdmin) {
      return NextResponse.json(
        { error: 'Admin required' },
        { status: 403 }
      );
    }

    // Validate request body is JSON and contains required fields
    const contentType = request.headers.get('content-type');
    if (contentType !== 'application/json') {
      return NextResponse.json(
        { error: 'Invalid content type' },
        { status: 400 }
      );
    }

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
    // Distinguish authentication errors from server errors
    const statusCode = error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError' ? 401 : 500;
    const message = statusCode === 401 ? 'Invalid token' : 'Server error';

    return NextResponse.json(
      { error: message },
      { status: statusCode }
    );
  }
}