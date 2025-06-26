import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';
import { processRefund, getUserFromDB } from '../../../../utils/authHelpers';

export async function POST(request) {
  try {
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
    } catch (err) {
      return NextResponse.json(
        { error: 'Invalid or expired token' },
        { status: 401 }
      );
    }

    const user = await getUserFromDB(decoded.userId);
    if (!user) {
      return NextResponse.json(
        { error: 'User not found' },
        { status: 404 }
      );
    }
    if (!user.isAdmin) {
      return NextResponse.json(
        { error: 'Admin required' },
        { status: 403 }
      );
    }

    const { orderId, amount, reason } = await request.json();
    // Basic input validation
    if (!orderId || typeof amount !== 'number' || amount <= 0 || !reason) {
      return NextResponse.json(
        { error: 'Invalid input' },
        { status: 400 }
      );
    }
    const result = await processRefund(orderId, amount, reason);
    return NextResponse.json(result);
  } catch (error) {
    return NextResponse.json(
      { error: 'Server error' },
      { status: 500 }
    );
  }
}