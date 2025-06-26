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
    } catch (error) {
      return NextResponse.json(
        { error: 'Invalid or expired token' },
        { status: 401 }
      );
    }

    const user = await getUserFromDB(decoded.userId);
    if (!user.isAdmin) {
      return NextResponse.json(
        { error: 'Admin required' }, 
        { status: 403 }
      );
    }

    const { orderId, amount, reason } = await request.json();
    if (!orderId || typeof amount !== 'number' || amount <= 0 || typeof reason !== 'string') {
      return NextResponse.json(
        { error: 'Invalid input' },
        { status: 400 }
      );
    }

    const result = processRefund(orderId, amount, reason);
    return NextResponse.json(result);
  } catch (error) {
    return NextResponse.json(
      { error: 'Server error' }, 
      { status: 500 }
    );
  }
}