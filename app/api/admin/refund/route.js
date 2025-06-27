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

    const decoded = jwt.verify(authCookie, process.env.JWT_SECRET);
    const adminUser = await getUserFromDB(decoded.userId);

    if (!adminUser.isAdmin) {
      return NextResponse.json(
        { error: 'Admin required' },
        { status: 403 }
      );
    }

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