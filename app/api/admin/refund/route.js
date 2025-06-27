import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';
import { processRefund, getUserFromDB } from '../../../../utils/authHelpers';

export async function POST(request) {
  try {
    // Authenticate user via JWT in cookie
    const authCookie = request.cookies.get('auth')?.value;
    if (!authCookie) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const decoded = jwt.verify(authCookie, process.env.JWT_SECRET);
    const user = await getUserFromDB(decoded.userId);

    // Authorize only admin users
    if (!user.isAdmin) {
      return NextResponse.json({ error: 'Admin required' }, { status: 403 });
    }

    // Parse and validate input
    const { orderId, amount, reason } = await request.json();

    if (!orderId || typeof orderId !== 'string' || orderId.trim() === '') {
      return NextResponse.json({ error: 'Invalid orderId' }, { status: 400 });
    }

    if (typeof amount !== 'number' || amount <= 0) {
      return NextResponse.json({ error: 'Invalid amount' }, { status: 400 });
    }

    // Process refund
    const result = processRefund(orderId, amount, reason);

    return NextResponse.json(result);
  } catch (error) {
    return NextResponse.json({ error: 'Server error' }, { status: 500 });
  }
}