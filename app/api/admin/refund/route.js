import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';
import { processRefund, getUserFromDB } from '../../../../utils/authHelpers';

function validateRefundInput({ orderId, amount, reason }) {
  if (!orderId || (typeof orderId !== 'string' && typeof orderId !== 'number')) {
    return false;
  }
  if (typeof amount !== 'number' || amount <= 0) {
    return false;
  }
  if (!reason || typeof reason !== 'string' || reason.trim() === '') {
    return false;
  }
  return true;
}

export async function POST(request) {
  try {
    const authCookie = request.cookies.get('auth')?.value;
    if (!authCookie) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    let decoded;
    try {
      decoded = jwt.verify(authCookie, process.env.JWT_SECRET);
    } catch {
      return NextResponse.json({ error: 'Invalid token' }, { status: 401 });
    }

    const user = await getUserFromDB(decoded.userId);
    if (!user.isAdmin) {
      return NextResponse.json({ error: 'Admin required' }, { status: 403 });
    }

    const { orderId, amount, reason } = await request.json();

    if (!validateRefundInput({ orderId, amount, reason })) {
      return NextResponse.json({ error: 'Invalid input' }, { status: 400 });
    }

    const result = processRefund(orderId, amount, reason);

    return NextResponse.json(result);
  } catch (error) {
    return NextResponse.json({ error: 'Server error' }, { status: 500 });
  }
}