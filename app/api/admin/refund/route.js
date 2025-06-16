import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';
import { processRefund, getUserFromDB } from '../../../../utils/authHelpers';

const MAX_REFUND_AMOUNT = 10000; // prevent excessively large refunds

function isValidOrderId(orderId) {
  return (
    typeof orderId === 'string' &&
    /^[A-Za-z0-9_-]{3,64}$/.test(orderId)
  );
}

function isValidAmount(amount) {
  const parsed = typeof amount === 'string' ? parseFloat(amount) : amount;
  if (!Number.isFinite(parsed)) return false;
  if (parsed <= 0 || parsed > MAX_REFUND_AMOUNT) return false;
  // Ensure max two decimal places
  return Math.abs(parsed * 100 - Math.round(parsed * 100)) < 1e-6;
}

function sanitizeReason(reason) {
  if (typeof reason !== 'string') return '';
  return reason.replace(/[<>]/g, '').slice(0, 256);
}

export async function POST(request) {
  try {
    // 1. Authenticate & Authorize caller
    const token = request.cookies.get('auth')?.value;
    if (!token) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch {
      return NextResponse.json({ error: 'Invalid token' }, { status: 401 });
    }

    const user = await getUserFromDB(decoded.userId);
    if (!user?.isAdmin) {
      return NextResponse.json({ error: 'Admin required' }, { status: 403 });
    }

    // 2. Validate request body
    if (request.headers.get('content-type') !== 'application/json') {
      return NextResponse.json({ error: 'Invalid content type' }, { status: 400 });
    }

    const { orderId, amount, reason } = await request.json();

    if (!isValidOrderId(orderId) || !isValidAmount(amount)) {
      return NextResponse.json({ error: 'Invalid refund parameters' }, { status: 400 });
    }

    const cleanedReason = sanitizeReason(reason);

    const result = processRefund(orderId, parseFloat(amount), cleanedReason);
    return NextResponse.json(result);
  } catch (error) {
    console.error('Refund processing failed:', error);
    return NextResponse.json({ error: 'Server error' }, { status: 500 });
  }
}