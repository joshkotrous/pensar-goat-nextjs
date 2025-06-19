import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';
import { processRefund, getUserFromDB } from '../../../../utils/authHelpers';

export async function POST(request) {
  try {
    // 1. Extract and validate auth cookie
    const authCookie = request.cookies.get('auth')?.value;
    if (!authCookie) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    // 2. Verify JWT and load caller details
    const decoded = jwt.verify(authCookie, process.env.JWT_SECRET);
    const user = await getUserFromDB(decoded.userId);

    // 3. Ensure the caller has administrative privileges
    if (!user.isAdmin) {
      return NextResponse.json(
        { error: 'Admin required' },
        { status: 403 }
      );
    }

    // 4. Proceed with the sensitive business operation
    const { orderId, amount, reason } = await request.json();
    const result = processRefund(orderId, amount, reason);

    return NextResponse.json(result);
  } catch (error) {
    // Any verification failure or unexpected error results in 401
    return NextResponse.json(
      { error: 'Invalid token' },
      { status: 401 }
    );
  }
}