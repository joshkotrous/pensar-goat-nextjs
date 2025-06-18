import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';
import { processRefund, getUserFromDB } from '../../../../utils/authHelpers';

export async function POST(request) {
  try {
    /* ---------------------------------------------------------
     * 1. Authentication – verify the caller is logged-in.
     * --------------------------------------------------------- */
    const authCookie = request.cookies.get('auth')?.value;
    if (!authCookie) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    let decodedToken;
    try {
      decodedToken = jwt.verify(authCookie, process.env.JWT_SECRET);
    } catch (err) {
      return NextResponse.json(
        { error: 'Invalid token' },
        { status: 401 }
      );
    }

    /* ---------------------------------------------------------
     * 2. Authorization – ensure the user has admin privileges.
     * --------------------------------------------------------- */
    const currentUser = await getUserFromDB(decodedToken.userId);
    if (!currentUser?.isAdmin) {
      return NextResponse.json(
        { error: 'Admin required' },
        { status: 403 }
      );
    }

    /* ---------------------------------------------------------
     * 3. Validate request body.
     * --------------------------------------------------------- */
    const contentType = request.headers.get('content-type');
    if (contentType !== 'application/json') {
      return NextResponse.json(
        { error: 'Invalid content type' },
        { status: 400 }
      );
    }

    const { orderId, amount, reason } = await request.json();
    if (!orderId || typeof amount !== 'number' || amount <= 0) {
      return NextResponse.json(
        { error: 'Invalid refund parameters' },
        { status: 400 }
      );
    }

    /* ---------------------------------------------------------
     * 4. Process refund.
     * --------------------------------------------------------- */
    const result = processRefund(orderId, amount, reason);
    return NextResponse.json(result);
  } catch (error) {
    return NextResponse.json(
      { error: 'Server error' },
      { status: 500 }
    );
  }
}