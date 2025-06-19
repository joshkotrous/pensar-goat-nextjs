import { NextResponse } from 'next/server';
import { processRefund } from '../../../../utils/authHelpers';

// Dummy decodeAuth utility (replace with real auth/session check in production)
async function getUserFromRequest(request) {
  // Example: extract cookie or header and decode user info.
  // This avoids external deps and assumes user info in a signed cookie/header.
  // Replace with your framework's or custom implementation as appropriate.
  const authHeader = request.headers.get('authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  // Simulate decoding a JWT or session token
  // (In real code, use server-side token/session parsing)
  const token = authHeader.slice(7);
  // FAKE token decode for demo: 'admin:username' or 'user:username'
  // Replace with secure server-only validation
  const [role, username] = token.split(':');
  if (!role || !username) return null;
  return { role, username };
}

export async function POST(request) {
  try {
    // Authorization: Only allow authenticated admin users.
    const user = await getUserFromRequest(request);
    if (!user) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      );
    }
    if (user.role !== 'admin') {
      return NextResponse.json(
        { error: 'Forbidden: admin access required' },
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