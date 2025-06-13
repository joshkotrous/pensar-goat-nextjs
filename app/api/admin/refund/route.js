import { NextResponse } from 'next/server';
import { processRefund } from '../../../../utils/authHelpers';
import crypto from 'crypto';

// Util: Simple JWT validation without external dependencies
function verifyJWT(token, secret) {
  // Split the token into its parts
  const [headerB64, payloadB64, signatureB64] = token.split('.');
  if (!headerB64 || !payloadB64 || !signatureB64) return null;

  try {
    // Verify signature
    const data = `${headerB64}.${payloadB64}`;
    const expectedSig = crypto
      .createHmac('sha256', secret)
      .update(data)
      .digest('base64')
      .replace(/=+$/, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');

    if (expectedSig !== signatureB64) {
      return null;
    }
    // Decode payload
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64').toString('utf8'));
    return payload;
  } catch {
    return null;
  }
}

export async function POST(request) {
  try {
    const authHeader = request.headers.get('authorization') || request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return NextResponse.json(
        { error: 'Unauthorized: Missing or invalid authorization header' },
        { status: 401 }
      );
    }

    const token = authHeader.substring('Bearer '.length);
    const secret = process.env.JWT_SECRET;
    if (!secret) {
      return NextResponse.json(
        { error: 'Server misconfiguration: JWT secret not set' },
        { status: 500 }
      );
    }

    const jwtPayload = verifyJWT(token, secret);
    if (!jwtPayload) {
      return NextResponse.json(
        { error: 'Unauthorized: Invalid token' },
        { status: 401 }
      );
    }

    // Check for authorization: must be an admin
    if (!jwtPayload.isAdmin) {
      return NextResponse.json(
        { error: 'Forbidden: Insufficient privileges' },
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