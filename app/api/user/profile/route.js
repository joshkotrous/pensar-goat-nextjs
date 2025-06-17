import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';
import { getUserSensitiveData } from '../../../../utils/authHelpers';

// Only these fields are safe to expose externally
const ALLOWED_USER_FIELDS = ['userId', 'email'];

export async function GET(request) {
  try {
    const authCookie = request.cookies.get('auth')?.value;
    if (!authCookie) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    // Verify and decode the JWT. Throws on failure.
    const decoded = jwt.verify(authCookie, process.env.JWT_SECRET);

    // Basic authorization: ensure token contains a user identifier
    if (!decoded?.userId) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    // Retrieve the full user record then expose only the whitelisted fields
    const fullUserRecord = getUserSensitiveData(decoded.userId);
    const publicProfile = Object.fromEntries(
      Object.entries(fullUserRecord).filter(([key]) => ALLOWED_USER_FIELDS.includes(key))
    );

    return NextResponse.json(publicProfile);
  } catch (error) {
    return NextResponse.json(
      { error: 'Invalid token' },
      { status: 401 }
    );
  }
}