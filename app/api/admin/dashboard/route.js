import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';
import { getAdminDashboardStats } from '../../../../utils/authHelpers';

export async function GET(request) {
  try {
    const authCookie = request.cookies.get('auth')?.value;
    if (!authCookie) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    // Ensure the JWT secret is configured before attempting verification
    const jwtSecret = process.env.JWT_SECRET;
    if (typeof jwtSecret !== 'string' || jwtSecret.trim() === '') {
      // Log loudly for operators; never proceed with an invalid secret
      console.error('Critical configuration error: JWT_SECRET is not defined');
      return NextResponse.json(
        { error: 'Server configuration error' },
        { status: 500 }
      );
    }

    const decoded = jwt.verify(authCookie, jwtSecret);
    const user = await getUserFromDB(decoded.userId);

    if (!user.isAdmin) {
      return NextResponse.json(
        { error: 'Admin required' },
        { status: 403 }
      );
    }

    const stats = getAdminDashboardStats();

    return NextResponse.json(stats);
  } catch (error) {
    return NextResponse.json(
      { error: 'Invalid token' },
      { status: 401 }
    );
  }
}