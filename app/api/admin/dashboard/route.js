import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';
import { getAdminDashboardStats, getUserFromDB } from '../../../../utils/authHelpers';

// Restrict accepted algorithms to the one used when issuing tokens
const JWT_VERIFY_OPTIONS = {
  algorithms: ['HS256']
};

export async function GET(request) {
  try {
    const authCookie = request.cookies.get('auth')?.value;
    if (!authCookie) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    // Perform strict verification to prevent algorithm-confusion and related attacks
    const decoded = jwt.verify(authCookie, process.env.JWT_SECRET, JWT_VERIFY_OPTIONS);
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