import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';

export async function POST(request) {
  try {
    // Enforce CSRF protection: require a custom header
    const csrfTokenHeader = request.headers.get('x-csrf-token');
    const csrfTokenCookie = request.cookies.get('csrfToken')?.value;
    if (!csrfTokenHeader || !csrfTokenCookie || csrfTokenHeader !== csrfTokenCookie) {
      return NextResponse.json(
        { error: 'CSRF token missing or invalid' },
        { status: 403 }
      );
    }

    const formData = await request.formData();
    const userId = formData.get('userId');
    
    const authCookie = request.cookies.get('auth')?.value;
    if (!authCookie) {
      return NextResponse.json(
        { error: 'Unauthorized' }, 
        { status: 401 }
      );
    }

    const decoded = jwt.verify(authCookie, process.env.JWT_SECRET);
    const adminUser = await getUserFromDB(decoded.userId);
    
    if (!adminUser.isAdmin) {
      return NextResponse.json(
        { error: 'Admin required' }, 
        { status: 403 }
      );
    }

    await deleteUserFromDB(userId);
    
    return NextResponse.json({ success: true });
  } catch (error) {
    return NextResponse.json(
      { error: 'Invalid token' }, 
      { status: 401 }
    );
  }
}