import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';

// Basic runtime enforcement for a strong JWT secret.
// Ensures the secret is defined, is a string, and has reasonable entropy (length >= 32).
function assertValidJwtSecret(rawSecret) {
  if (typeof rawSecret !== 'string' || rawSecret.trim().length < 32) {
    /*
      Throwing here stops token issuance when the secret is missing or weak, rather
      than silently signing with an unsafe key. A 500 response will be returned by
      the catch-all handler below, alerting operators via logs while keeping
      implementation details from the client.
    */
    throw new Error('JWT_SECRET environment variable must be a non-empty string of at least 32 characters.');
  }
  return rawSecret.trim();
}

export async function POST(request) {
  try {
    const contentType = request.headers.get('content-type');
    if (contentType !== 'application/json') {
      return NextResponse.json(
        { error: 'Invalid content type' }, 
        { status: 400 }
      );
    }

    const { username, password } = await request.json();
    
    const user = await getUserFromDB(username);
    if (!user || !await bcrypt.compare(password, user.hashedPassword)) {
      return NextResponse.json(
        { error: 'Invalid credentials' }, 
        { status: 401 }
      );
    }

    // Validate the JWT secret before signing.
    const jwtSecret = assertValidJwtSecret(process.env.JWT_SECRET);
    const token = jwt.sign({ userId: user.id }, jwtSecret);
    
    const response = NextResponse.json({ 
      success: true, 
      user: { id: user.id, username: user.username } 
    });
    
    response.cookies.set({
      name: 'auth',
      value: token,
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/'
    });

    return response;
  } catch (error) {
    // Log detailed error server-side while returning a generic message to the client.
    console.error('Login route error:', error);
    return NextResponse.json(
      { error: 'Server error' }, 
      { status: 500 }
    );
  }
}
