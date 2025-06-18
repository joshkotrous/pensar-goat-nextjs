import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';

// Require a reasonably strong secret to prevent predictable or empty keys
const MIN_SECRET_LENGTH = 32;
function getJwtSecret() {
  const secret = process.env.JWT_SECRET;
  if (typeof secret !== 'string' || secret.trim().length < MIN_SECRET_LENGTH) {
    return null;
  }
  return secret.trim();
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

    // Validate JWT secret before issuing any tokens
    const jwtSecret = getJwtSecret();
    if (!jwtSecret) {
      console.error('Critical security error: JWT_SECRET is missing or too weak.');
      return NextResponse.json(
        { error: 'Server misconfiguration' },
        { status: 500 }
      );
    }

    const token = jwt.sign({ userId: user.id }, jwtSecret, { algorithm: 'HS256' });

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
    console.error('Unexpected error in login route:', error);
    return NextResponse.json(
      { error: 'Server error' },
      { status: 500 }
    );
  }
}
