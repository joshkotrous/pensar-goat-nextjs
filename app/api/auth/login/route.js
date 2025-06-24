import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';

function validateJwtSecret(secret) {
  if (!secret || typeof secret !== 'string') {
    throw new Error('JWT secret is not set.');
  }
  // Minimum 32 characters, at least one uppercase, one lowercase, one digit, one special char
  if (secret.length < 32) {
    throw new Error('JWT secret is too short. It must be at least 32 characters.');
  }
  if (!/[A-Z]/.test(secret) || !/[a-z]/.test(secret) || !/[0-9]/.test(secret) || !/[^A-Za-z0-9]/.test(secret)) {
    throw new Error('JWT secret must contain uppercase, lowercase, digit, and special character.');
  }
  return secret;
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

    let jwtSecret;
    try {
      jwtSecret = validateJwtSecret(process.env.JWT_SECRET);
    } catch (e) {
      return NextResponse.json(
        { error: e.message },
        { status: 500 }
      );
    }

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
    return NextResponse.json(
      { error: 'Server error' }, 
      { status: 500 }
    );
  }
}
