import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';


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

    // ------------------------------------------------------------------
    // Secure token issuance: include an explicit expiration claim ("exp")
    // ------------------------------------------------------------------
    const EXPIRES_FALLBACK_SEC = 60 * 60; // 1 hour
    const expiresEnv = process.env.JWT_EXPIRES_IN; // optional env override (seconds or jsonwebtoken format)

    // `jsonwebtoken` accepts shorthand such as "1h". We pass the raw env string
    // (or default) to `expiresIn`, and calculate a numeric variant for the cookie.
    const expiresInOption = expiresEnv || '1h';
    const cookieMaxAge = expiresEnv && /^\d+$/.test(expiresEnv)
      ? parseInt(expiresEnv, 10)
      : EXPIRES_FALLBACK_SEC;

    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET,
      { expiresIn: expiresInOption }
    );
    
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
      path: '/',
      maxAge: cookieMaxAge // keep cookie lifetime in sync with JWT
    });

    return response;
  } catch (error) {
    return NextResponse.json(
      { error: 'Server error' }, 
      { status: 500 }
    );
  }
}
