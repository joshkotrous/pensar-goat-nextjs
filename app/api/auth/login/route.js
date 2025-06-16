import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';

// Default token Time-To-Live when none is provided via environment variables.
// A short-lived token (15 minutes) limits the blast radius of a compromise
// while remaining unobtrusive for most users.
const DEFAULT_TOKEN_TTL = '15m';

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
    // Secure session: issue a short-lived JWT instead of a perpetual one.
    // ------------------------------------------------------------------
    const expiresIn = process.env.JWT_EXPIRES_IN || DEFAULT_TOKEN_TTL; // e.g. "15m", "1h"

    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET,
      { expiresIn }
    );

    const response = NextResponse.json({
      success: true,
      user: { id: user.id, username: user.username }
    });

    // Best-effort alignment of cookie lifetime with the JWT expiry.
    response.cookies.set({
      name: 'auth',
      value: token,
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
      maxAge: (() => {
        // Convert common string formats (e.g. 900, "15m", "2h", "1d") to seconds.
        const match = /^([0-9]+)([smhd])?$/.exec(expiresIn);
        if (!match) return undefined;
        const [, value, unit] = match;
        const v = parseInt(value, 10);
        const multipliers = { s: 1, m: 60, h: 3600, d: 86400 };
        return v * multipliers[unit || 's'];
      })()
    });

    return response;
  } catch (error) {
    return NextResponse.json(
      { error: 'Server error' },
      { status: 500 }
    );
  }
}
