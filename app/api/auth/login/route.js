import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';

/*
 * Pre-computed dummy hash used to equalise bcrypt execution time when the
 * supplied username is not found.  This prevents timing-based user
 * enumeration because the expensive compare runs in all cases.
 */
const DUMMY_PASSWORD_HASH = bcrypt.hashSync('@@invalid@@', 10);

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

    // Fetch user and always perform a bcrypt comparison to avoid timing leaks
    const user = await getUserFromDB(username);
    const hashForComparison = user ? user.hashedPassword : DUMMY_PASSWORD_HASH;
    const passwordMatches = await bcrypt.compare(password, hashForComparison);

    if (!user || !passwordMatches) {
      return NextResponse.json(
        { error: 'Invalid credentials' },
        { status: 401 }
      );
    }

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET);

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
