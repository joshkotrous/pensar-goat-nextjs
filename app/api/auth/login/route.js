import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';

// Pre-computed bcrypt hash for the dummy password "invalid_password" (cost factor 10).
// Used solely to equalise timing when the supplied username does not exist.
const DUMMY_HASH = '$2b$10$CwTycUXWue0Thq9StjUM0uJ8ye3GqX6G8eVY.3ZX31lrT7IQ6KZu2';

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

    // Always invoke bcrypt.compare to eliminate username-based timing differences.
    const hashedPassword = user ? user.hashedPassword : DUMMY_HASH;
    const passwordMatch = await bcrypt.compare(password, hashedPassword);

    // Authentication fails if the user does not exist OR the password is incorrect.
    if (!user || !passwordMatch) {
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
