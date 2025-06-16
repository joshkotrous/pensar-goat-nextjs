// app/api/admin/dashboard/route.js
import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';
import { getAdminDashboardStats, getUserFromDB } from '../../../../utils/authHelpers';

export async function GET(request) {
  try {
    const authCookie = request.cookies.get('auth')?.value;
    if (!authCookie) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    // Strictly verify the token – only allow HS256 and limit age
    const decoded = jwt.verify(authCookie, process.env.JWT_SECRET, {
      algorithms: ['HS256'],
      maxAge: '2h'
    });
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

// app/api/admin/delete-user/route.js
import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';
import { getUserFromDB, deleteUserFromDB } from '../../../../utils/authHelpers';

export async function POST(request) {
  try {
    const formData = await request.formData();
    const userId = formData.get('userId');

    const authCookie = request.cookies.get('auth')?.value;
    if (!authCookie) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const decoded = jwt.verify(authCookie, process.env.JWT_SECRET, {
      algorithms: ['HS256'],
      maxAge: '2h'
    });
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

// app/api/user/profile/route.js
import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';
import { getUserSensitiveData } from '../../../../utils/authHelpers';

export async function GET(request) {
  try {
    const authCookie = request.cookies.get('auth')?.value;
    if (!authCookie) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const decoded = jwt.verify(authCookie, process.env.JWT_SECRET, {
      algorithms: ['HS256'],
      maxAge: '2h'
    });

    const userData = getUserSensitiveData(decoded.userId);

    return NextResponse.json(userData);
  } catch (error) {
    return NextResponse.json(
      { error: 'Invalid token' },
      { status: 401 }
    );
  }
}

// app/api/auth/login/route.js
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';
import { getUserFromDB } from '../../../../utils/authHelpers';

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

    // Issue a short-lived, HS256-signed token
    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET,
      {
        algorithm: 'HS256',
        expiresIn: '1h'
      }
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