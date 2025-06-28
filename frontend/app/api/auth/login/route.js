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
