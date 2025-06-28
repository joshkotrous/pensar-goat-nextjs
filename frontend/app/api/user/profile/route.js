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

    const decoded = jwt.verify(authCookie, process.env.JWT_SECRET);
    
    const userData = getUserSensitiveData(decoded.userId);
    
    return NextResponse.json(userData);
  } catch (error) {
    return NextResponse.json(
      { error: 'Invalid token' }, 
      { status: 401 }
    );
  }
}