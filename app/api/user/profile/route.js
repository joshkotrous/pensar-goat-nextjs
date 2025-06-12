import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';
import { getUserSensitiveData } from '../../../../utils/authHelpers';

// Explicitly whitelist the expected signing algorithm to prevent algorithm-confusion attacks
const VERIFY_OPTIONS = Object.freeze({ algorithms: ['HS256'] });

export async function GET(request) {
  try {
    const authCookie = request.cookies.get('auth')?.value;
    if (!authCookie) {
      return NextResponse.json(
        { error: 'Unauthorized' }, 
        { status: 401 }
      );
    }

    // Constrain verification to the approved algorithm
    const decoded = jwt.verify(authCookie, process.env.JWT_SECRET, VERIFY_OPTIONS);
    
    const userData = getUserSensitiveData(decoded.userId);
    
    return NextResponse.json(userData);
  } catch (error) {
    return NextResponse.json(
      { error: 'Invalid token' }, 
      { status: 401 }
    );
  }
}