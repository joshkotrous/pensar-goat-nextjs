import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';
import { getUserFromDB } from '../../../../utils/authHelpers';

export async function GET(request, { params }) {
  const { userId } = params;

  // Reject anything that is not a simple positive integer (defence-in-depth)
  if (!/^[0-9]+$/.test(userId)) {
    return NextResponse.json({ error: 'Invalid user id' }, { status: 400 });
  }

  try {
    /* ------------------------------------------------------------------
     * 1. Authenticate the caller via the signed JWT stored in the "auth"
     *    cookie.  Enforce algorithm consistency and maximum token age.
     * ----------------------------------------------------------------*/
    const authCookie = request.cookies.get('auth')?.value;
    if (!authCookie) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    let decoded;
    try {
      decoded = jwt.verify(authCookie, process.env.JWT_SECRET, {
        algorithms: ['HS256'],
        maxAge: '24h'
      });
    } catch {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Ensure the token actually contains an expiry claim (defence-in-depth)
    if (!decoded.exp) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    /* ------------------------------------------------------------------
     * 2. Authorise: allow access only to the profile owner or an admin.
     * ----------------------------------------------------------------*/
    const requestingUser = await getUserFromDB(decoded.userId);
    const isOwner = requestingUser.id?.toString() === userId;
    const isAdmin = requestingUser.isAdmin === true;

    if (!isOwner && !isAdmin) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }

    /* ------------------------------------------------------------------
     * 3. Build a safe response payload (plain text, no embedded markup).
     * ----------------------------------------------------------------*/
    const userData = {
      id: parseInt(userId, 10),
      bio: `This is user ${userId}'s bio.`,
      comments: [
        { id: 1, author: 'Alice', text: 'Great post!' },
        { id: 2, author: 'Bob',  text: 'Thanks for sharing!' }
      ]
    };

    return NextResponse.json(userData);
  } catch {
    // Log a generic message to avoid log-injection with attacker data
    console.error('Unexpected error in users/[userId] route');
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}