import jwt from 'jsonwebtoken';
import { cookies } from 'next/headers';
import UserProfile, { MessageBoard } from '../components/UserProfile';

export default function Home() {
  // Extract the JWT issued at login (if present)
  const cookieStore = cookies();
  const authToken = cookieStore.get('auth')?.value;

  let userId = null;

  if (authToken) {
    try {
      // Verify token integrity and read the embedded user identifier
      const decoded = jwt.verify(authToken, process.env.JWT_SECRET);
      if (decoded && decoded.userId !== undefined && decoded.userId !== null) {
        userId = String(decoded.userId);
      }
    } catch (_) {
      // Invalid / expired token – treat visitor as unauthenticated
    }
  }

  return (
    <div>
      <h1>SAST Benchmarking Application</h1>
      {/* Only show a profile when the visitor is properly authenticated */}
      {userId && <UserProfile userId={userId} />}
      <MessageBoard />
    </div>
  );
}