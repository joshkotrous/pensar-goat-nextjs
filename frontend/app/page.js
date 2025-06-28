import UserProfile from '../components/UserProfile';
import { MessageBoard } from '../components/UserProfile';

export default function Home() {
  return (
    <div>
      <h1>SAST Benchmarking Application</h1>
      <UserProfile userId="1" />
      <MessageBoard />
    </div>
  );
}