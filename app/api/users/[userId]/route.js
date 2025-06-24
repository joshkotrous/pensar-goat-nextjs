import { NextResponse } from 'next/server';

// Simple HTML escape function to sanitize output
function escapeHTML(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export async function GET(request, { params }) {
  const { userId } = params;

  const userData = {
    id: userId,
    bio: escapeHTML(`This is user ${userId}'s bio. <script>alert('xss')</script> Some text here.`),
    comments: [
      {
        id: 1,
        author: 'Alice',
        text: escapeHTML('Great post! <script>alert("xss")</script>')
      },
      {
        id: 2,
        author: 'Bob',
        text: escapeHTML('Thanks for sharing <img src=x onerror=alert(1)>')
      }
    ]
  };

  return NextResponse.json(userData);
}