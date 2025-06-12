import { NextResponse } from 'next/server';

// ---------------------------------------------------------------------------
// Utility: minimal HTML encoder to neutralise script-injection payloads.
// This avoids new dependencies while covering the most dangerous characters
// for HTML contexts.
// ---------------------------------------------------------------------------
function htmlEncode(str = '') {
  return String(str).replace(/[&<>"']/g, (ch) => {
    switch (ch) {
      case '&': return '&amp;';
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '"': return '&quot;';
      case "'": return '&#39;';
      default:   return ch;
    }
  });
}

export async function GET(request, { params }) {
  const { userId } = params;

  // Raw (potentially unsafe) user-generated values --------------------------
  const rawBio = `This is user ${userId}'s bio. <script>alert('xss')</script> Some text here.`;
  const rawComments = [
    {
      id: 1,
      author: 'Alice',
      text: 'Great post! <script>alert("xss")</script>'
    },
    {
      id: 2,
      author: 'Bob',
      text: 'Thanks for sharing <img src=x onerror=alert(1)>'
    }
  ];

  // Sanitised payload returned to the client --------------------------------
  const userData = {
    id: userId,
    bio: htmlEncode(rawBio),
    comments: rawComments.map((c) => ({
      ...c,
      text: htmlEncode(c.text)
    }))
  };

  return NextResponse.json(userData);
}