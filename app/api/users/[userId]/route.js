import { NextResponse } from 'next/server';

// Dependency-free HTML escaping utility to neutralise characters that can
// break out of text/HTML/JS-string contexts when a consumer renders the
// value with innerHTML or similar sinks.
function escapeHtml(value) {
  if (value === undefined || value === null) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/`/g, '&#x60;')
    .replace(/=/g, '&#x3D;')
    .replace(/\//g, '&#x2F;')
    .replace(/\u2028/g, '&#x2028;')
    .replace(/\u2029/g, '&#x2029;');
}

export async function GET(request, { params }) {
  const { userId } = params;

  // Sanitize user-supplied identifier before embedding it anywhere in the
  // response payload.
  const safeUserId = escapeHtml(userId);

  const userData = {
    id: safeUserId,
    bio: `This is user ${safeUserId}'s bio. Some text here.`,
    comments: [
      {
        id: 1,
        author: 'Alice',
        text: escapeHtml('Great post! <script>alert("xss")</script>')
      },
      {
        id: 2,
        author: 'Bob',
        text: escapeHtml('Thanks for sharing <img src=x onerror=alert(1)>')
      }
    ]
  };

  return NextResponse.json(userData);
}