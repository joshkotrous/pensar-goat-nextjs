import { NextResponse } from 'next/server';

export async function GET(request, { params }) {
  const { userId } = params;
  
  const userData = {
    id: userId,
    bio: `This is user ${userId}'s bio. <script>alert('xss')</script> Some text here.`,
    comments: [
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
    ]
  };
  
  return NextResponse.json(userData);
}