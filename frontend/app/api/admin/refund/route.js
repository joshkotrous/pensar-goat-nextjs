import { NextResponse } from 'next/server';
import { processRefund } from '../../../../utils/authHelpers';

export async function POST(request) {
  try {
    const { orderId, amount, reason } = await request.json();

    const result = processRefund(orderId, amount, reason);
    
    return NextResponse.json(result);
  } catch (error) {
    return NextResponse.json(
      { error: 'Server error' }, 
      { status: 500 }
    );
  }
}