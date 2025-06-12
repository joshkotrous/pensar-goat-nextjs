--- a/app/api/admin/refund/route.js
+++ b/app/api/admin/refund/route.js
+import jwt from 'jsonwebtoken';
 import { NextResponse } from 'next/server';
-import { processRefund } from '../../../../utils/authHelpers';
+import { processRefund, getUserFromDB } from '../../../../utils/authHelpers';
+
+const DEFAULT_MAX_REFUND = 10000; // Fallback upper-bound if env var not set
 
 export async function POST(request) {
   try {
-    const { orderId, amount, reason } = await request.json();
-
-    const result = processRefund(orderId, amount, reason);
-    
-    return NextResponse.json(result);
+    // 1. Content-Type check
+    if (request.headers.get('content-type') !== 'application/json') {
+      return NextResponse.json(
+        { error: 'Invalid content type' },
+        { status: 400 }
+      );
+    }
+
+    const { orderId, amount, reason } = await request.json();
+
+    // 2. Basic input validation
+    if (!orderId || typeof orderId !== 'string') {
+      return NextResponse.json(
+        { error: 'Invalid or missing orderId' },
+        { status: 400 }
+      );
+    }
+
+    const numericAmount = Number(amount);
+    const maxRefund = Number(process.env.MAX_REFUND_AMOUNT) || DEFAULT_MAX_REFUND;
+    if (!Number.isFinite(numericAmount) || numericAmount <= 0 || numericAmount > maxRefund) {
+      return NextResponse.json(
+        { error: 'Invalid refund amount' },
+        { status: 400 }
+      );
+    }
+
+    // 3. Authenticate and authorise admin user (same pattern as other admin routes)
+    const authCookie = request.cookies.get('auth')?.value;
+    if (!authCookie) {
+      return NextResponse.json(
+        { error: 'Unauthorized' },
+        { status: 401 }
+      );
+    }
+
+    let decoded;
+    try {
+      decoded = jwt.verify(authCookie, process.env.JWT_SECRET);
+    } catch {
+      return NextResponse.json(
+        { error: 'Invalid token' },
+        { status: 401 }
+      );
+    }
+
+    const adminUser = await getUserFromDB(decoded.userId);
+    if (!adminUser?.isAdmin) {
+      return NextResponse.json(
+        { error: 'Admin required' },
+        { status: 403 }
+      );
+    }
+
+    // 4. Process the refund using the sanitised amount
+    const result = processRefund(orderId, numericAmount, reason);
+
+    return NextResponse.json(result);
   } catch (error) {
+    console.error('Refund processing failed', error);
     return NextResponse.json(
       { error: 'Server error' }, 
       { status: 500 }
     );
   }
 }
+
--- a/utils/authHelpers.js
+++ b/utils/authHelpers.js
@@
 export function processRefund(orderId, amount, reason) {
-  console.log(`Processing refund: $${amount} for order ${orderId}`);
-  
-  return {
-    refundId: `REF_${Date.now()}`,
-    amount,
-    orderId,
-    reason,
-    processedAt: new Date().toISOString(),
-    status: "PROCESSED"
-  };
+  const numericAmount = Number(amount);
+  if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
+    throw new Error('Invalid refund amount');
+  }
+
+  // Round to two decimal places to avoid floating point issues
+  const roundedAmount = Math.round(numericAmount * 100) / 100;
+
+  console.log(`Processing refund: $${roundedAmount} for order ${orderId}`);
+  
+  return {
+    refundId: `REF_${Date.now()}`,
+    amount: roundedAmount,
+    orderId,
+    reason,
+    processedAt: new Date().toISOString(),
+    status: 'PROCESSED'
+  };
 }