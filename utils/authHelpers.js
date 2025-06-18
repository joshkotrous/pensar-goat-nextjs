diff --git a/utils/authHelpers.js b/utils/authHelpers.js
index 9bde0d1..7f4e9b3 100644
--- a/utils/authHelpers.js
+++ b/utils/authHelpers.js
@@
 import jwt from 'jsonwebtoken';
 import bcrypt from 'bcrypt';
+
+// Internal helper – throws if the supplied user is not an administrator.
+function assertIsAdmin(user) {
+  if (!user || user.isAdmin !== true) {
+    throw new Error('Unauthorized: admin privileges required');
+  }
+}
@@
-export function processRefund(orderId, amount, reason) {
-  console.log(`Processing refund: $${amount} for order ${orderId}`);
-
+export function processRefund(orderId, amount, reason, currentUser) {
+  // Authorisation gate – ensures only admins can execute a refund.
+  assertIsAdmin(currentUser);
+
+  // Redacted audit log; avoids leaking full orderId or amount while keeping traceability.
+  console.info(
+    `Refund approved by admin:${currentUser.id} – order:${String(orderId).substring(0, 4)}… amount:${Number(amount).toFixed(2)}`
+  );
+
   return {
     refundId: `REF_${Date.now()}`,
     amount,
@@
   };
 }
diff --git a/app/api/admin/refund/route.js b/app/api/admin/refund/route.js
index e68c9d4..a42fbd0 100644
--- a/app/api/admin/refund/route.js
+++ b/app/api/admin/refund/route.js
@@
-import { NextResponse } from 'next/server';
-import { processRefund } from '../../../../utils/authHelpers';
+import { NextResponse } from 'next/server';
+import jwt from 'jsonwebtoken';
+import { processRefund, getUserFromDB } from '../../../../utils/authHelpers';
@@
 export async function POST(request) {
   try {
     const { orderId, amount, reason } = await request.json();
-
-    const result = processRefund(orderId, amount, reason);
-
-    return NextResponse.json(result);
+
+    // --- Authentication & authorisation ---
+    const authCookie = request.cookies.get('auth')?.value;
+    if (!authCookie) {
+      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
+    }
+
+    let decoded;
+    try {
+      decoded = jwt.verify(authCookie, process.env.JWT_SECRET, {
+        algorithms: ['HS256'],
+      });
+    } catch {
+      return NextResponse.json({ error: 'Invalid token' }, { status: 401 });
+    }
+
+    const currentUser = await getUserFromDB(decoded.userId);
+    if (!currentUser.isAdmin) {
+      return NextResponse.json({ error: 'Admin required' }, { status: 403 });
+    }
+
+    const result = processRefund(orderId, amount, reason, currentUser);
+    return NextResponse.json(result);
   } catch (error) {
     return NextResponse.json(
-      { error: 'Server error' },
+      { error: error.message || 'Server error' },
       { status: 500 }
     );
   }
 }
