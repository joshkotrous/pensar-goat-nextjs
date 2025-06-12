diff --git a/utils/authHelpers.js b/utils/authHelpers.js
@@
 import jwt from 'jsonwebtoken';
 import bcrypt from 'bcrypt';
 
+// ---------------------------------------------------------------------------
+//  Authentication utilities
+// ---------------------------------------------------------------------------
+
+/**
+ * Safely obtain the JWT secret from the environment.
+ * Throws an error when the variable is absent or empty so that the
+ * application never signs or verifies tokens with an invalid key.
+ */
+export function getJwtSecret() {
+  const secret = process.env.JWT_SECRET;
+
+  if (typeof secret !== 'string' || secret.trim() === '') {
+    /*
+     * Deliberately fail fast – continuing would allow jsonwebtoken to
+     * fall back to the literal string "undefined", completely breaking
+     * authentication security.
+     */
+    throw new Error('JWT secret environment variable (JWT_SECRET) is not set');
+  }
+
+  return secret;
+}
+
 export function getUserSensitiveData(userId) {
   return {
@@
   return { deleted: true, userId };
 }
