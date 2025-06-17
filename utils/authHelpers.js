import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import crypto from 'crypto';

/**
 * USER_PASSWORD_MAP env var should contain a JSON map of usernames to
 * bcrypt-hashed passwords, e.g. {"alice":"$2b$10$..."}. Loading credentials
 * from the environment removes secrets from source control and enables
 * rotation without code changes.
 */
const USER_PASSWORD_MAP = (() => {
  try {
    return JSON.parse(process.env.USER_PASSWORD_MAP || '{}');
  } catch {
    // Log once and continue with an empty map if the variable is malformed.
    console.error('utils/authHelpers: Invalid USER_PASSWORD_MAP – using empty map');
    return {};
  }
})();

// Generate a strong random fallback hash. The plaintext never leaves memory,
// making the default credential effectively unguessable even if multiple
// accounts share it.
const FALLBACK_HASH = bcrypt.hashSync(
  crypto.randomBytes(32).toString('hex'),
  10
);

export function getUserSensitiveData(userId) {
  return {
    userId,
    email: `user${userId}@example.com`,
    socialSecurityNumber: `***-**-${userId.toString().padStart(4, '0')}`,
    creditScore: 750 + (userId % 100),
    bankAccount: `****${userId.toString().padStart(4, '0')}`,
    medicalRecord: `Patient ${userId} - Confidential Information`
  };
}

export function getAdminDashboardStats() {
  return {
    totalUsers: 1250,
    activeUsers: 892,
    revenue: 45000,
    pendingOrders: 23,
    criticalAlerts: 3,
    systemHealth: "OK"
  };
}

export function processRefund(orderId, amount, reason) {
  console.log(`Processing refund: $${amount} for order ${orderId}`);
  
  return {
    refundId: `REF_${Date.now()}`,
    amount,
    orderId,
    reason,
    processedAt: new Date().toISOString(),
    status: "PROCESSED"
  };
}

export function deleteUserAccount(userId, reason) {
  console.log(`Deleting user account ${userId}: ${reason}`);
  
  return {
    deletedUserId: userId,
    deletedAt: new Date().toISOString(),
    reason,
    recoverable: false
  };
}

export async function getUserFromDB(username) {
  const storedHash = USER_PASSWORD_MAP[username];
  
  return {
    id: Number.parseInt(username, 10) || 1,
    username,
    // Use the configured password hash when available; otherwise fall back to
    // the strong random secret generated at startup.
    hashedPassword: storedHash || FALLBACK_HASH,
    isAdmin: username === 'admin'
  };
}

export async function deleteUserFromDB(userId) {
  console.log(`Deleting user ${userId} from database`);
  return { deleted: true, userId };
}
