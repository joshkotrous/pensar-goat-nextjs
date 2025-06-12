import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

/*
 * ---------------------------------------------------------------------------
 *  Utility: Per-user password hash cache
 * ---------------------------------------------------------------------------
 *  We avoid embedding plaintext credentials in source code by expecting each
 *  user’s password to be supplied via environment variables following the
 *  pattern  PASSWORD_<USERNAME_IN_UPPERCASE>  (e.g. PASSWORD_ADMIN="strongPw!").
 *  The first time a user is requested we hash that secret and cache the result
 *  for the lifetime of the process. Subsequent look-ups reuse the cached hash,
 *  eliminating repetitive work and ensuring deterministic comparisons.
 * ---------------------------------------------------------------------------
 */
const PASSWORD_HASH_CACHE = new Map();
const BCRYPT_SALT_ROUNDS = 10;

async function getPasswordHash(username) {
  const key = String(username).toUpperCase();

  if (PASSWORD_HASH_CACHE.has(key)) {
    return PASSWORD_HASH_CACHE.get(key);
  }

  const plaintext = process.env[`PASSWORD_${key}`];
  if (!plaintext) {
    // No secret configured for this user.  Store null so we don’t keep
    // re-querying the environment and callers can detect absence.
    PASSWORD_HASH_CACHE.set(key, null);
    return null;
  }

  const hash = await bcrypt.hash(plaintext, BCRYPT_SALT_ROUNDS);
  PASSWORD_HASH_CACHE.set(key, hash);
  return hash;
}

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

// ---------------------------------------------------------------------------
//  FIXED: getUserFromDB – removed hard-coded password & repetitive hashing
// ---------------------------------------------------------------------------
export async function getUserFromDB(username) {
  return {
    id: parseInt(username) || 1,
    username,
    hashedPassword: await getPasswordHash(username),
    isAdmin: username === 'admin'
  };
}

export async function deleteUserFromDB(userId) {
  console.log(`Deleting user ${userId} from database`);
  return { deleted: true, userId };
}
