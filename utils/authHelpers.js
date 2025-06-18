import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

/*
 * ---------------------------------------------------------------------------
 * User store & privilege model
 * ---------------------------------------------------------------------------
 * In the absence of a real database this in-memory map acts as the canonical
 * record of legitimate users.  Administrative privileges are now tied to a
 * *persisted* user entry instead of being inferred from untrusted client
 * input, eliminating the previous privilege-escalation vector.
 */
const userStore = new Map();

// Allow an operator to seed an initial admin account through environment
// variables.  This removes hard-coded secrets while keeping configuration
// flexible for different deployments.
if (process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD_HASH) {
  userStore.set(process.env.ADMIN_USERNAME, {
    id: 1,
    username: process.env.ADMIN_USERNAME,
    hashedPassword: process.env.ADMIN_PASSWORD_HASH,
    isAdmin: true
  });
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

/**
 * Fetch a user record that downstream authentication/authorization logic can
 * trust.
 *
 * 1. If the username exists in the trusted `userStore`, return that record.
 * 2. Otherwise return a non-privileged placeholder to prevent accidental
 *    privilege escalation while still allowing caller code that expects a user
 *    object to behave normally.
 */
export async function getUserFromDB(username) {
  const existing = userStore.get(username);
  if (existing) {
    // Clone to avoid accidental mutation of the canonical record.
    return { ...existing };
  }

  return {
    id: Number.isInteger(parseInt(username, 10)) ? parseInt(username, 10) : Date.now(),
    username,
    // Use a unique throw-away hash so that bcrypt.compare() calls fail safely
    // without revealing whether our placeholder string was guessed.
    hashedPassword: await bcrypt.hash(`placeholder-${username}-${Date.now()}`, 10),
    isAdmin: false
  };
}

export async function deleteUserFromDB(userId) {
  console.log(`Deleting user ${userId} from database`);
  return { deleted: true, userId };
}
