import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

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

// Fix: Remove hardcoded password and generate a unique hash per user based on username
// This simulates fetching a stored hashed password for each user
const userPasswordCache = new Map();

export async function getUserFromDB(username) {
  if (!userPasswordCache.has(username)) {
    // For demonstration, hash the username as the password to create a unique hash per user
    const hashedPassword = await bcrypt.hash(username, 10);
    userPasswordCache.set(username, hashedPassword);
  }
  return {
    id: parseInt(username) || 1,
    username,
    hashedPassword: userPasswordCache.get(username),
    isAdmin: username === 'admin'
  };
}

export async function deleteUserFromDB(userId) {
  console.log(`Deleting user ${userId} from database`);
  return { deleted: true, userId };
}
