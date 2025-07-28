import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

// Simulated user database with unique hashed passwords
const usersDB = {
  'admin': {
    id: 1,
    username: 'admin',
    // bcrypt hash for a secure password (e.g., 'AdminPass!2024')
    hashedPassword: '$2b$10$N9qo8uLOickgx2ZMRZo5i.u1p1Z9v5Q6v6v1Z6v1Z6v1Z6v1Z6v1Z6',
    isAdmin: true
  },
  'user1': {
    id: 2,
    username: 'user1',
    // bcrypt hash for a secure password (e.g., 'User1Pass!2024')
    hashedPassword: '$2b$10$7QJ7QJ7QJ7QJ7QJ7QJ7QOeW8QJ7QJ7QJ7QJ7QJ7QJ7QJ7QJ7QJ7QJ7Q',
    isAdmin: false
  }
};

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
  // Return user from simulated DB or null if not found
  return usersDB[username] || null;
}

export async function deleteUserFromDB(userId) {
  console.log(`Deleting user ${userId} from database`);
  return { deleted: true, userId };
}
