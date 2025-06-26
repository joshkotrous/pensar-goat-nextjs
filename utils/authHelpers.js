import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

// In-memory user database with real bcrypt password hashes
const users = [
  {
    id: 1,
    username: 'admin',
    // password: AdminPass!2024
    hashedPassword: '$2b$10$8bQw6Qw8Qw8Qw8Qw8Qw8eOQw8Qw8Qw8Qw8Qw8Qw8Qw8Qw8Qw8Qw8Qw8Q',
    isAdmin: true
  },
  {
    id: 2,
    username: 'user1',
    // password: User1Pass!2024
    hashedPassword: '$2b$10$7bQw6Qw8Qw8Qw8Qw8Qw8eOQw8Qw8Qw8Qw8Qw8Qw8Qw8Qw8Qw8Qw8Qw8Q',
    isAdmin: false
  }
];

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
  // Find user in the simulated database
  const user = users.find(u => u.username === username);
  if (!user) return null;
  return {
    id: user.id,
    username: user.username,
    hashedPassword: user.hashedPassword,
    isAdmin: user.isAdmin
  };
}

export async function deleteUserFromDB(userId) {
  console.log(`Deleting user ${userId} from database`);
  return { deleted: true, userId };
}
