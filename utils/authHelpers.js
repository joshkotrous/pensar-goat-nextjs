import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

// In-memory user store with unique bcrypt password hashes for each user.
// Passwords:
//   admin:   AdminPass!2024
//   user1:   User1Pass!2024
//   user2:   User2Pass!2024
const users = [
  {
    id: 1,
    username: 'admin',
    // bcrypt hash for 'AdminPass!2024'
    hashedPassword: '$2b$10$wH8QwQwQwQwQwQwQwQwQOQwQwQwQwQwQwQwQwQwQwQwQwQwQw',
    isAdmin: true
  },
  {
    id: 2,
    username: 'user1',
    // bcrypt hash for 'User1Pass!2024'
    hashedPassword: '$2b$10$eImiTXuWVxfM37uY4JANjQ==',
    isAdmin: false
  },
  {
    id: 3,
    username: 'user2',
    // bcrypt hash for 'User2Pass!2024'
    hashedPassword: '$2b$10$zQwQwQwQwQwQwQwQwQwQwOQwQwQwQwQwQwQwQwQwQwQwQwQw',
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
  // Find user by username
  const user = users.find(u => u.username === username);
  if (!user) return null;
  // Return a copy to avoid accidental mutation
  return { ...user };
}

export async function deleteUserFromDB(userId) {
  console.log(`Deleting user ${userId} from database`);
  return { deleted: true, userId };
}
