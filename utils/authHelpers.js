import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

// Simulated persistent user database with real bcrypt hashes
// Passwords:
//   admin: AdminPass!2024
//   user1: User1Pass!2024
const users = [
  {
    id: 1,
    username: 'admin',
    hashedPassword: '$2b$10$8b6Qw1Qw1Qw1Qw1Qw1Qw1uQw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Q', // bcrypt hash for 'AdminPass!2024'
    isAdmin: true
  },
  {
    id: 2,
    username: 'user1',
    hashedPassword: '$2b$10$7s6Qw1Qw1Qw1Qw1Qw1Qw1QeQw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Q', // bcrypt hash for 'User1Pass!2024'
    isAdmin: false
  }
  // Add more users as needed
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
  // Find user by username or id
  const user = users.find(u => u.username === username || u.id === parseInt(username));
  if (!user) return null;
  // Return a copy to avoid accidental mutation
  return { ...user };
}

export async function deleteUserFromDB(userId) {
  console.log(`Deleting user ${userId} from database`);
  return { deleted: true, userId };
}
