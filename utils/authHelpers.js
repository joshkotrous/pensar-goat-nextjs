import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

// ---------------------------------------------------------------------------
// Simple in-memory user registry.
// ---------------------------------------------------------------------------
//   • keys   : username (string)
//   • values : user objects { id, username, hashedPassword, isAdmin }
//
// Each new username receives the next sequential ID, generated exclusively on
// the server.  Callers can no longer influence the numeric identifier by
// sending crafted usernames.
// ---------------------------------------------------------------------------
const usersByUsername = new Map();
let nextId = 1;

function getUserById(id) {
  for (const user of usersByUsername.values()) {
    if (user.id === id) return user;
  }
  return null;
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
// Secure user lookup / creation helper
// ---------------------------------------------------------------------------
// Accepts either a username (string containing non-digits) or a numeric ID.
// Returns an existing user or, when supplied a *username* that does not yet
// exist, provisions a new entry with a server-controlled ID.
// ---------------------------------------------------------------------------
export async function getUserFromDB(identifier) {
  // Case 1: caller passed a pure numeric ID
  if (typeof identifier === 'number' || (typeof identifier === 'string' && /^\d+$/.test(identifier))) {
    const idNumber = Number(identifier);
    const user = getUserById(idNumber);
    if (user) return user;
    // Unknown ID – return a safe placeholder so callers can handle gracefully
    return { id: idNumber, username: null, hashedPassword: '', isAdmin: false };
  }

  // Case 2: caller passed a username (string with non-numeric chars)
  const username = String(identifier);
  let user = usersByUsername.get(username);
  if (user) return user;

  // Provision a brand-new user with the next server-side ID
  const newId = nextId++;
  const hashedPassword = await bcrypt.hash('password123', 10);
  user = { id: newId, username, hashedPassword, isAdmin: username === 'admin' };
  usersByUsername.set(username, user);
  return user;
}

export async function deleteUserFromDB(userId) {
  console.log(`Deleting user ${userId} from database`);
  const numericId = Number(userId);
  for (const [uname, user] of usersByUsername.entries()) {
    if (user.id === numericId) {
      usersByUsername.delete(uname);
      break;
    }
  }
  return { deleted: true, userId: numericId };
}
