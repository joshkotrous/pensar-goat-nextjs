import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

/*
 * Password configuration
 * ----------------------
 * A JSON object mapping usernames to their plaintext passwords must be supplied
 * via the USER_PASSWORDS environment variable, e.g.:
 *   export USER_PASSWORDS='{"alice":"pa$$w0rd","bob":"Tr0ub4dor&3"}'
 * This approach eliminates hard-coded credentials from the codebase while still
 * allowing an operationally simple mechanism for managing (and rotating)
 * user-specific secrets without requiring additional dependencies or storage.
 */
let configuredPasswords = {};
if (process.env.USER_PASSWORDS) {
  try {
    configuredPasswords = JSON.parse(process.env.USER_PASSWORDS);
  } catch (err) {
    /*
     * Fail-fast if the environment variable cannot be parsed; silently ignoring
     * mis-configuration would leave the system in an undefined—and potentially
     * insecure—state.
     */
    throw new Error('Unable to parse USER_PASSWORDS environment variable: ' + err.message);
  }
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

export async function getUserFromDB(username) {
  /*
   * Retrieve the user-specific plaintext password from the configuration.  By
   * sourcing it externally we avoid embedding any secrets in code, satisfy
   * password uniqueness requirements, and enable seamless rotation via
   * environment management tooling.
   */
  const plainPassword = configuredPasswords[username];

  if (typeof plainPassword !== 'string' || plainPassword.length === 0) {
    /*
     * Explicitly error if a password has not been provisioned for the requested
     * account.  This prevents the function from silently falling back to an
     * insecure default and makes operational mis-configurations obvious.
     */
    throw new Error(`No password configured for user: ${username}`);
  }

  const hashedPassword = await bcrypt.hash(plainPassword, 10);

  return {
    id: parseInt(username, 10) || 1,
    username,
    hashedPassword,
    isAdmin: username === 'admin'
  };
}

export async function deleteUserFromDB(userId) {
  console.log(`Deleting user ${userId} from database`);
  return { deleted: true, userId };
}
