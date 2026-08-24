// Backend Integration Example: Node.js + Express
// Demonstrates strictly where hashPassword() and verifyPassword() are invoked.

const { hashPassword, verifyPassword } = require("antech-kdf");

async function registerUser(password) {
  return await hashPassword(password);
}

async function loginUser(password, storedHash) {
  return await verifyPassword(password, storedHash);
}

module.exports = { registerUser, loginUser };
