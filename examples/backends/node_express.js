// Backend sketch: register/login with the Node SDK.

const { hash, verify } = require("antech-kdf");

function registerUser(password) {
  return hash(password);
}

function loginUser(password, storedHash) {
  return verify(password, storedHash);
}

module.exports = { registerUser, loginUser };
