const alcore = require("alcore");
const crypto = require("crypto");
const scrypt = require("scrypt-js");

class DenseCrypto {
  constructor() {
    this.alcore = alcore();
    this.hashAlgorithm = "sha3-512";
  }

  generateKeyPair() {
    return crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: "spki",
        format: "pem",
      },
      privateKeyEncoding: {
        type: "pkcs8",
        format: "pem",
      },
    });
  }

  encrypt(publicKey, data) {
    const bufferData = Buffer.from(data, "utf8");
    const encryptedData = crypto.publicEncrypt(publicKey, bufferData);
    return encryptedData.toString("base64");
  }

  decrypt(privateKey, encryptedData) {
    const bufferData = Buffer.from(encryptedData, "base64");
    const decryptedData = crypto.privateDecrypt(privateKey, bufferData);
    return decryptedData.toString("utf8");
  }

  sign(privateKey, data) {
    const sign = crypto.createSign("SHA256");
    sign.update(data);
    sign.end();
    const signature = sign.sign(privateKey);
    return signature.toString("hex");
  }

  verify(publicKey, data, signature) {
    const verify = crypto.createVerify("SHA256");
    verify.update(data);
    verify.end();
    const isValid = verify.verify(publicKey, signature, "hex");
    return isValid;
  }

  async deriveKey(password, salt, N = 2 ** 14, r = 8, p = 1) {
    const passwordBuffer = Buffer.from(password, "utf8");
    const saltBuffer = Buffer.from(salt, "utf8");
    const dk = await scrypt.scrypt(passwordBuffer, saltBuffer, N, r, p, 64);
    return dk.toString("hex");
  }

  hash(data) {
    const hash = crypto.createHash(this.hashAlgorithm);
    hash.update(data);
    return hash.digest("hex");
  }

  hmac(key, data) {
    const hmac = crypto.createHmac(this.hashAlgorithm, key);
    hmac.update(data);
    return hmac.digest("hex");
  }
}

module.exports = {
  DenseCrypto,
};