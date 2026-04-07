const crypto = require('crypto');
const midtransClient = require('midtrans-client');

function isProduction() {
  return String(process.env.MIDTRANS_IS_PRODUCTION || '').toLowerCase() === 'true';
}

function hasMidtransConfig() {
  return Boolean(process.env.MIDTRANS_CLIENT_KEY && process.env.MIDTRANS_SERVER_KEY);
}

function getMidtransConfig() {
  return {
    isProduction: isProduction(),
    serverKey: process.env.MIDTRANS_SERVER_KEY || '',
    clientKey: process.env.MIDTRANS_CLIENT_KEY || '',
    merchantId: process.env.MIDTRANS_MERCHANT_ID || ''
  };
}

function createSnapClient() {
  const config = getMidtransConfig();
  return new midtransClient.Snap({
    isProduction: config.isProduction,
    serverKey: config.serverKey,
    clientKey: config.clientKey
  });
}

function createCoreApiClient() {
  const config = getMidtransConfig();
  return new midtransClient.CoreApi({
    isProduction: config.isProduction,
    serverKey: config.serverKey,
    clientKey: config.clientKey
  });
}

function getSnapScriptUrl() {
  return isProduction()
    ? 'https://app.midtrans.com/snap/snap.js'
    : 'https://app.sandbox.midtrans.com/snap/snap.js';
}

function verifyMidtransSignature(payload) {
  if (!payload || !process.env.MIDTRANS_SERVER_KEY) return false;
  const expected = crypto
    .createHash('sha512')
    .update(`${payload.order_id}${payload.status_code}${payload.gross_amount}${process.env.MIDTRANS_SERVER_KEY}`)
    .digest('hex');

  return expected === payload.signature_key;
}

module.exports = {
  hasMidtransConfig,
  getMidtransConfig,
  createSnapClient,
  createCoreApiClient,
  getSnapScriptUrl,
  verifyMidtransSignature
};
