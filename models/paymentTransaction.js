const mongoose = require('mongoose');

const PaymentTransactionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  orderId: { type: String, required: true, unique: true },
  gateway: { type: String, enum: ['midtrans'], default: 'midtrans' },
  kind: { type: String, enum: ['subscription_upgrade'], default: 'subscription_upgrade' },
  plan: { type: String, enum: ['pro'], default: 'pro' },
  billingCycle: { type: String, enum: ['monthly', 'yearly'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, default: 'IDR' },
  status: {
    type: String,
    enum: ['pending', 'paid', 'settlement', 'capture', 'challenge', 'deny', 'cancel', 'expire', 'failure', 'refund', 'partial_refund'],
    default: 'pending'
  },
  paymentMethod: { type: String, default: 'snap' },
  snapToken: { type: String },
  snapRedirectUrl: { type: String },
  midtransTransactionId: { type: String },
  midtransStatusCode: { type: String },
  transactionStatus: { type: String },
  fraudStatus: { type: String },
  paidAt: { type: Date },
  completedAt: { type: Date },
  expiresAt: { type: Date },
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
  rawNotifications: [{ type: mongoose.Schema.Types.Mixed }]
}, { timestamps: true });

PaymentTransactionSchema.index({ user: 1, createdAt: -1 });
PaymentTransactionSchema.index({ status: 1, createdAt: -1 });

module.exports = mongoose.model('PaymentTransaction', PaymentTransactionSchema);
