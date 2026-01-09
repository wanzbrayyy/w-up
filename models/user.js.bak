const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  password: { type: String, required: true },
  isTwoFactorEnabled: { type: Boolean, default: false },
  twoFactorSecret: {
    ascii: String,
    otpauth_url: String
  },
  apiKeys: [{
    key: String,
    label: String,
    createdAt: { type: Date, default: Date.now }
  }],
  loginHistory: [{
    ip: String,
    userAgent: String,
    date: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

UserSchema.methods.comparePassword = function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', UserSchema);