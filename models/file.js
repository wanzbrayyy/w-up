const mongoose = require('mongoose');

const FileSchema = new mongoose.Schema({
  originalName: { type: String, required: true },
  customAlias: { type: String, required: true, unique: true },
  contentType: { type: String, required: true },
  size: { type: Number, required: true },
  base64: { type: String, required: true },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  downloads: { type: Number, default: 0 },
  password: { type: String },
  expiresAt: { type: Date },
  downloadLimit: { type: Number },
  reports: [{
    reason: String,
    reportedAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('File', FileSchema);