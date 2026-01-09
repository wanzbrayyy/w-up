const mongoose = require('mongoose');

const FileRequestSchema = new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  slug: { type: String, required: true, unique: true },
  label: { type: String, required: true },
  destinationFolder: { type: mongoose.Schema.Types.ObjectId, ref: 'File' },
  expiresAt: { type: Date },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('FileRequest', FileRequestSchema);