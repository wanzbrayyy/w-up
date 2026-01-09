const mongoose = require('mongoose');

const UploadSessionSchema = new mongoose.Schema({
  sessionId: { type: String, required: true, unique: true },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  filename: String,
  totalSize: Number,
  uploadedSize: { type: Number, default: 0 },
  chunks: [{
    index: Number,
    data: String 
  }],
  createdAt: { type: Date, default: Date.now, expires: 86400 } 
});

module.exports = mongoose.model('UploadSession', UploadSessionSchema);