const mongoose = require('mongoose');

const CollaboratorSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  role: { type: String, enum: ['viewer', 'uploader', 'editor'], default: 'viewer' }
}, { _id: false });

const ShareLinkSchema = new mongoose.Schema({
  linkId: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  password: { type: String },
  expiresAt: { type: Date }
});

const SignatureRequestSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  status: { type: String, enum: ['pending', 'signed', 'declined'], default: 'pending' },
  signedAt: { type: Date },
  signedFileR2Key: { type: String }
});

const AnnotationSchema = new mongoose.Schema({
  type: { type: String, required: true }, // 'comment', 'drawing'
  data: { type: mongoose.Schema.Types.Mixed },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now }
});

const FileSchema = new mongoose.Schema({
  originalName: { type: String, required: true },
  customAlias: { type: String, required: true, unique: true },
  contentType: { type: String, required: true },
  size: { type: Number, required: true },
  base64: { type: String, required: false },
  storageType: { type: String, enum: ['mongo', 'r2'], default: 'r2' },
  r2Key: { type: String },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  isFolder: { type: Boolean, default: false },
  parentId: { type: mongoose.Schema.Types.ObjectId, ref: 'File', default: null },
  downloads: { type: Number, default: 0 },
  downloadHistory: [{ date: Date, count: Number }],
  lastDownloadedAt: { type: Date },
  password: { type: String },
  passwordHint: { type: String },
  expiresAt: { type: Date },
  downloadLimit: { type: Number },
  isBurnAfterRead: { type: Boolean, default: false },
  sha256Hash: { type: String },
  md5Hash: { type: String },
  virusScan: {
    status: { type: String, enum: ['unscanned', 'clean', 'infected', 'scanning'], default: 'unscanned' },
    lastChecked: Date,
    permalink: String
  },
  collaborators: [CollaboratorSchema],
  shareLinks: [ShareLinkSchema],
  signatureRequests: [SignatureRequestSchema],
  annotations: [AnnotationSchema],
  sharedWithTeams: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Team' }],
  comments: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    username: String,
    text: String,
    mentions: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    createdAt: { type: Date, default: Date.now }
  }],
  reactions: {
    like: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    love: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
  },
  accessRequests: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    requestedAt: { type: Date, default: Date.now }
  }],
  allowedGeo: {
    lat: Number,
    long: Number,
    radiusKm: Number
  },
  deletedAt: { type: Date, default: null },
  isStarred: { type: Boolean, default: false },
  isHidden: { type: Boolean, default: false },
  tags: [{ type: String }],
  description: { type: String, default: '' },
  versions: [{
    version: Number,
    r2Key: String, 
    uploadedAt: { type: Date, default: Date.now },
    size: Number
  }],
  reports: [{
    reason: String,
    reportedAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

FileSchema.index({ owner: 1, parentId: 1, deletedAt: 1 });

module.exports = mongoose.model('File', FileSchema);
