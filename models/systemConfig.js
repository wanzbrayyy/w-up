const mongoose = require('mongoose');

const SystemConfigSchema = new mongoose.Schema({
  maintenanceMode: { type: Boolean, default: false },
  globalAnnouncement: { type: String, default: '' },
  adsEnabled: { type: Boolean, default: true },
  adScript: { type: String, default: '' },
  adsTxtContent: { type: String, default: 'google.com, pub-9198935842866616, DIRECT, f08c47fec0942fa0' },
  updatedAt: { type: Date, default: Date.now }
});

SystemConfigSchema.statics.getConfig = async function() {
  let config = await this.findOne();
  if (!config) {
    config = await this.create({});
  }
  return config;
};

module.exports = mongoose.model('SystemConfig', SystemConfigSchema);