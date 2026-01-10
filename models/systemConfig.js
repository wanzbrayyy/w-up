const mongoose = require('mongoose');

const SystemConfigSchema = new mongoose.Schema({
  maintenanceMode: { type: Boolean, default: false },
  globalAnnouncement: { type: String, default: '' }, 
  adsEnabled: { type: Boolean, default: true },
  adScript: { type: String, default: '<!-- Place AdSense Code Here -->' },
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