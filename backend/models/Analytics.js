const mongoose = require('mongoose');

const analyticsSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true, 
    unique: true 
  },
  userEmail: { 
    type: String, 
    required: true 
  },
  totalChecks: { type: Number, default: 0 },
  vpnDetected: { type: Number, default: 0 },
  cleanIPs: { type: Number, default: 0 },
  
  riskBreakdown: {
    High: { type: Number, default: 0 },
    Medium: { type: Number, default: 0 },
    Low: { type: Number, default: 0 }
  },
  
  threatTypes: {
    TOR: { type: Number, default: 0 },
    VPN: { type: Number, default: 0 },
    PROXY: { type: Number, default: 0 },
    Clean: { type: Number, default: 0 }
  },
  
  lastUpdated: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Analytics', analyticsSchema);
