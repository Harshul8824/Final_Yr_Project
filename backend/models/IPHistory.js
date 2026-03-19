const mongoose = require('mongoose');

const ipHistorySchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  userEmail: { 
    type: String, 
    required: true 
  },
  ip: { 
    type: String, 
    required: true 
  },
  checkedAt: { 
    type: Date, 
    default: Date.now 
  },
  results: {
    qualityScore: {
      isVPN: Boolean,
      isProxy: Boolean,
      isTor: Boolean,
      fraudScore: Number,
    },
    localIPSearch: {
      result: Number,
      proxyType: String,
      country: String,
      isp: String,
    },
    vpnListCheck: {
      result: Number,
      matchedIP: String,
    },
    onlineDataCheck: {
      result: Number,
      threatType: String,
    },
    portScan: {
      status: String,
      openPortsCount: Number,
    }
  },
  overallRisk: { 
    type: String, 
    enum: ['Low', 'Medium', 'High'], 
    default: 'Low' 
  }
});

module.exports = mongoose.model('IPHistory', ipHistorySchema);
