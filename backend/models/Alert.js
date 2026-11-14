const mongoose = require('mongoose');

const alertSchema = new mongoose.Schema({
  category: { type: String, enum: ['Malware', 'Host', 'Network'], required: true },
  type:     { type: String, required: true },            // e.g. "Port Scan"
  severity: { type: String, enum: ['Low', 'Medium', 'High', 'Critical'], required: true },
  source:   { type: String, default: 'unknown' },        // IP address or file path
  host:     { type: String, default: 'unknown' },        // machine that raised the alert
  details:  { type: String, default: '' },
  timestamp:{ type: Date, default: Date.now, index: true }
});

module.exports = mongoose.model('Alert', alertSchema);
