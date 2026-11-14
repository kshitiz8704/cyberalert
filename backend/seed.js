// Fills the DB with sample alerts so the dashboard can be shown without running the engine
require('dotenv').config();
const mongoose = require('mongoose');
const Alert = require('./models/Alert');

const samples = [
  ['Malware', 'Known Malware Hash', 'Critical', 'C:/Users/test/Downloads/setup.exe', 'SHA-256 matches known malicious hash'],
  ['Malware', 'YARA Rule Match', 'High', '/tmp/payload.ps1', 'Rule Suspicious_PowerShell_Download matched'],
  ['Malware', 'High Entropy File', 'Medium', 'D:/files/data.bin', 'Entropy 7.8 - file may be packed/encrypted'],
  ['Host', 'File Modified', 'Medium', '/etc/hosts', 'Watched file content changed'],
  ['Host', 'File Deleted', 'High', '/var/www/index.php', 'Watched file was deleted'],
  ['Host', 'Brute Force Login', 'High', '192.168.1.50', '8 failed logins in 60s'],
  ['Host', 'Suspicious Process', 'High', 'nc.exe', 'Blacklisted process name running (pid 4120)'],
  ['Network', 'Port Scan', 'High', '10.0.0.23', '22 distinct ports probed in 10s'],
  ['Network', 'Repeated Connections', 'Medium', '10.0.0.77', '40 SYN packets to 10.0.0.5:22 in 10s'],
  ['Network', 'ICMP Flood', 'Medium', '10.0.0.99', '60 ping requests in 10s'],
  ['Network', 'Suspicious DNS Query', 'Low', '192.168.1.12', 'Very long / random-looking domain name']
];
const r = (n) => Math.floor(Math.random() * n);

(async () => {
  await mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/cyberalert');
  const docs = Array.from({ length: 70 }, () => {
    const [category, type, severity, source, details] = samples[r(samples.length)];
    return { category, type, severity, source, details, host: 'demo-pc', timestamp: new Date(Date.now() - r(24 * 3600 * 1000)) };
  });
  await Alert.insertMany(docs);
  console.log('Inserted', docs.length, 'sample alerts');
  process.exit(0);
})();
