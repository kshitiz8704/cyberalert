const router = require('express').Router();
const PDFDocument = require('pdfkit');
const Alert = require('../models/Alert');

// Only the detection engine (which knows the API key) may create alerts
function requireKey(req, res, next) {
  if (req.header('x-api-key') !== (process.env.API_KEY || 'cyberalert-secret'))
    return res.status(401).json({ error: 'Invalid API key' });
  next();
}

// POST /api/alerts  <- called by Python engine
router.post('/alerts', requireKey, async (req, res) => {
  try { res.status(201).json(await Alert.create(req.body)); }
  catch (e) { res.status(400).json({ error: e.message }); }
});

// GET /api/alerts?severity=&category=&search=&page=&limit=
router.get('/alerts', async (req, res) => {
  const { severity, category, search } = req.query;
  const page = Math.max(parseInt(req.query.page) || 1, 1);
  const limit = Math.min(parseInt(req.query.limit) || 15, 200);
  const q = {};
  if (severity) q.severity = severity;
  if (category) q.category = category;
  if (search) {
    const rx = new RegExp(search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
    q.$or = [{ type: rx }, { source: rx }, { details: rx }];
  }
  const [alerts, total] = await Promise.all([
    Alert.find(q).sort({ timestamp: -1 }).skip((page - 1) * limit).limit(limit),
    Alert.countDocuments(q)
  ]);
  res.json({ alerts, total, page, pages: Math.ceil(total / limit) });
});

// GET /api/stats  <- numbers for dashboard cards and charts
router.get('/stats', async (req, res) => {
  const group = async (f) => {
    const rows = await Alert.aggregate([{ $group: { _id: '$' + f, count: { $sum: 1 } } }, { $sort: { count: -1 } }]);
    return rows.map((r) => ({ name: r._id, count: r.count }));
  };
  const toMap = (rows) => Object.fromEntries(rows.map((r) => [r.name, r.count]));
  const since = new Date(Date.now() - 24 * 3600 * 1000);
  const timeline = await Alert.aggregate([
    { $match: { timestamp: { $gte: since } } },
    { $group: { _id: { $dateToString: { format: '%H:00', date: '$timestamp' } }, count: { $sum: 1 } } },
    { $sort: { _id: 1 } }
  ]);
  res.json({
    total: await Alert.countDocuments(),
    bySeverity: toMap(await group('severity')),
    byCategory: toMap(await group('category')),
    byType: await group('type'),
    timeline: timeline.map((t) => ({ hour: t._id, count: t.count }))
  });
});

// GET /api/report/csv
router.get('/report/csv', async (req, res) => {
  const rows = await Alert.find().sort({ timestamp: -1 }).limit(5000);
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const lines = ['Timestamp,Severity,Category,Type,Source,Host,Details'];
  rows.forEach((a) => lines.push([a.timestamp.toISOString(), a.severity, a.category, a.type, a.source, a.host, a.details].map(esc).join(',')));
  res.set({ 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename=cyberalert_report.csv' });
  res.send(lines.join('\n'));
});

// GET /api/report/pdf
router.get('/report/pdf', async (req, res) => {
  const rows = await Alert.find().sort({ timestamp: -1 }).limit(60);
  const count = (f, v) => Alert.countDocuments({ [f]: v });
  const doc = new PDFDocument({ margin: 40 });
  res.set({ 'Content-Type': 'application/pdf', 'Content-Disposition': 'attachment; filename=cyberalert_report.pdf' });
  doc.pipe(res);
  doc.fontSize(20).text('CyberAlert - Security Report');
  doc.fontSize(10).fillColor('gray').text('Generated: ' + new Date().toLocaleString()).moveDown();
  doc.fillColor('black').fontSize(13).text('Summary');
  doc.fontSize(11).text('Total alerts: ' + (await Alert.countDocuments()));
  for (const s of ['Critical', 'High', 'Medium', 'Low']) doc.text(`${s}: ${await count('severity', s)}`);
  for (const c of ['Malware', 'Host', 'Network']) doc.text(`${c} alerts: ${await count('category', c)}`);
  doc.moveDown().fontSize(13).text('Latest alerts');
  doc.fontSize(8);
  rows.forEach((a) => {
    doc.moveDown(0.4).text(`[${a.timestamp.toLocaleString()}] ${a.severity.toUpperCase()} | ${a.category} | ${a.type} | ${a.source}`);
    if (a.details) doc.fillColor('gray').text('   ' + a.details).fillColor('black');
  });
  doc.end();
});

// DELETE /api/alerts  (clear history, handy for demos)
router.delete('/alerts', requireKey, async (req, res) => {
  await Alert.deleteMany({});
  res.json({ ok: true });
});

module.exports = router;
