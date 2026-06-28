/**
 * SecuMonitor — server.js completo
 * Fases 2 + 3 + Gestión de Riesgos + Informes PDF
 * npm install express firebase-admin cors pdfkit
 */

const express   = require('express');
const cors      = require('cors');
const PDFDoc    = require('pdfkit');
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore }        = require('firebase-admin/firestore');
const { generateEvent, generateBruteForceBurst, generatePortScanBurst, evaluateEvent, EventWindow } = require('./index.js');

// ── FIREBASE ─────────────────────────────────────────────────────────────────
const svcAccount = process.env.FIREBASE_SERVICE_ACCOUNT_JSON
  ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON)
  : require('./serviceAccountKey.json');

initializeApp({ credential: cert(svcAccount) });
const db = getFirestore();
const eventsCol = db.collection('events');
const alertsCol = db.collection('alerts');
const risksCol  = db.collection('risks');

// ── HELPERS ───────────────────────────────────────────────────────────────────
const win5m = new EventWindow(5 * 60 * 1000);

function riskLevel(score) {
  if (score <= 4)  return 'bajo';
  if (score <= 9)  return 'medio';
  if (score <= 14) return 'alto';
  return 'critico';
}

function cellColor(p, i) {           // returns light hex for PDF
  const s = p * i;
  if (s <= 4)  return '#bbf7d0';
  if (s <= 9)  return '#fef08a';
  if (s <= 14) return '#fed7aa';
  return '#fecaca';
}

// ── ABUSEIPDB THREAT INTELLIGENCE ─────────────────────────────────────────────
require('dotenv').config();
const ipCache = new Map();

async function checkAbuseIPDB(ip) {
  if (!process.env.ABUSEIPDB_KEY) return null;
  const cached = ipCache.get(ip);
  if (cached && Date.now() - cached.ts < 3600000) return cached.data; // TTL 1h
  try {
    const res = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      { headers: { Key: process.env.ABUSEIPDB_KEY, Accept: 'application/json' } }
    );
    const { data } = await res.json();
    if (!data) return null;
    const result = {
      score:        data.abuseConfidenceScore,
      totalReports: data.totalReports,
      country:      data.countryCode,
      isp:          data.isp,
      isTor:        data.isTor,
      usageType:    data.usageType,
    };
    ipCache.set(ip, { data: result, ts: Date.now() });
    return result;
  } catch (e) { console.error('AbuseIPDB:', e.message); return null; }
}

async function processEvent(evt) {
  await eventsCol.doc(evt.id).set(evt);
  win5m.add(evt);
  const alerts = evaluateEvent(evt, win5m);
  for (const a of alerts) {
    const abuse = await checkAbuseIPDB(a.sourceIp);
    await alertsCol.add({
      ...a,
      timestamp: new Date().toISOString(),
      status: 'nuevo',
      ...(abuse && { abuse }),
    });
    console.log(`🚨 [${a.severity.toUpperCase()}] ${a.message}${abuse ? ` | AbuseIPDB: ${abuse.score}%` : ''}`);
  }
  return alerts;
}

// ── EXPRESS ───────────────────────────────────────────────────────────────────
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ── MONITORING ROUTES ─────────────────────────────────────────────────────────
app.get('/api/health', (_, res) => res.json({ status: 'ok', ts: new Date().toISOString() }));

app.post('/api/events', async (req, res) => {
  try {
    const evt = { id: `evt_${Date.now()}_${Math.floor(Math.random()*9999)}`, ...req.body, timestamp: req.body.timestamp || new Date().toISOString() };
    const alerts = await processEvent(evt);
    res.status(201).json({ evt, alertsGenerated: alerts.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/events/simulate', async (req, res) => {
  try {
    const evts = [...Array.from({ length: 5 }, () => generateEvent()), ...generateBruteForceBurst(), ...generatePortScanBurst()];
    let total = 0;
    for (const e of evts) total += (await processEvent(e)).length;
    res.json({ eventsGenerated: evts.length, alertsGenerated: total });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/events', async (req, res) => {
  try {
    const snap = await eventsCol.orderBy('timestamp', 'desc').limit(+req.query.limit || 50).get();
    res.json(snap.docs.map(d => d.data()));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/alerts', async (req, res) => {
  try {
    const snap = await alertsCol.orderBy('timestamp', 'desc').limit(+req.query.limit || 50).get();
    res.json(snap.docs.map(d => ({ id: d.id, ...d.data() })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Consulta manual de reputación de IP (usada desde el dashboard y el PDF)
app.get('/api/ip-check/:ip', async (req, res) => {
  try {
    const result = await checkAbuseIPDB(req.params.ip);
    if (!result) return res.status(503).json({ error: 'AbuseIPDB no disponible — configura ABUSEIPDB_KEY' });
    res.json(result);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── RISK ROUTES ───────────────────────────────────────────────────────────────
app.get('/api/risks', async (_, res) => {
  try {
    const snap = await risksCol.orderBy('createdAt', 'desc').get();
    res.json(snap.docs.map(d => ({ id: d.id, ...d.data() })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/risks', async (req, res) => {
  try {
    const d = req.body;
    const score  = (d.probability  || 1) * (d.impact  || 1);
    const rScore = (d.residualProbability || d.probability || 1) * (d.residualImpact || d.impact || 1);
    const risk = { ...d, score, level: riskLevel(score), residualScore: rScore, residualLevel: riskLevel(rScore), status: d.status || 'pendiente', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
    const ref = await risksCol.add(risk);
    res.status(201).json({ id: ref.id, ...risk });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/risks/:id', async (req, res) => {
  try {
    const d = req.body;
    const upd = { ...d, updatedAt: new Date().toISOString() };
    if (d.probability  && d.impact)         { upd.score         = d.probability * d.impact;                 upd.level         = riskLevel(upd.score); }
    if (d.residualProbability && d.residualImpact) { upd.residualScore = d.residualProbability * d.residualImpact; upd.residualLevel = riskLevel(upd.residualScore); }
    await risksCol.doc(req.params.id).update(upd);
    res.json({ id: req.params.id, ...upd });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/risks/:id', async (req, res) => {
  try { await risksCol.doc(req.params.id).delete(); res.json({ deleted: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// ── STATS (para gráficos) ────────────────────────────────────────────────────
app.get('/api/stats', async (req, res) => {
  try {
    const [es, as] = await Promise.all([
      eventsCol.where('timestamp','>=',new Date(Date.now()-86400000).toISOString()).get(),
      alertsCol.where('timestamp','>=',new Date(Date.now()-604800000).toISOString()).get(),
    ]);
    const evtHr = Array(24).fill(0);
    es.docs.forEach(d => { const h=Math.floor((Date.now()-new Date(d.data().timestamp))/3600000); if(h<24)evtHr[23-h]++; });
    const alta=Array(7).fill(0),media=Array(7).fill(0),baja=Array(7).fill(0),lbls=[];
    for(let i=6;i>=0;i--) lbls.push(new Date(Date.now()-i*86400000).toLocaleDateString('es-CL',{weekday:'short',day:'numeric'}));
    as.docs.forEach(d => {
      const {timestamp,severity}=d.data(),di=Math.floor((Date.now()-new Date(timestamp))/86400000);
      if(di<7){const idx=6-di,s=(severity||'baja').toLowerCase();if(s==='alta')alta[idx]++;else if(s==='media')media[idx]++;else baja[idx]++;}
    });
    res.json({
      eventsByHour:{labels:Array.from({length:24},(_,i)=>new Date(Date.now()-(23-i)*3600000).getHours()+':00'),data:evtHr},
      alertsByDay:{labels:lbls,alta,media,baja}
    });
  }catch(e){res.status(500).json({error:e.message});}
});

// ── PDF: MONITORING REPORT ────────────────────────────────────────────────────
app.get('/api/reports/generate', async (req, res) => {
  try {
    const range = req.query.range || '7d';
    const days  = { '1d': 1, '7d': 7, '30d': 30 }[range] || 7;
    const since = new Date(Date.now() - days * 86400000).toISOString();
    const [eSnap, aSnap] = await Promise.all([eventsCol.where('timestamp','>=',since).get(), alertsCol.where('timestamp','>=',since).get()]);
    const evts   = eSnap.docs.map(d => d.data());
    const alerts = aSnap.docs.map(d => d.data());
    const c = { alta: 0, media: 0, baja: 0 };
    const ips = {};
    alerts.forEach(a => { const s = (a.severity||'baja').toLowerCase(); if (c[s]!==undefined) c[s]++; if (a.sourceIp) ips[a.sourceIp] = (ips[a.sourceIp]||0)+1; });
    const topIps = Object.entries(ips).sort((a,b)=>b[1]-a[1]).slice(0,5);
    const lbl = { '1d':'Últimas 24 horas','7d':'Últimos 7 días','30d':'Últimos 30 días' }[range];

    res.setHeader('Content-Type','application/pdf');
    res.setHeader('Content-Disposition',`attachment; filename="secumonitor-monitoreo-${new Date().toISOString().slice(0,10)}.pdf"`);
    const doc = new PDFDoc({ margin: 50 });
    doc.pipe(res);

    doc.fontSize(20).fillColor('#000').text('SecuMonitor — Informe de Monitoreo');
    doc.fontSize(10).fillColor('#555').text(`Periodo: ${lbl}`).text(`Generado: ${new Date().toLocaleString('es-CL')}`);
    doc.moveDown(1.5);
    doc.fontSize(14).fillColor('#000').text('Resumen', { underline: true }).moveDown(0.4);
    doc.fontSize(11).text(`Eventos totales: ${evts.length}`).text(`Alertas: ${alerts.length} (Alta: ${c.alta}, Media: ${c.media}, Baja: ${c.baja})`);
    doc.moveDown(1.2);
    doc.fontSize(14).text('Top IPs sospechosas', { underline: true }).moveDown(0.4);
    if (!topIps.length) doc.fontSize(11).fillColor('#888').text('Sin alertas en este periodo.');
    else topIps.forEach(([ip, n]) => doc.fontSize(11).fillColor('#000').text(`${ip}  —  ${n} alerta(s)`));
    doc.moveDown(1.2);
    doc.fontSize(14).text('Alertas de severidad alta', { underline: true }).moveDown(0.4);
    const altas = alerts.filter(a => (a.severity||'').toLowerCase()==='alta');
    if (!altas.length) doc.fontSize(11).fillColor('#888').text('Sin alertas altas en este periodo.');
    else altas.forEach(a => { doc.fontSize(10).fillColor('#000').text(`[${a.rule}] ${a.message}`); doc.fillColor('#888').text(`IP: ${a.sourceIp||'—'}   ${new Date(a.timestamp).toLocaleString('es-CL')}`).moveDown(0.3); });
    doc.end();
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── PDF: RISK MATRIX REPORT ───────────────────────────────────────────────────
app.get('/api/reports/risks', async (_, res) => {
  try {
    const snap  = await risksCol.orderBy('createdAt','asc').get();
    const risks = snap.docs.map(d => ({ id: d.id, ...d.data() }));

    res.setHeader('Content-Type','application/pdf');
    res.setHeader('Content-Disposition',`attachment; filename="secumonitor-riesgos-${new Date().toISOString().slice(0,10)}.pdf"`);
    const doc = new PDFDoc({ margin: 50, size: 'A4' });
    doc.pipe(res);

    // ── Portada ──
    doc.fontSize(22).fillColor('#1e3a5f').text('SecuMonitor', { align: 'center' });
    doc.fontSize(16).fillColor('#000').text('Informe de Gestión de Riesgos', { align: 'center' });
    doc.fontSize(10).fillColor('#666').text(`Generado: ${new Date().toLocaleString('es-CL')}`, { align: 'center' });
    doc.moveDown(2);

    // ── 1. Resumen ejecutivo ──
    const lvlC = { bajo:0, medio:0, alto:0, critico:0 };
    risks.forEach(r => { if (lvlC[r.level]!==undefined) lvlC[r.level]++; });
    doc.fontSize(13).fillColor('#000').text('1. Resumen Ejecutivo', { underline: true }).moveDown(0.4);
    doc.fontSize(11).text(`Total riesgos identificados: ${risks.length}`)
       .text(`  • Crítico: ${lvlC.critico}  |  Alto: ${lvlC.alto}  |  Medio: ${lvlC.medio}  |  Bajo: ${lvlC.bajo}`);
    doc.moveDown(1.5);

    // ── 2. Mapa de calor ──
    doc.fontSize(13).fillColor('#000').text('2. Mapa de Calor (Probabilidad × Impacto)', { underline: true });
    doc.fontSize(8).fillColor('#666').text('Eje X = Impacto (1→5)  |  Eje Y = Probabilidad (5↑ a 1↓)').moveDown(0.4);

    const csz = 34, hmX = 100, hmY = doc.y;
    for (let p = 5; p >= 1; p--) {
      for (let i = 1; i <= 5; i++) {
        const cx = hmX + (i-1)*csz, cy = hmY + (5-p)*csz;
        doc.rect(cx, cy, csz, csz).fillAndStroke(cellColor(p,i), '#aaa');
        doc.fillColor('#444').fontSize(7).text((p*i).toString(), cx+2, cy+2);
      }
    }
    // Etiquetas P
    for (let p = 5; p >= 1; p--) doc.fillColor('#333').fontSize(9).text(p, hmX-18, hmY+(5-p)*csz+csz/2-4);
    // Etiquetas I
    for (let i = 1; i <= 5; i++) doc.fillColor('#333').fontSize(9).text(i, hmX+(i-1)*csz+csz/2-4, hmY+5*csz+5);
    // Riesgos sobre el mapa
    risks.forEach((r, idx) => {
      const cx = hmX + (r.impact-1)*csz + csz/2, cy = hmY + (5-r.probability)*csz + csz/2;
      doc.circle(cx, cy, 9).fill('#1e3a5f');
      doc.fillColor('#fff').fontSize(7).text((idx+1).toString(), cx-9, cy-4, { width: 18, align: 'center' });
    });
    // Leyenda
    const lgY = hmY + 5*csz + 22;
    [['#bbf7d0','Bajo'],['#fef08a','Medio'],['#fed7aa','Alto'],['#fecaca','Crítico']].forEach(([c,l],i) => {
      doc.rect(hmX+i*100, lgY, 10, 10).fillAndStroke(c,'#aaa');
      doc.fillColor('#333').fontSize(8).text(l, hmX+i*100+13, lgY+1);
    });
    // Mover cursor bajo el mapa
    doc.text(' ', 50, lgY+22, { lineBreak: false });
    doc.moveDown(1.5);

    // ── 3. Detalle por riesgo ──
    doc.addPage();
    doc.fontSize(13).fillColor('#000').text('3. Detalle de Riesgos por Fase', { underline: true }).moveDown(0.8);

    const lvlHex = { bajo:'#15803d', medio:'#a16207', alto:'#c2410c', critico:'#b91c1c' };
    risks.forEach((r, idx) => {
      if (doc.y > 680) doc.addPage();
      const lvl = r.level || 'bajo';
      doc.fontSize(12).fillColor(lvlHex[lvl]||'#000').text(`${idx+1}. ${r.name}`).moveDown(0.2);

      // Fase 1 - Identificación
      doc.fontSize(8).fillColor('#888').text('FASE 1 — IDENTIFICACIÓN');
      doc.fontSize(10).fillColor('#000').text(`Categoría: ${r.category||'—'}   |   Activos: ${r.assets||'—'}`).text(`${r.description||'Sin descripción.'}`).moveDown(0.4);

      // Fase 2 - Análisis
      doc.fontSize(8).fillColor('#888').text('FASE 2 — ANÁLISIS');
      doc.fontSize(10).fillColor('#000').text(`Probabilidad: ${r.probability}/5   ×   Impacto: ${r.impact}/5   =   Puntuación: ${r.score}   →   Nivel: ${lvl.toUpperCase()}`).moveDown(0.4);

      // Fase 3 - Mitigación
      doc.fontSize(8).fillColor('#888').text('FASE 3 — MITIGACIÓN');
      doc.fontSize(10).fillColor('#000')
         .text(`Estrategia: ${r.mitigation||'No definida'}`)
         .text(`Responsable: ${r.responsible||'—'}   |   Fecha: ${r.deadline||'—'}   |   Estado: ${(r.status||'pendiente').replace('_',' ')}`).moveDown(0.4);

      // Fase 4 - Riesgo residual
      doc.fontSize(8).fillColor('#888').text('FASE 4 — RIESGO RESIDUAL');
      const red = r.score ? Math.round((1 - r.residualScore/r.score)*100) : 0;
      doc.fontSize(10).fillColor('#000').text(`Prob. residual: ${r.residualProbability}/5   ×   Impacto residual: ${r.residualImpact}/5   =   Puntuación: ${r.residualScore}   →   Nivel: ${(r.residualLevel||'—').toUpperCase()}`);
      if (red > 0) doc.fillColor('#15803d').text(`↓ Reducción del riesgo: ${red}%`);
      doc.fillColor('#000').moveDown(0.8);
      doc.strokeColor('#ddd').lineWidth(0.5).moveTo(50, doc.y).lineTo(545, doc.y).stroke();
      doc.moveDown(0.6);
    });

    doc.end();
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── START ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ SecuMonitor en http://localhost:${PORT}`));
