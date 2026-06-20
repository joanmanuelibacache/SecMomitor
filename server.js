/**
 * SecuMonitor - Fase 2: API Backend + Conexión a Firestore
 *
 * Requisitos antes de correr esto (ver guía completa en el chat):
 * 1. Crear proyecto en https://console.firebase.google.com
 * 2. Activar Firestore Database
 * 3. Generar y descargar "serviceAccountKey.json" (Configuración → Cuentas de servicio)
 * 4. Instalar dependencias: npm install express firebase-admin cors
 *
 * Estructura del proyecto en este punto:
 *   /secumonitor
 *     index.js                (Fase 1: generador + motor de reglas)
 *     test.js                 (Fase 1: tests)
 *     server.js               (este archivo)
 *     serviceAccountKey.json  (NO subir a git — agregar a .gitignore)
 *     .gitignore
 *
 * Ejecutar con: node server.js
 */

const express = require('express');
const cors = require('cors');
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');

const {
  generateEvent,
  generateBruteForceBurst,
  generatePortScanBurst,
  evaluateEvent,
  EventWindow,
} = require('./index.js');

// ============================================================
// 1. INICIALIZAR FIREBASE (API modular, recomendada desde v10+)
// ============================================================

// En Render no podemos subir serviceAccountKey.json (está en .gitignore).
// En su lugar, usamos una variable de entorno con el JSON completo.
// Localmente, si no existe la variable, cae al archivo local.
const serviceAccount = process.env.FIREBASE_SERVICE_ACCOUNT_JSON
  ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON)
  : require('./serviceAccountKey.json');

initializeApp({
  credential: cert(serviceAccount),
});

const db = getFirestore();
const eventsCollection = db.collection('events');
const alertsCollection = db.collection('alerts');

// ============================================================
// 2. VENTANA EN MEMORIA PARA EVALUACIÓN RÁPIDA DE REGLAS
// ============================================================
// Evitamos leer Firestore en cada evento (sería lento y costoso).
// La ventana vive en memoria del proceso; Firestore guarda el histórico
// completo para el futuro dashboard e informes.

const window5min = new EventWindow(5 * 60 * 1000);

// ============================================================
// 3. PROCESAMIENTO DE EVENTOS
// ============================================================

async function processEvent(event) {
  // Guardar el evento en Firestore
  await eventsCollection.doc(event.id).set(event);

  // Evaluar contra las reglas de detección
  window5min.add(event);
  const alerts = evaluateEvent(event, window5min);

  // Guardar las alertas generadas
  for (const alert of alerts) {
    const alertDoc = {
      ...alert,
      timestamp: new Date().toISOString(),
      status: 'nuevo', // nuevo | revisado | falso_positivo
    };
    await alertsCollection.add(alertDoc);
    console.log(`🚨 [${alert.severity.toUpperCase()}] ${alert.message}`);
  }

  return alerts;
}

// ============================================================
// 4. SERVIDOR EXPRESS
// ============================================================

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // sirve el dashboard (public/index.html)

// Health check — útil para verificar que el servidor (o Render más adelante) está vivo
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Ingesta de un evento individual.
// Más adelante, tu VM/parser de logs reales llamará a este endpoint.
app.post('/api/events', async (req, res) => {
  try {
    const event = {
      id: `evt_${Date.now()}_${Math.floor(Math.random() * 10000)}`,
      ...req.body,
      timestamp: req.body.timestamp || new Date().toISOString(),
    };
    const alerts = await processEvent(event);
    res.status(201).json({ event, alertsGenerated: alerts.length });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error procesando el evento' });
  }
});

// Dispara una simulación completa (útil para seguir probando sin la VM lista)
app.post('/api/events/simulate', async (req, res) => {
  try {
    const events = [
      ...Array.from({ length: 5 }, () => generateEvent()),
      ...generateBruteForceBurst(),
      ...generatePortScanBurst(),
    ];

    let totalAlerts = 0;
    for (const event of events) {
      const alerts = await processEvent(event);
      totalAlerts += alerts.length;
    }

    res.json({ eventsGenerated: events.length, alertsGenerated: totalAlerts });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error en la simulación' });
  }
});

// Listar eventos recientes (lo usará el dashboard en la Fase 3)
app.get('/api/events', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const snapshot = await eventsCollection
      .orderBy('timestamp', 'desc')
      .limit(limit)
      .get();
    const events = snapshot.docs.map(doc => doc.data());
    res.json(events);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error obteniendo eventos' });
  }
});

// Listar alertas recientes (lo usará el dashboard en la Fase 3)
app.get('/api/alerts', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const snapshot = await alertsCollection
      .orderBy('timestamp', 'desc')
      .limit(limit)
      .get();
    const alerts = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    res.json(alerts);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error obteniendo alertas' });
  }
});

// ============================================================
// 5. INICIAR SERVIDOR
// ============================================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ SecuMonitor backend corriendo en http://localhost:${PORT}`);
  console.log(`   Prueba: POST http://localhost:${PORT}/api/events/simulate`);
});