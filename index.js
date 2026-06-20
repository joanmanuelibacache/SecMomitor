/**
 * SecuMonitor - Fase 1
 * Generador de eventos simulados + Motor de reglas de detección
 *
 * Estructura sugerida del proyecto (para cuando lo separes en archivos):
 *   /src
 *     eventGenerator.js
 *     detectionRules.js
 *     store.js
 *     index.js
 *   package.json
 *
 * Por ahora todo está en un solo archivo para que puedas probarlo rápido.
 * Ejecutar con: node index.js
 */

// ============================================================
// 1. GENERADOR DE EVENTOS SIMULADOS
// ============================================================

const EVENT_TYPES = ['login_failed', 'login_success', 'port_scan', 'connection'];

const FAKE_IPS = [
  '203.0.113.45', '198.51.100.23', '192.0.2.77',
  '45.142.120.9', '185.220.101.4', '91.219.236.18',
  '8.8.8.8', '1.1.1.1' // IPs "limpias" para contraste
];

const COUNTRIES = ['CL', 'AR', 'RU', 'CN', 'US', 'NL', 'BR'];

function randomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomPort() {
  const commonPorts = [22, 80, 443, 21, 3389, 8080, 3306, 5432];
  return Math.random() < 0.5 ? randomItem(commonPorts) : Math.floor(Math.random() * 65535);
}

/**
 * Genera un evento simulado individual.
 * En la versión con VM real, esto se reemplaza por un parser de logs
 * (ver nota "logParser" al final del archivo).
 */
function generateEvent() {
  const type = randomItem(EVENT_TYPES);
  const ip = randomItem(FAKE_IPS);

  return {
    id: `evt_${Date.now()}_${Math.floor(Math.random() * 10000)}`,
    type,
    sourceIp: ip,
    country: randomItem(COUNTRIES),
    port: type === 'port_scan' || type === 'connection' ? randomPort() : 22,
    user: type.startsWith('login') ? randomItem(['admin', 'root', 'jcastro', 'test']) : null,
    timestamp: new Date().toISOString(),
  };
}

/**
 * Genera una ráfaga de eventos para simular un ataque de fuerza bruta
 * desde una sola IP (útil para probar las reglas de detección).
 */
function generateBruteForceBurst(ip = randomItem(FAKE_IPS), count = 8) {
  const events = [];
  for (let i = 0; i < count; i++) {
    events.push({
      id: `evt_${Date.now()}_${i}`,
      type: 'login_failed',
      sourceIp: ip,
      country: randomItem(COUNTRIES),
      port: 22,
      user: 'admin',
      timestamp: new Date().toISOString(),
    });
  }
  return events;
}

/**
 * Genera una ráfaga de eventos para simular escaneo de puertos.
 */
function generatePortScanBurst(ip = randomItem(FAKE_IPS), portCount = 12) {
  const events = [];
  // Puertos consecutivos en vez de aleatorios puros: garantiza que todos
  // sean únicos (y un escaneo real también suele ser secuencial,
  // ej. nmap recorriendo puertos 1000-1011).
  const startPort = Math.floor(Math.random() * 50000) + 1000;
  for (let i = 0; i < portCount; i++) {
    events.push({
      id: `evt_${Date.now()}_scan_${i}`,
      type: 'port_scan',
      sourceIp: ip,
      country: randomItem(COUNTRIES),
      port: startPort + i,
      user: null,
      timestamp: new Date().toISOString(),
    });
  }
  return events;
}

// ============================================================
// 2. MOTOR DE REGLAS DE DETECCIÓN
// ============================================================

/**
 * Ventana de eventos en memoria para evaluar patrones temporales.
 * En la versión con Firestore (Fase 2), esto se reemplaza por consultas
 * a la colección "events" filtrando por timestamp.
 */
class EventWindow {
  constructor(windowMs = 5 * 60 * 1000) {
    this.windowMs = windowMs;
    this.events = [];
  }

  add(event) {
    this.events.push(event);
    this._prune();
  }

  _prune() {
    const cutoff = Date.now() - this.windowMs;
    this.events = this.events.filter(e => new Date(e.timestamp).getTime() >= cutoff);
  }

  getByIp(ip) {
    return this.events.filter(e => e.sourceIp === ip);
  }
}

const window5min = new EventWindow(5 * 60 * 1000);

/**
 * Reglas de detección. Cada regla recibe el evento nuevo + la ventana
 * de eventos recientes, y devuelve una alerta (o null si no aplica).
 */
const RULES = [
  {
    name: 'fuerza_bruta',
    severity: 'alta',
    evaluate(event, win) {
      if (event.type !== 'login_failed') return null;
      const recent = win.getByIp(event.sourceIp).filter(e => e.type === 'login_failed');
      if (recent.length >= 5) {
        return {
          rule: 'fuerza_bruta',
          severity: 'alta',
          message: `${recent.length} intentos fallidos de login desde ${event.sourceIp} en los últimos 5 min`,
          sourceIp: event.sourceIp,
        };
      }
      return null;
    },
  },
  {
    name: 'escaneo_puertos',
    severity: 'media',
    evaluate(event, win) {
      if (event.type !== 'port_scan' && event.type !== 'connection') return null;
      const recent = win.getByIp(event.sourceIp);
      const uniquePorts = new Set(recent.map(e => e.port));
      if (uniquePorts.size >= 10) {
        return {
          rule: 'escaneo_puertos',
          severity: 'media',
          message: `Conexiones a ${uniquePorts.size} puertos distintos desde ${event.sourceIp} en los últimos 5 min`,
          sourceIp: event.sourceIp,
        };
      }
      return null;
    },
  },
  {
    name: 'acceso_fuera_horario',
    severity: 'baja',
    evaluate(event) {
      if (event.type !== 'login_success') return null;
      const hour = new Date(event.timestamp).getHours();
      if (hour >= 0 && hour < 5) {
        return {
          rule: 'acceso_fuera_horario',
          severity: 'baja',
          message: `Login exitoso fuera de horario habitual (${hour}:00) desde ${event.sourceIp}`,
          sourceIp: event.sourceIp,
        };
      }
      return null;
    },
  },
  {
    name: 'multiples_paises',
    severity: 'media',
    evaluate(event, win) {
      if (event.type !== 'login_success' || !event.user) return null;
      const recentByUser = win.events.filter(
        e => e.user === event.user && e.type === 'login_success'
      );
      const countries = new Set(recentByUser.map(e => e.country));
      if (countries.size > 2) {
        return {
          rule: 'multiples_paises',
          severity: 'media',
          message: `Usuario "${event.user}" con logins desde ${countries.size} países distintos`,
          sourceIp: event.sourceIp,
        };
      }
      return null;
    },
  },
];

/**
 * Evalúa un evento contra todas las reglas activas.
 * Devuelve un array de alertas (puede estar vacío).
 */
function evaluateEvent(event, win) {
  return RULES
    .map(rule => rule.evaluate(event, win))
    .filter(alert => alert !== null);
}

// ============================================================
// 3. ALMACENAMIENTO (placeholder — se conecta a Firestore en Fase 2)
// ============================================================

const eventStore = [];
const alertStore = [];

function saveEvent(event) {
  eventStore.push(event);
  // TODO Fase 2: reemplazar por
  // await db.collection('events').doc(event.id).set(event);
}

function saveAlert(alert) {
  alertStore.push({ ...alert, id: `alert_${Date.now()}`, timestamp: new Date().toISOString() });
  // TODO Fase 2: reemplazar por
  // await db.collection('alerts').add(alert);
}

// ============================================================
// 4. LOOP PRINCIPAL DE SIMULACIÓN
// ============================================================

function processEvent(event) {
  saveEvent(event);
  window5min.add(event);

  const alerts = evaluateEvent(event, window5min);
  alerts.forEach(alert => {
    saveAlert(alert);
    console.log(`🚨 [${alert.severity.toUpperCase()}] ${alert.message}`);
  });
}

function runSimulation() {
  console.log('=== SecuMonitor - Simulación Fase 1 ===\n');

  // Tráfico normal de fondo
  for (let i = 0; i < 10; i++) {
    processEvent(generateEvent());
  }

  console.log('\n--- Simulando ataque de fuerza bruta ---');
  generateBruteForceBurst().forEach(processEvent);

  console.log('\n--- Simulando escaneo de puertos ---');
  generatePortScanBurst().forEach(processEvent);

  console.log('\n=== Resumen ===');
  console.log(`Eventos totales: ${eventStore.length}`);
  console.log(`Alertas generadas: ${alertStore.length}`);
}

// Solo corre la simulación si se ejecuta directamente (node index.js),
// no cuando otro archivo lo importa con require() — esto permite testearlo.
if (require.main === module) {
  runSimulation();
}

// ============================================================
// NOTA: Migración futura a logs reales de una VM (laboratorio aislado)
// ============================================================
// function logParser(line) {
//   // Ejemplo para auth.log de Linux:
//   // "Failed password for admin from 192.168.56.10 port 51234 ssh2"
//   const match = line.match(/Failed password for (\S+) from (\S+) port (\d+)/);
//   if (match) {
//     return {
//       id: `evt_${Date.now()}`,
//       type: 'login_failed',
//       sourceIp: match[2],
//       user: match[1],
//       port: 22,
//       country: 'desconocido', // se podría resolver con ip-api.com
//       timestamp: new Date().toISOString(),
//     };
//   }
//   return null;
// }
// Se conectaría con fs.watch() o un stream tailing /var/log/auth.log

module.exports = {
  generateEvent,
  generateBruteForceBurst,
  generatePortScanBurst,
  evaluateEvent,
  RULES,
  EventWindow,
};