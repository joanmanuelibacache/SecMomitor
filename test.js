/**
 * SecuMonitor - Fase 1: Tests de verificación
 *
 * Verifica que el generador de eventos y el motor de reglas
 * funcionan correctamente antes de pasar a la Fase 2.
 *
 * Requisito: tener index.js (el código de Fase 1) en la misma carpeta.
 * Ejecutar con: node test.js
 */

const assert = require('assert');
const {
  generateEvent,
  generateBruteForceBurst,
  generatePortScanBurst,
  evaluateEvent,
  EventWindow,
} = require('./index.js');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`✅ PASS: ${name}`);
    passed++;
  } catch (err) {
    console.log(`❌ FAIL: ${name}`);
    console.log(`   → ${err.message}`);
    failed++;
  }
}

// ------------------------------------------------------------
// Test 1: generateEvent() devuelve un evento con forma válida
// ------------------------------------------------------------
test('generateEvent() devuelve un objeto con los campos esperados', () => {
  const event = generateEvent();
  assert.ok(event.id, 'falta id');
  assert.ok(event.type, 'falta type');
  assert.ok(event.sourceIp, 'falta sourceIp');
  assert.ok(event.timestamp, 'falta timestamp');
});

// ------------------------------------------------------------
// Test 2: Regla de fuerza bruta se dispara con 5+ intentos fallidos
// ------------------------------------------------------------
test('Detecta fuerza bruta con 5+ intentos fallidos desde la misma IP', () => {
  const win = new EventWindow();
  const burst = generateBruteForceBurst('10.0.0.99', 6);

  let alertaFuerzaBruta = null;
  burst.forEach(event => {
    win.add(event);
    const alerts = evaluateEvent(event, win);
    const found = alerts.find(a => a.rule === 'fuerza_bruta');
    if (found) alertaFuerzaBruta = found;
  });

  assert.ok(alertaFuerzaBruta, 'no se generó alerta de fuerza_bruta');
  assert.strictEqual(alertaFuerzaBruta.severity, 'alta');
  assert.strictEqual(alertaFuerzaBruta.sourceIp, '10.0.0.99');
});

// ------------------------------------------------------------
// Test 3: NO se dispara fuerza bruta con pocos intentos (evita falsos positivos)
// ------------------------------------------------------------
test('NO detecta fuerza bruta con solo 2 intentos fallidos', () => {
  const win = new EventWindow();
  const burst = generateBruteForceBurst('10.0.0.50', 2);

  let disparo = false;
  burst.forEach(event => {
    win.add(event);
    const alerts = evaluateEvent(event, win);
    if (alerts.some(a => a.rule === 'fuerza_bruta')) disparo = true;
  });

  assert.strictEqual(disparo, false, 'se disparó fuerza_bruta con solo 2 intentos (falso positivo)');
});

// ------------------------------------------------------------
// Test 4: Regla de escaneo de puertos se dispara con 10+ puertos distintos
// ------------------------------------------------------------
test('Detecta escaneo de puertos con 10+ puertos distintos desde la misma IP', () => {
  const win = new EventWindow();
  const burst = generatePortScanBurst('10.0.0.77', 12);

  let alertaEscaneo = null;
  burst.forEach(event => {
    win.add(event);
    const alerts = evaluateEvent(event, win);
    const found = alerts.find(a => a.rule === 'escaneo_puertos');
    if (found) alertaEscaneo = found;
  });

  assert.ok(alertaEscaneo, 'no se generó alerta de escaneo_puertos');
  assert.strictEqual(alertaEscaneo.severity, 'media');
});

// ------------------------------------------------------------
// Test 5: Regla de acceso fuera de horario (madrugada)
// ------------------------------------------------------------
test('Detecta login exitoso fuera de horario (madrugada)', () => {
  const win = new EventWindow();
  const event = {
    id: 'evt_test_horario',
    type: 'login_success',
    sourceIp: '10.0.0.20',
    country: 'CL',
    port: 22,
    user: 'jcastro',
    timestamp: new Date(new Date().setHours(3, 0, 0, 0)).toISOString(),
  };

  win.add(event);
  const alerts = evaluateEvent(event, win);
  const found = alerts.find(a => a.rule === 'acceso_fuera_horario');

  assert.ok(found, 'no se generó alerta de acceso_fuera_horario para login a las 3 AM');
});

// ------------------------------------------------------------
// Test 6: Regla de múltiples países para un mismo usuario
// ------------------------------------------------------------
test('Detecta logins desde múltiples países para el mismo usuario', () => {
  const win = new EventWindow();
  const countries = ['CL', 'RU', 'CN'];
  let lastAlerts = [];

  countries.forEach((country, i) => {
    const event = {
      id: `evt_test_pais_${i}`,
      type: 'login_success',
      sourceIp: `10.0.0.${i}`,
      country,
      port: 22,
      user: 'mismo_usuario',
      timestamp: new Date().toISOString(),
    };
    win.add(event);
    lastAlerts = evaluateEvent(event, win);
  });

  const found = lastAlerts.find(a => a.rule === 'multiples_paises');
  assert.ok(found, 'no se generó alerta de multiples_paises tras 3 países distintos');
});

// ------------------------------------------------------------
// Resumen
// ------------------------------------------------------------
console.log('\n========================================');
console.log(`Resultado: ${passed} pasaron, ${failed} fallaron`);
console.log('========================================');

if (failed > 0) {
  process.exit(1);
}
