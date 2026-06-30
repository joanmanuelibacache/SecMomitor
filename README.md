# 🛡️ SecMonitor — Sistema SIEM de Monitoreo y Gestión de Riesgos

SecMonitor es un sistema **SIEM (Security Information and Event Management)** desarrollado desde cero como proyecto personal, orientado a la detección de patrones de ataque, gestión de riesgos de seguridad y generación automática de informes. Desplegado en la nube con Firebase y Render.

---

## 🚀 Demo en vivo

> [https://secmomitor.onrender.com](https://secmonitor.onrender.com)  
> *(el plan gratuito de Render puede tardar ~30s en despertar si lleva tiempo inactivo)*

---

## ✨ Funcionalidades

### 🖥️ Monitoreo en tiempo real
- Detección de patrones de ataque mediante motor de reglas personalizado
- Alertas clasificadas por severidad: **Alta / Media / Baja**
- Actualización automática del dashboard cada 15 segundos
- Gráficos de tendencias: eventos por hora (últimas 24h) y alertas por día (últimos 7 días)
- Botón para limpiar la vista de alertas sin borrar los datos

### 🔍 Reglas de detección implementadas

| Regla | Condición | Severidad |
|---|---|---|
| Fuerza bruta | >5 intentos fallidos desde la misma IP en 5 min | Alta |
| Escaneo de puertos | Conexiones a >10 puertos distintos en 5 min | Media |
| Acceso fuera de horario | Login exitoso entre 00:00 y 05:00 | Baja |
| Múltiples países | Mismo usuario desde >2 países en la misma ventana | Media |

### 🛡️ Gestión de Riesgos
- Matriz de riesgos con proceso completo de 4 fases:
  1. **Identificación** — nombre, descripción, categoría, activos afectados
  2. **Análisis** — puntuación de probabilidad × impacto con previsualización en tiempo real
  3. **Mitigación** — estrategia, responsable, fecha límite y estado
  4. **Riesgo Residual** — cálculo del riesgo remanente tras la mitigación y % de reducción
- Mapa de calor interactivo (5×5) con posicionamiento visual de cada riesgo
- Edición y eliminación de riesgos registrados

### 📄 Informes PDF automáticos
- **Informe de monitoreo** — resumen de eventos, top IPs sospechosas y detalle de alertas altas por período (24h / 7d / 30d)
- **Informe de gestión de riesgos** — portada, resumen ejecutivo, mapa de calor y detalle completo de cada riesgo con sus 4 fases

---

## 🏗️ Arquitectura

```
[Generador de eventos / Parser de logs]
              ↓
    [API REST — Express (Render)]
         ↓              ↓
[Motor de reglas]   [Firestore (Firebase)]
         ↓              ↓
  [Alertas]       [Histórico de eventos]
         ↓
  [Dashboard Web] → [Informes PDF]
```

---

## 🛠️ Stack tecnológico

| Componente | Tecnología |
|---|---|
| Backend / API | Node.js + Express |
| Base de datos | Firebase Firestore |
| Hosting backend | Render (Web Service) |
| Frontend | HTML + CSS + JavaScript vanilla |
| Gráficos | Chart.js |
| Generación PDF | PDFKit |
| Simulación de eventos | Generador propio con motor de reglas |

---

## ⚙️ Instalación local

### Requisitos
- Node.js v18+
- Cuenta en [Firebase](https://console.firebase.google.com) con Firestore activo
- Cuenta en [Render](https://render.com) (para deploy en la nube)

### Pasos

```bash
# 1. Clonar el repositorio
git clone https://github.com/joanmanuelibacache/SecMomitor.git
cd secmonitor

# 2. Instalar dependencias
npm install

# 3. Agregar credenciales de Firebase
# Descarga serviceAccountKey.json desde Firebase Console
# (Configuración del proyecto → Cuentas de servicio → Generar nueva clave privada)
# y colócalo en la raíz del proyecto

# 4. Iniciar el servidor
node server.js
```

Abre [http://localhost:3000](http://localhost:3000) en tu navegador.

---

## 🧪 Tests

El proyecto incluye tests automatizados para verificar el motor de reglas de detección:

```bash
node test.js
```

Verifica 6 casos: generación de eventos, detección correcta de cada patrón de ataque y ausencia de falsos positivos.

---

## 🔭 Roadmap

- [ ] Integración con **AbuseIPDB** para threat intelligence real
- [ ] **Mapeo MITRE ATT&CK** por regla de detección
- [ ] Notificaciones en tiempo real vía **bot de Telegram**
- [ ] **Autenticación** con Firebase Auth
- [ ] **Correlación multi-evento** (kill chain detection)
- [ ] Migración a **logs reales** desde entorno de laboratorio (VM aislada)
- [ ] Exportación a **CSV**

---

## 👤 Autor

**Joan Manuel Castro**  
Técnico en Ciberseguridad | Estudiante de Ingeniería en Informática  
[LinkedIn](https://www.linkedin.com/in/joan-ibacache-2202a8415) · [Hack The Box](https://profile.hackthebox.com/profile/019f06dc-0f00-7262-8808-d4a0ca774091)

---

> ⚠️ Este proyecto es de uso educativo y para entorno de laboratorio controlado. No utilizar en sistemas sin autorización explícita.
