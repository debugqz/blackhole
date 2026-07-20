# BLACKHOLE — Especificación Técnica v0.1

> Plataforma de mensajería privada P2P con cifrado E2EE real, sin custodia central de datos, sin moderación de contenido, sostenida por suscripción cosmética pagada en criptomonedas.

Este documento es el contexto base del proyecto. Está pensado para entregarse a un agente de desarrollo (Claude Code) como punto de partida. Recoge todas las decisiones de arquitectura ya tomadas, el razonamiento detrás de cada una, y lo que queda explícitamente pendiente.

---

## 0. Visión y alcance

Blackhole es un referente en privacidad real, no en privacidad de marketing. La comparación honesta no es "como Telegram" — es más cercana a Signal + Session + Tor, combinados. Los tres pilares no negociables:

1. **Zero-knowledge real**: ni el operador de la plataforma puede leer contenido ni reconstruir con quién habla cada usuario.
2. **Sin autoridad central de moderación de contenido**: no se escanea ni se lee ningún mensaje, nunca, bajo ninguna circunstancia.
3. **Sin ánimo de lucro sobre la privacidad**: el core de mensajería es y será siempre gratuito. El negocio vive en personalización cosmética, no en vender "más seguridad".

---

## 1. Modelo de amenaza

Protegemos al usuario contra:
- La propia plataforma/operador (zero-knowledge por diseño, no por política).
- Terceros que interceptan tráfico de red (cifrado en tránsito + onion routing).
- Compromiso de un nodo intermedio de la red (ningún nodo individual puede leer contenido ni, idealmente, metadata completa).
- Análisis de metadata y correlación de tráfico (sealed sender, onion routing multi-salto, tráfico de cobertura).

Explícitamente **no** pretendemos proteger contra un atacante con control físico total y sostenido del dispositivo del usuario (keyloggers a nivel OS, malware preinstalado). Esto se documenta públicamente para no vender falsas garantías.

---

## 2. Arquitectura criptográfica

### 2.1 Protocolo base
- **Signal Protocol** (X3DH + Double Ratchet) para chats 1:1.
- **MLS (Messaging Layer Security, RFC 9420)** para grupos — escala mejor que ratcheting pareado y está diseñado específicamente para este caso.
- **Cifrado post-cuántico híbrido desde el día uno** (X25519 + Kyber/ML-KEM), no como parche posterior. Mitiga ataques "harvest now, decrypt later".
- Librería criptográfica: **libsodium** o equivalente ya auditado. Cero implementaciones propias de primitivas criptográficas en la v1.

### 2.2 Sobre el criptosistema propio (futuro)
Se ha planteado diseñar un criptosistema propio más adelante. Queda documentado como advertencia de diseño: la única forma seria de hacerlo es con criptógrafos profesionales dedicados, verificación formal (Tamarin Prover / ProVerif), y años de revisión pública **antes** de reemplazar cualquier pieza del protocolo ya auditado. No es tarea de v1 ni de v2. Cualquier intento de sustituir Signal Protocol/MLS sin este proceso es el riesgo #1 de fallo catastrófico del proyecto.

### 2.3 Metadata
- **Sealed sender**: el servidor/nodo de entrada no conoce al remitente, solo al destinatario.
- Misma lógica aplicada a la **señalización de llamadas** (punto 31): el nodo de señalización no debe poder reconstruir quién-llamó-a-quién-cuándo.
- Retención de logs mínima y con purga agresiva y automática.

### 2.4 Key Transparency
Log público append-only y auditable de claves públicas (mismo concepto que Certificate Transparency web, o el Key Transparency de Signal). Permite a cualquier cliente verificar que la clave pública que recibe de un contacto es la misma que ve el resto de la red — detecta MITM silencioso a nivel de infraestructura, complementario a la verificación manual (QR/número de seguridad) entre dos personas.

---

## 3. Identidad y autenticación

- **Registro sin número de teléfono obligatorio.** Teléfono queda como opción, no requisito.
- **Passkeys/FIDO2** como método principal de autenticación. TOTP como respaldo. **SMS explícitamente evitado** como único segundo factor (vulnerable a SIM swapping).
- **Descubrimiento de contactos**:
  - Método base: intercambio manual por link / QR / código (sin fricción, sin fuga de agenda).
  - **Usernames en paralelo**, con mitigaciones para no centralizar ni exponer la red:
    - Opt-in (usuario decide si es "buscable" — no por defecto).
    - Rate limiting agresivo en búsquedas del directorio (anti-scraping).
    - Costo mínimo (proof-of-work) al registrar username, anti-Sybil.
    - Directorio distribuido en la misma DHT, no en servidor central propio.
- **Verificación de claves** entre contactos vía número de seguridad / escaneo QR (estilo Signal), complementado por Key Transparency (2.4).

---

## 4. Multi-dispositivo, backups y recuperación

- **Sincronización multi-dispositivo** vía intercambio de claves entre dispositivos (mismo enfoque que Signal), nunca subiendo claves privadas en claro a ningún servidor.
- **Vinculación de dispositivo nuevo**: escaneo de QR entre un dispositivo ya autenticado y el nuevo.
- **Panel de "dispositivos activos"**: el usuario ve todos los dispositivos vinculados y puede revocar acceso al instante (crítico en caso de robo/pérdida).
- **Backups cifrados** con clave que solo el usuario controla (esquema tipo secure value recovery — ni el servidor puede leerlos sin la clave del usuario).
- **Recuperación de cuenta sin backdoor**: modelo tipo *seed phrase* (12-24 palabras) generada al crear la cuenta, guardada offline por el usuario. Si se pierden todos los dispositivos y la seed phrase, la cuenta es irrecuperable por diseño — no existe puerta trasera de "recuperar contraseña". Esto debe comunicarse de forma muy explícita en el onboarding.

---

## 5. Arquitectura de red (P2P)

### 5.1 Capa de transporte
- **libp2p** como base (no reinventar NAT traversal/descubrimiento de peers desde cero).
- **STUN** para hole punching directo entre peers cuando es posible.
- **TURN** como relay de respaldo cuando el hole punching falla (~10-20% de los casos); el TURN solo reenvía paquetes ya cifrados, no puede leerlos.

### 5.2 Enrutamiento y anonimato
- **DHT tipo Kademlia** para descubrimiento sin servidor central.
- **Onion routing multi-salto** (3 saltos mínimo, estilo Tor/Session) sobre la DHT — decisión explícita para maximizar resistencia a análisis de tráfico, priorizando seguridad sobre latencia.
- **Mitigación de ataques Eclipse/Sybil**: selección de nodos con aleatoriedad verificable (no "los más cercanos" de forma predecible), y diversidad forzada por salto (los 3 saltos del circuito no pueden caer en la misma subred/operador).
- **Tráfico de cobertura (dummy traffic)**: paquetes de relleno a intervalos constantes entre cliente y nodo de entrada, para que enviar un mensaje real sea indistinguible de estar inactivo. Evaluar como opción configurable por el costo en batería/datos.

### 5.3 Mensajería offline (store-and-forward)
- Buzones cifrados en nodos de la red, indexados por hash de la clave pública del destinatario (el nodo no sabe la identidad real).
- **TTL** (ej. 30 días) con borrado automático.
- El daemon local hace pull al reconectar, descifra localmente, y solicita borrado de la copia en el nodo.

### 5.4 Grupos a escala
- El emisor publica una sola vez a los nodos responsables del grupo (fan-out), no un push individual por cada miembro. Cada miembro hace pull desde ahí.

### 5.5 Archivos y multimedia
- Capa separada de **almacenamiento por contenido direccionado** (estilo IPFS), con chunking y descarga reanudable, cifrado E2EE, ciclo de vida y límites de tamaño propios (independiente del buzón de mensajes de texto).

### 5.6 Notificaciones push
- Uso de **APNs/FCM con payloads vacíos** ("hay algo, revisá la red") — el push no lleva contenido ni metadata legible.
- **UnifiedPush** como alternativa en Android para no depender de Google.

---

## 6. Cliente y daemon local

- Arquitectura de **daemon local** corriendo en `localhost` (puerto propio) en la máquina/dispositivo del usuario.
- La UI (app/web) habla únicamente con el daemon vía localhost, nunca directo a la red.
- El daemon gestiona: claves criptográficas, cifrado/descifrado, y la conexión a la red P2P/DHT/onion.

---

## 7. Seguridad del endpoint (dispositivo)

- Claves en **hardware seguro**: Secure Enclave (iOS), Keystore/StrongBox (Android).
- **Base de datos local cifrada en reposo** (tipo SQLCipher), clave derivada del PIN/passcode del usuario — nunca texto plano en disco.
- Bloqueo de capturas de pantalla en chats sensibles.
- Mensajes autodestructivos configurables.
- **Panic wipe**: borrado rápido de la app vía gesto/PIN de emergencia.
- Advertencia/restricciones en dispositivos con jailbreak/root.
- **Cero SDKs de analítica/crash-reporting de terceros** (nada de Firebase Analytics, Crashlytics, etc.). Si se necesita reporte de errores: sistema propio, auto-hosteado, opt-in explícito.

---

## 8. Moderación, spam y abuso

- **No hay escaneo ni lectura de contenido de mensajes, nunca, bajo ninguna circunstancia.** Este es un principio de diseño, no una política revocable.
- Sí se implementan, sin romper E2EE:
  - **Bloqueo de usuarios** a nivel cliente.
  - **Reporte voluntario**: el usuario que reporta decide qué comparte de su propio historial; la plataforma nunca accede a mensajes que el usuario no eligió mostrar.
  - "Solicitudes de mensaje" por defecto para contacto de desconocidos (no llegan directo al chat principal hasta aceptar).
- **Anti-spam de red** (no de contenido): proof-of-work liviano por mensaje enviado, invisible para el usuario normal, costoso para un emisor masivo automatizado.

---

## 9. Transparencia y auditoría

- **Código cliente open source en GitHub**, auditable por cualquiera.
- **Builds reproducibles**: cualquiera puede verificar que el binario/APK publicado corresponde exactamente al código fuente publicado.
- Auditorías de seguridad independientes, publicadas.
- (Programa de bug bounty / pentesting recurrente / fuzzing continuo: ver sección 13, en stand-by por decisión explícita.)

---

## 10. Distribución

- **Sin tiendas oficiales** (App Store / Google Play quedan fuera por decisión del proyecto).
- Sí: **F-Droid, APK directo, builds de escritorio** (Windows/Mac/Linux), y **onion service (Tor)** como vía de acceso alterna en países que bloqueen el dominio principal.
- ⚠️ **Punto abierto sin confirmar** — ver sección 14.

---

## 11. Gobernanza

- Modelo **"benevolent dictator"** (estándar en proyectos FOSS grandes) para decisiones de protocolo y roadmap.
- Incentivos económicos para operadores de nodo de la red: **diferido**, ver sección 13.

---

## 12. Modelo económico y pagos

- **Core de mensajería 100% gratis, sin excepciones, siempre.** Nunca se vende "más privacidad" como upsell — rompería la ética del proyecto.
- **Monetización exclusivamente en personalización cosmética**: gifts/regalos virtuales de perfil, banners, temas, insignias, etc.
- **Pagos 100% en criptomonedas**, sin fiat/tarjeta, sin KYC:
  - **Monero (XMR) como método principal** — privacidad por defecto y obligatoria (ring signatures, stealth addresses, montos ocultos). Es la única opción que realmente cumple "difícil de rastrear".
  - **Bitcoin y Ethereum como métodos secundarios**, junto a otras criptos a evaluar. Importante: BTC y ETH son **pseudónimos, no anónimos** — toda transacción es pública y rastreable en su blockchain, y se puede des-anonimizar retroactivamente si la wallet toca un exchange con KYC. Esto debe quedar explícito en la UI ("Monero: privado por diseño" vs. "Bitcoin/ETH: público en blockchain") para que el usuario elija informado.
- **Infraestructura de cobro**: BTCPay Server (open source, auto-hosteado, sin KYC impuesto), nativo para BTC/Lightning, con plugin para Monero. ETH/otras altcoins requieren integración adicional, no vienen "de fábrica" tan maduras — a resolver en fase de implementación.
- Solicitudes de pago ruteadas también a través del onion service, para que ni la IP de quien paga quede expuesta.
- **Aislamiento estricto de datos**: la base de datos de pagos/suscripciones nunca se vincula directamente con la de mensajería — solo un token opaco intercambiable confirma "activo/inactivo".

---

## 13. Explícitamente diferido / en stand-by

Estos puntos fueron identificados pero decididos deliberadamente para más adelante — no son huecos olvidados, son decisiones pospuestas a propósito:

- **Exposición legal por jurisdicción** (restricciones de cifrado, países que bloquean apps de mensajería cifrada): omitido por ahora.
- **Incentivos económicos para operadores de nodo**: a definir cuando se diseñe la economía de la red.
- **Programa de aseguramiento continuo** (bug bounty permanente, pentesting recurrente, verificación formal, fuzzing en CI/CD, disclosure policy pública): **en stand-by**, propuesto pero no priorizado todavía.

---

## 14. Decisiones pendientes de confirmar

- **iOS y distribución sin tienda oficial**: Apple restringe la instalación fuera de App Store salvo excepciones regionales (actualmente UE, Japón, y Brasil en proceso de habilitación — sujeto a cambios regulatorios). Fuera de esas regiones, un usuario de iPhone no podría instalar Blackhole sin recurrir a certificados empresariales (prohibidos por Apple para distribución pública) o TestFlight (límite de 10,000 usuarios, expira cada 90 días). **Esto se marcó como pregunta abierta y no se confirmó explícitamente** — antes de que Claude Code arranque el cliente iOS, esta decisión debería cerrarse: ¿se acepta ese alcance limitado en iOS, o se reconsidera la política de "sin tiendas oficiales" específicamente para esa plataforma?

---

## Apéndice — Stack tecnológico de referencia

| Capa | Tecnología propuesta |
|---|---|
| Cifrado 1:1 | Signal Protocol (X3DH + Double Ratchet) |
| Cifrado grupos | MLS (RFC 9420) |
| Post-cuántico | Híbrido X25519 + Kyber/ML-KEM |
| Primitivas criptográficas | libsodium |
| Transporte P2P | libp2p |
| NAT traversal | STUN + TURN |
| Enrutamiento anónimo | Onion routing multi-salto (3+) sobre DHT Kademlia |
| Almacenamiento de archivos | Sistema tipo IPFS (content-addressed, chunked) |
| Cifrado local en reposo | SQLCipher |
| Claves en hardware | Secure Enclave (iOS) / Keystore-StrongBox (Android) |
| Autenticación | Passkeys/FIDO2 + TOTP de respaldo |
| Push | APNs/FCM (payload vacío) + UnifiedPush (Android) |
| Pagos | BTCPay Server (BTC/Lightning/XMR), integración adicional para ETH |
| Distribución | F-Droid, APK directo, builds desktop, onion service |

---

## Apéndice — Mapeo de decisiones originales (1-31)

Referencia cruzada por si se necesita volver al razonamiento original de cada decisión: modelo de amenaza (1) → §1; protocolo de cifrado y criptosistema propio futuro (2) → §2.1-2.2; metadata (3) → §2.3; autenticación (4) → §3; multi-dispositivo/backups (5) → §4; grupos/llamadas (6) → §2.1, §2.3; infraestructura/red P2P (7) → §5; moderación (8) → §8; transparencia/open source (9) → §9; modelo de negocio (10) → §12; descubrimiento de contactos/usernames (11) → §3; push (12) → §5.6; onion routing (13) → §5.2; anti-spam (14) → §8; archivos grandes (15) → §5.5; fan-out de grupos (16) → §5.4; seguridad de endpoint (17) → §7; post-cuántico (18) → §2.1; distribución (19) → §10, §14; exposición legal (20) → §13; gobernanza (21) → §11; aseguramiento continuo (22) → §13; sostenibilidad/gratis+cosméticos (23) → §12; recuperación de cuenta (24) → §4; cifrado en reposo (25) → §7; gestión de dispositivos (26) → §4; ataques Eclipse/Sybil (27) → §5.2; tráfico de cobertura (28) → §5.2; key transparency (29) → §2.4; SDKs de terceros (30) → §7; metadata de llamadas (31) → §2.3.

---

## Decisiones de stack tomadas al iniciar el scaffold (post v0.1)

No estaban fijadas en v0.1 y se resolvieron al arrancar el repo:

- **Lenguaje del daemon: Rust.** Justificación: `libsignal` (la propia librería de Signal para X3DH/Double Ratchet) está escrita en Rust; `openmls` es la implementación de referencia de MLS (RFC 9420) en Rust; `rust-libp2p` es una implementación madura de libp2p. Es la opción con mejor alineación directa con el stack de la sección 2 y 5, minimizando bindings/FFI.
- **Cliente inicial: solo desktop (Tauri).** Se prioriza un extremo a extremo funcional en Windows/Mac/Linux antes de invertir en mobile/web. Tauri permite compartir crates de Rust entre el daemon y el shell del cliente. Mobile (iOS/Android) y web quedan para una fase posterior — la pregunta abierta de la §14 sobre distribución en iOS sigue sin resolver y deberá cerrarse antes de arrancar ese cliente.
