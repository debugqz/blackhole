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
- **Bloqueos compartibles** (implementado, §18): exportar/importar la
  propia lista de bloqueados como un link — siempre una cortesía
  voluntaria entre usuarios, nunca una lista centralizada ni aplicada
  automáticamente.

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

## 15. Funciones añadidas (post-v0.1)

Implementadas sobre la base de v0.1, sin tocar ninguno de los no-negociables (§2.2, CLAUDE.md). Todas están en `bh-crypto`/`bh-storage`/`bh-api`/`bh-calls`, reales y testeadas (ver cada crate), salvo donde se indica lo contrario.

- **Reacciones y respuestas citadas (quote-reply)**: reacciones por emoji (`bh_storage::reactions`) y `reply_to_message_id` en cada mensaje. Almacenamiento local únicamente — el transporte cifrado de una reacción/cita viaja como una variante más de `bh_crypto::envelope::Envelope`, indistinguible desde fuera de cualquier otro mensaje cifrado (ver más abajo).
- **Mensajes efímeros configurables**: el sweeper de auto-destrucción de §7 ya existía; ahora cada conversación tiene su propio temporizador (`disappearing_timer_secs`, `bh_storage::conversations::set_disappearing_timer`) que se aplica automáticamente al enviar (`POST /conversations/:id/messages`).
- **Recibos de entrega/lectura sin metadata para el operador**: en vez de un "protocolo de recibos" aparte (que filtraría "estas dos partes están intercambiando recibos ahora"), un recibo es una variante más de `bh_crypto::envelope::Envelope` (`Envelope::Receipt`) — viaja dentro de la misma sesión Double Ratchet/MLS ya autenticada que el contenido de chat, así que cualquier cosa fuera del destinatario ve ciphertext idéntico sin importar qué contiene. Ver `docs/THREAT_MODEL.md` para la fuga residual de longitud de ciphertext.
- **Verificación por número de seguridad** (ya prevista en §3): `bh_crypto::safety_number` implementa el fingerprint iterado (SHA-512, mismo estilo que Signal) combinando ambas identidades, mostrable como 12 grupos de 5 dígitos o QR. `Contact.verified` (ya existía en el schema) se marca vía `POST /contacts/:id/verify` tras la comparación manual — la app nunca marca "verificado" por sí sola.
- **Invitaciones expirables / de un solo uso**: `bh_crypto::invite::InvitePayload` ahora lleva un token aleatorio y una expiración opcional. Como no hay servidor, la única autoridad real es el emisor: `bh_storage::invites` lleva el registro local (`issued_invites`) y `Database::consume_invite` decide atómicamente si un intento de canje sigue siendo válido.
- **Exportación/importación cifrada de historial**: reutiliza `bh_crypto::backup::seal`/`open` (Argon2id + ChaCha20-Poly1305), aplicado a un paquete conversación+mensajes+reacciones+recibos en vez de a todo el backup de cuenta (`bh-api::export`).
- **Multi-cuenta (perfiles aislados)**: cada perfil es una base SQLCipher y un *service name* de keystore completamente separados (`bh_storage::profiles::ProfileManager`), el mismo modelo de aislamiento que ya exige §12 entre pagos y mensajería, aplicado aquí entre identidades. El listado de perfiles (id/nombre/fecha) es el único dato en texto plano — nunca contenido ni claves.
- **Llamadas de voz/video E2EE** (`bh-calls`, nuevo crate):
  - *Señalización y acuerdo de claves* (`bh_crypto::call_keys`, `bh_calls::signaling`): ECDH efímero por llamada + HKDF, independiente de las claves de sesión a largo plazo (forward secrecy específico de la llamada). El offer/answer/candidatos viaja como `Envelope::Call` dentro de la sesión cifrada existente — mismo principio que los recibos.
  - *Cifrado de medios* (`bh_crypto::call_keys::SframeContext`): capa SFrame (estilo draft-ietf-sframe) sobre el audio/video ya codificado, con ratcheting de época — una segunda capa de cifrado independiente de DTLS-SRTP, así que ni siquiera un relay/TURN comprometido puede ver el contenido.
  - *Transporte* (`bh_calls::transport`): WebRTC real vía `webrtc-rs` (ICE/DTLS/SRTP) — STUN y TURN son configurables (`BLACKHOLE_STUN_SERVERS`/`BLACKHOLE_TURN_SERVERS`+`_USERNAME`+`_CREDENTIAL`, un STUN público por defecto), pero no hay servidor TURN desplegado para este proyecto (mismo estado que los nodos de bootstrap de `bh-network`), validado con dos `RTCPeerConnection` locales reales en los tests.
  - *Audio* (`bh_calls::audio`): Opus (`audiopus`, bindings sobre libopus) + captura/reproducción real con `cpal`. El roundtrip de codec está testeado con PCM sintético; captura/reproducción de hardware real no se ejercita en CI (sin micrófono/altavoces).
  - *Video* (`bh_calls::video`): captura de cámara (`nokhwa`) + codificación VP8 (`vpx-encode`, sobre libvpx). **Decodificación VP8 deliberadamente fuera de alcance**: no existe un crate Rust seguro de decodificación VP8, y escribir bindings FFI propios contra libvpx es exactamente el tipo de código no auditado que este proyecto evita escribir (mismo principio que §2.2, aplicado a códecs en vez de a criptografía) — se deja al cliente Tauri, que puede decodificar con las APIs nativas del webview.
  - Requiere en tiempo de compilación `opus`, `libvpx` y `pkg-config` del sistema (vía Homebrew/apt/etc.) — ver comentarios en `crates/bh-calls/Cargo.toml`.
- **Solicitudes de pago cripto en el chat** (`bh_crypto::payment_address`, `bh_storage::payment_requests`, `bh-api::payment_requests`): deliberadamente el diseño más simple posible — un mensaje cifrado más que lleva una dirección/monto sugerido/memo para XMR, BTC o ETH. Blackhole nunca custodia fondos ni consulta una blockchain; la liquidación ocurre wallet-a-wallet, totalmente fuera de la app, y "pagado" es siempre una marca manual local (`paid_at`), nunca una confirmación on-chain. Esto es intencional y distinto del §12 (monetización cosmética vía BTCPay): al no tocar infraestructura de pagos en absoluto, esta función queda automáticamente fuera del requisito de aislamiento pagos/mensajería de §12, en vez de tener que cumplirlo. `bh_crypto::payment_address` valida el *formato* de la dirección (base58check+bech32 para BTC, EIP-55 para ETH, base58 con checksum Keccak-256 propio de Monero para XMR) para atrapar errores de tipeo antes de mostrar un QR — composición de funciones hash auditadas, no un criptosistema nuevo (mismo criterio que `safety_number` en §2.2). El monto nunca se codifica en el URI/deep-link (`bitcoin:`/`ethereum:`/`monero:` + solo la dirección) para evitar que un bug de conversión de unidades (wei, unidades atómicas) falsee silenciosamente cuánto se debe — se muestra aparte, como texto informativo.

---

## 16. Funciones añadidas (segunda ronda, post-§15)

Segunda tanda de funciones sobre la base de §15, mismo criterio: nada toca
los no-negociables (§2.2, CLAUDE.md), todo es real y testeado en su crate
correspondiente salvo donde se indica lo contrario.

- **Sync activo multi-dispositivo** (`bh-api::device_sync`): distinto de la
  vinculación de dispositivo (§4, ya implementada) — una vez un dispositivo
  está vinculado, este módulo mantiene su vista del historial al día. Sin
  `bh-network` ni un segundo proceso real, `GET /devices/:id/sync` ejercita
  de todas formas un handshake X3DH + Double Ratchet genuino entre la
  identidad real del dispositivo primario y una identidad "sombra" generada
  localmente para el endpoint del dispositivo vinculado (mismo truco que
  usan los miembros "sombra" de grupos para contactos) — cada entrada
  sincronizada trae `ratchet_roundtrip_ok` como prueba en vivo de que el
  cifrado/descifrado ocurrió de verdad, no una simulación. Lo que sí
  persiste entre reinicios es el cursor de entrega
  (`device_sync_cursor`); la sesión ratchet en sí es memoria de proceso,
  igual que el estado MLS de `groups.rs` antes de §3.2 del threat model.
- **Paquetes de stickers y temas de pago** (`bh-storage::cosmetics`/
  `message_stickers`, `bh-api::cosmetics`/`stickers`): extiende el sistema
  de cosméticos de §12 con un cuarto tipo (`sticker_pack`) además de
  banner/theme/badge. Enviar un sticker exige poseerlo — verificado
  server-side contra `cosmetic_inventory` (la base de mensajería), nunca
  contra `cosmetic_catalog`/`purchases` (la de pagos), preservando el
  aislamiento estricto que exige §12. El contenido de cada pack (qué
  stickers existen) es metadata estática en código, no hay todavía un
  pipeline de assets real.
- **Notas a uno mismo**: una conversación local singleton por perfil, sin
  contraparte (`ConversationKind::SelfNotes`, `contact_id`/`group_id`
  ambos `NULL`). Como no hay contraparte, no hay sesión de cifrado que
  establecer — el mensaje va directo a la base ya cifrada por SQLCipher,
  el mismo límite de confianza que todo lo demás en esa base, simplemente
  sin la capa Double Ratchet/MLS encima (esa capa protege mensajes *en
  tránsito* entre dos partes; aquí no hay tránsito). Se crea de forma
  perezosa en el primer `GET /conversations` y también eager en
  `POST /identity`, así que cubre tanto cuentas nuevas como perfiles
  existentes.
- **Mensajes editables**: editar reutiliza el mismo camino de
  almacenamiento local que enviar; nunca es una sobreescritura silenciosa
  — `Database::edit_message` archiva el cuerpo anterior en
  `message_edits` (con la marca de tiempo desde la que fue la versión
  vigente) antes de actualizar la fila viva, así que `edited_at.is_some()`
  es una señal siempre visible de que existe historial para inspeccionar.
  Solo el propio usuario puede editar sus mensajes salientes
  (`sender_contact_id` nulo) — editar un mensaje ajeno es `403`.
- **Canales de difusión (broadcast)** (`bh-storage::groups`,
  `bh-api::groups`/`conversations`): un canal es el mismo grupo MLS de
  siempre con un flag `broadcast_only` — la restricción de "solo el owner
  puede publicar" se aplica a nivel API (`send_message` rechaza con `403`
  cualquier envío que declare un `sender_contact_id` que no sea el usuario
  local, si el grupo detrás de la conversación es `broadcast_only`), no a
  nivel criptográfico. El grupo MLS subyacente funciona exactamente igual
  que cualquier otro — esto es una política de posting, no un mecanismo
  criptográfico nuevo.
- **Vista previa de enlaces (client-side)**: deliberadamente **nunca pasa
  por el daemon**. Un comando de Tauri separado
  (`fetch_link_preview`, `client/desktop/src-tauri/src/link_preview.rs`)
  hace la petición HTTP directo al sitio enlazado — el daemon no tiene
  forma de saber que se pidió una preview. Off por defecto: activarlo
  revela la IP del usuario (y que abrió ese link) al operador del sitio
  enlazado, un costo de privacidad real e inevitable para esta clase de
  función, comunicado explícitamente en el texto del toggle en vez de
  escondido detrás de un default silencioso. Incluye una guardia SSRF
  best-effort (rechaza loopback/privado/link-local; no resuelve el
  hostname, así que DNS-rebinding queda fuera de alcance — aceptable
  porque el usuario elige qué URL pegar, no es una superficie
  atacante-controlada).
- **Relay de notificaciones push opacas** (`crates/bh-push-relay`, nuevo
  crate — implementa §5.6): a diferencia de todo lo demás en este repo,
  este es un componente de servidor nuevo, no una función del daemon
  local. Su único trabajo es reenviar un token opaco de "despertar" — sin
  contenido, sin identidad del remitente, sin id de conversación ni de
  contacto. `POST /register` acepta el token; `POST /wake/:token` dispara
  un push sin contenido hacia APNs/FCM/UnifiedPush, en sí mismo todavía un
  stub (`// TODO(real-push)`, necesita credenciales de plataforma que este
  repo no puede provisionar). Sin base de datos, sin logging más allá de
  lo operacionalmente necesario. El registro del lado del daemon
  (`bh-storage::push`/`bh-api::push`) guarda un token opaco rotativo +
  on/off + `relay_url` — opt-in, apagado por defecto, ya que incluso un
  push opaco tiene un costo de metadata ("algún cliente, más o menos
  ahora, quiere despertar") que un usuario totalmente offline/manual no
  paga. **El wiring real ya está hecho**, no solo el registro local: al
  activar push con un `relay_url` y una red viva, el daemon llama de
  verdad al `POST /register` del relay y publica (firmado, contra la
  misma `identity_public_key` ya confiada vía X3DH — evita que un nodo DHT
  malicioso inyecte una `relay_url` atacante-controlada) un
  `PushRelayRecord` en la DHT (`bh-network::push_relay_directory`); del
  lado del envío, `bh-api::message_crypto::wake_recipient_best_effort`
  llama de verdad a `POST {relay_url}/wake/{token}` justo después de que
  un mensaje real llega al buzón del destinatario — ver CLAUDE.md para el
  detalle completo. Sigue sin haber una instancia de `bh-push-relay`
  desplegada para usuarios reales; eso queda para quien opere un nodo,
  igual que los nodos de bootstrap del DHT o un servidor TURN.
- **Mensajes de voz**: reutiliza exactamente el mismo camino de adjuntos
  con chunking y cifrado por chunk de §5.5/`bh-files` — la única
  diferencia es un `attachment_kind: voice` y una duración en segundos.
  Como un sticker, el mensaje va con `body: null`; el cliente lo identifica
  pidiendo el adjunto en vez de parsear un emoji en el texto. Grabado con
  `MediaRecorder` en el webview, reproducción inline con un `<audio>`
  cargado bajo demanda.
- **Búsqueda local de mensajes**: FTS5 real de SQLite sobre
  `messages.body`, indexado dentro de la misma base cifrada con SQLCipher
  — hereda el mismo cifrado en reposo que todo lo demás. Esto es el
  usuario buscando su propio buzón ya descifrado localmente por el
  daemon, nunca nada que salga del proceso ni sea visible para un
  relay/operador — explícitamente no es "escaneo de contenido" en el
  sentido prohibido de §8/CLAUDE.md. Las queries se sanitizan (cada
  palabra se cita como literal FTS5 y se unen con `AND`) para que
  puntuación arbitraria (`"`, `-`, `NOT`, `:`, `*`) nunca se interprete
  como sintaxis de consulta.
- **Llamadas grupales** (`bh-calls::group`): malla completa (*full-mesh*)
  WebRTC — cada participante abre una conexión directa a cada otro
  participante, tope de `MAX_GROUP_CALL_PARTICIPANTS = 6` (no existe SFU
  todavía). La clave base compartida de SFrame para toda la llamada sale
  directo del *exporter secret* del grupo MLS
  (`bh_crypto::mls::Group::export_call_base_key`, el mismo mecanismo que
  usa un exporter de TLS 1.3) en vez de un esquema de acuerdo de claves
  por-arista inventado — cada miembro ya comparte secretos de época tras
  procesar los mismos commits, así que no hace falta ninguna ronda extra
  de negociación y no se escribió ninguna primitiva criptográfica nueva
  (mismo criterio que §2.2). Sin `bh-network` ni membresía de grupo real
  todavía, los participantes además del que llama son miembros MLS
  "sombra" generados localmente — mismo patrón honesto-sobre-su-alcance
  que ya usan grupos/canales.
- **Compartir pantalla** (`bh-calls::screen`, vía el crate `scap` —
  ScreenCaptureKit en macOS, Windows.Graphics.Capture en Windows, el
  portal PipeWire en Linux): los frames pasan por el mismo pipeline de
  codificación VP8 + cifrado SFrame que ya usa el video de cámara, en una
  segunda pista WebRTC paralela (`"screen"` en vez de `"video"`) — no es
  un códec ni un esquema de cifrado separado. La captura real necesita
  permiso de grabación de pantalla otorgado al proceso, algo que un
  sandbox de CI no tiene, así que esa apertura concreta no se ejercita en
  CI (los tests cubren la lógica de recorte de dimensiones y, por
  separado, que la pista de screen-share sobrevive una conexión WebRTC
  local real).

---

## 17. Conectar la red real y cerrar riesgos pendientes (post-§16)

Tercera tanda: a diferencia de §15/§16 (funciones nuevas), esta ronda
conecta capacidad que ya existía pero corría en local/aislado, y cierra
pragmáticamente varios de los riesgos ya documentados en
`docs/THREAT_MODEL.md`. Mismo criterio de siempre: nada toca los
no-negociables (§2.2, CLAUDE.md).

- **Mensajería `Direct` real sobre `bh-network`**: hasta ahora,
   `bh-network` (DHT, buzones, sealed sender, onion routing) y el envío de
   mensajes vivían en mundos separados — el daemon spawneaba la red
   (`GET /network/status`, solo lectura) pero `POST /conversations/:id/
   messages` nunca la usaba. Ahora sí: para conversaciones `Direct`,
   `bh-api::message_crypto::send_encrypted_over_network` hace un handshake
   X3DH + Double Ratchet real (reutilizando `bh_crypto::ratchet` tal cual,
   sin tocar el protocolo), envuelve el ciphertext con sealed sender, y lo
   empuja al buzón Kademlia del destinatario; un loop en segundo plano
   (`message_receive::spawn_receive_loop`) hace polling del buzón propio,
   descifra, y entrega. Probado con un test de integración genuino de dos
   daemons independientes, dos identidades reales, sin estado de proceso
   compartido — no una sesión "sombra" en el mismo proceso como device
   sync o grupos. **Las conversaciones `Group` siguen sin conectar** — el
   fan-out de ciphertext MLS real vía `Mailbox::fan_out` queda
   explícitamente fuera de esta ronda.
- **Hardening pragmático de tres riesgos ya conocidos** (ver
   `docs/THREAT_MODEL.md` para el análisis STRIDE completo de cada uno):
   el módulo de onion routing (§3.4) se reescribió por completo, pasando
   del bucketing aproximado de tamaño de paquete a un formato de paquete
   Sphinx real (Danezis-Goldberg) vía el crate `sphinx-packet` (la
   implementación de producción del proyecto de mixnet Nym — composición
   de una implementación ya auditada, no cripto casera) — ahora todo
   paquete, en todo salto, para toda longitud de ruta y tamaño de
   payload, tiene *exactamente* el mismo tamaño, cerrando la fuga por
   completo en vez de solo reducirla; el merge de manifiesto de buzones
   (§3.6) ahora espera un
   backoff aleatorio entre reintentos en vez de reintentar inmediatamente,
   reduciendo colisiones bajo contención; y el desbloqueo local por
   passkey/TOTP (§3.11), que hasta ahora solo gateaba la UI *después* de
   que el daemon ya había abierto la base SQLCipher, ahora tiene una
   alternativa real: un passkey enrolado específicamente para esto deriva
   un secreto de 32 bytes vía la extensión PRF de WebAuthn (hardware —
   Secure Enclave/TPM/llave de seguridad — no algo que tenga que vivir
   legible en el keystore del SO), y el shell Tauri no lanza el proceso
   del daemon hasta tener ese secreto, pasándolo como `BLACKHOLE_DB_PIN`.
   TOTP se investigó y se descartó deliberadamente para este camino
   específico — un secreto TOTP tiene que ser legible por el cliente para
   verificar un código sin la base abierta, lo que lo vuelve tan expuesto
   como la propia clave que protegería.
- **Admisión al routing table del DHT acotada por subred**
   (`bh_network::routing_admission`): antes, cualquier peer que
   respondiera a Identify entraba sin límite a la tabla Kademlia. Ahora se
   admite como máximo un puñado de peers distintos por prefijo de IP
   (/24 en IPv4, /48 en IPv6), mismo principio de diversidad de subred que
   ya usaba la selección de saltos del onion routing (§5.2). No es
   S/Kademlia completo — un atacante con diversidad real de IP no se ve
   frenado por esto — pero cierra la versión más burda del problema
   (inundar la tabla con Sybils desde un solo bloque de direcciones).
- **Streaming de llamadas hacia el cliente + UI completa** (`bh-calls`
   ya tenía transporte/cifrado reales desde §15, pero nada los conectaba a
   una pantalla): nuevo canal `GET /calls/:call_id/ws`
   (`bh-api::call_stream`) — eventos de estado como JSON y frames de
   video/screen-share ya descifrados como binario. El audio nunca viaja
   por este canal: se decodifica y reproduce nativamente dentro del propio
   proceso daemon vía `cpal` (`bh-api::call_audio`), así que no hay nada
   que la UI necesite renderizar para eso. El webview no puede abrir ese
   WebSocket directamente (su handshake siempre lleva un header `Origin`,
   que el middleware de seguridad del daemon rechaza), así que el propio
   proceso Tauri hace de puente (`call_stream_bridge.rs`, cliente
   `tokio-tungstenite`) y reenvía eventos/frames al webview vía el sistema
   de eventos de Tauri. El cliente decodifica VP8 con la API `WebCodecs`
   del navegador (`Vp8CanvasRenderer` en `calls.ts`) — el daemon nunca
   decodifica video, mismo principio que §15 ya estableció para VP8.
   **Alcance**: como la entrega de señalización de llamada entre dos
   dispositivos reales todavía no está conectada a la red P2P, cada
   llamada que arranca esta UI hace de llamante y llamado contra el mismo
   daemon — la conexión WebRTC, la captura/codificación de medios, y el
   cifrado SFrame de extremo a extremo son genuinos, solo el salto de
   señalización es local en vez de ir por la red, y la UI lo dice
   explícitamente (mismo patrón ya usado para la vinculación de
   dispositivo en §4).
- **Token de portador entre el cliente Tauri y el daemon**
   (`bh-api::server::require_bearer_token`): cierra el hueco que
   `docs/THREAT_MODEL.md` §3.9 dejaba abierto — enlazar solo a loopback
   defiende contra la red, pero no contra otro proceso local en la misma
   máquina. Cada request ahora debe llevar `Authorization: Bearer
   <token>`, un token aleatorio generado por proceso del daemon y escrito
   a un archivo con permisos `0600` que el cliente Tauri lee de vuelta —
   independiente del middleware que ya rechazaba requests con header
   `Origin` (defiende contra una pestaña de navegador maliciosa, no contra
   otro proceso).
- **Key Transparency gossip desplegado**: `bh_crypto::key_transparency`
   ahora tiene `SignedTreeHead`/`sign_tree_head`/`verify_tree_head` — una
   identidad firma su propio tree head con la misma clave de firma a largo
   plazo que ya firma prekeys/safety numbers, y `bh_network::tree_head` lo
   publica sobre la DHT bajo una clave bien conocida derivada de la clave
   pública del firmante. El daemon repubblica cada 10 minutos (los
   registros Kademlia expiran); `create_identity` también dispara un
   publish inmediato en el bootstrap. `get_safety_number` ahora devuelve
   `key_transparency_corroborated`: fetch-and-verify best-effort del tree
   head publicado del contacto, evidencia corroborante **adicional** (nunca
   reemplazo) de la comparación manual out-of-band — `None` (sin red, o el
   contacto nunca publicó) se trata como "no se pudo verificar", no como
   bandera roja; `Some(false)` (un tree head válidamente firmado que no
   coincide con la clave en archivo) es una señal genuina que vale la pena
   mostrar. **Brecha residual**: esto solo detecta que un contacto
   silenciosamente recibió una clave *diferente* sobre la red — si caller
   y contacto terminan hablando en vistas de red disjuntas/particionadas
   (un atacante controlando *ambos* lados de la lookup del DHT), el gossip
   solo no puede detectarlo; un diseño tipo Certificate Transparency real
   necesitaría monitores independientes con chequeos cruzados,
   explícitamente fuera de scope para un log auto-publicado por identidad.

---

## 18. Bloqueos compartibles, señal de confianza de contacto, preferencias de UI y cuarta ronda de hardening (post-§17)

Cuarta tanda: a diferencia de §17 (conectar capacidad ya existente a la red
real), esta ronda agrega dos superficies nuevas pequeñas orientadas al
usuario (bloqueos compartibles, señal de confianza) más una preferencia de
cliente sin ningún componente criptográfico o de red (densidad/tamaño de
fuente), y cierra media docena de gaps de seguridad ya identificados o
recién encontrados durante esta pasada. Mismo criterio de siempre: nada
toca los no-negociables (§2.2, CLAUDE.md); ver `docs/THREAT_MODEL.md` §3.14
para el análisis STRIDE completo.

- **Bloqueos compartibles** (`bh-api::moderation::{export_blocklist,
  decode_blocklist,apply_blocklist}`, tres rutas nuevas bajo
  `/moderation/blocklist/*`, con panel de export/import en el cliente): una
  cortesía, no un sistema de moderación — un link copiable
  (`blackhole://blocklist?d=...`, JSON base64 plano, misma convención que
  `bh_crypto::invite::InvitePayload::to_link`, sin cifrar porque nada del
  contenido es secreto) que lista las claves públicas de identidad + label
  local de los contactos que este perfil ya bloqueó. Decodificar solo
  *previsualiza* qué entradas coinciden con los contactos propios del que
  importa; aplicar solo bloquea un contacto que el importador ya tiene y
  seleccionó explícitamente por id — nada de esto crea un contacto nuevo ni
  bloquea a nadie automáticamente, así que el principio "sin moderación de
  contenido, nunca" (§8) queda intacto: el único efecto real siempre
  termina en la misma llamada local `set_contact_blocked` que ya usaba el
  botón de bloqueo existente. Compartir el link es una acción explícita del
  usuario, no algo que viaje solo — pero, una vez compartido, el receptor sí
  aprende exactamente a quién bloqueó el que lo exportó; una fuga de
  metadata real, aunque acotada y voluntaria (`docs/THREAT_MODEL.md` §3.14
  lo documenta con ese nombre).
- **Señal de confianza de contacto** (`bh-api::contacts::{TrustLevel,
  compute_trust_level}`, expuesta como `ContactView` en `GET /contacts`,
  con badge en el cliente): una heurística puramente local y nunca
  persistida — `Blocked`/`Verified`/`Established`/`New` — calculada de
  nuevo en cada request a partir de `Contact.blocked`/`Contact.verified` y
  un conteo de mensajes por contacto
  (`bh-storage::contacts::message_counts_by_contact`, una sola query
  agregada). Solo `Verified` refleja una garantía criptográfica real (una
  comparación de número de seguridad confirmada); `Established` (≥10
  mensajes no borrados en una conversación `Direct` a lo largo de ≥3 días)
  es una señal mucho más débil, mostrada únicamente para que un contacto
  no verificado de larga data no se vea idéntico a uno agregado hace cinco
  minutos. Nunca sustituye la verificación manual del número de seguridad
  (§2.4) — es un dato de UI, no un mecanismo de confianza nuevo.
- **Preferencias de UI del cliente** (`client/desktop/src/ui_prefs.ts`):
  densidad de la lista de conversaciones y tamaño de fuente, guardadas en
  `localStorage` puro, deliberadamente *no* aisladas por perfil (a
  diferencia de la preferencia de `link_preview.ts`, que sí lo está porque
  gatea un comportamiento real de red) ya que describen cómo se ve la
  pantalla de este dispositivo, no algo sobre una identidad o contenido.
  Nunca llega al daemon.
- **Cuarta ronda de hardening pragmático** (ver `docs/THREAT_MODEL.md`
  §3.14 y las entradas correspondientes en §3.6/§3.7/§3.9/§3.12 para el
  detalle completo de cada uno):
  - **Buzones**: `mailbox.rs` ahora limita el tamaño serializado de un
    manifiesto (`MAX_MANIFEST_BYTES`) y rechaza un `push` una vez que el
    manifiesto de un destinatario/grupo ya está en ese límite — cierra una
    denegación de servicio barata donde un atacante podía resolver miles
    de pruebas de trabajo triviales y llenar el manifiesto de la víctima
    hasta romper el límite de tamaño de registro de la DHT.
  - **Token de portador**: la comparación en `require_bearer_token` ahora
    es en tiempo constante (`subtle::ConstantTimeEq`), cerrando un canal
    lateral de timing contra otro proceso local en la misma máquina.
  - **Borrado seguro en SQLCipher**: tanto `bh-storage::db` como
    `bh-crypto::mls_storage` activan `PRAGMA secure_delete = ON` — sin
    esto, los secretos de época de un miembro removido de un grupo MLS
    quedaban recuperables en el archivo de la base de datos, no
    verdaderamente borrados.
  - **Parser de `PushRelayRecord`**: `read_u32`/`read_string` ahora usan
    suma con verificación de overflow en vez de suma directa — este
    parser procesa bytes de la DHT, de un peer no confiable, *antes* de
    verificar la firma, así que una longitud declarada maliciosa cerca de
    `u32::MAX` ya no puede provocar un panic ni un wraparound.
  - **Keystore**: `Backend::File` ahora crea su directorio/archivo con
    permisos exclusivos del dueño (`0o700`/`0o600`) en el momento mismo de
    la creación, en vez de con un `chmod` posterior — cierra una ventana
    breve donde la ruta existía con permisos más laxos según el umask del
    proceso.
  - **Credencial TURN** (`infra/docker-compose.yml`): coturn ahora lee el
    usuario/credencial de un archivo de configuración generado en vez de
    un flag `--user=...` en la línea de comandos, así que la credencial ya
    no aparece en `ps aux`/`docker inspect`/`docker top` del host —
    hardening de despliegue, no cambia el hecho ya aceptado de que es una
    credencial estática, no efímera (`infra/README.md`).

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
- **Infraestructura de cobro para personalización cosmética (§12): Monero vía el plugin oficial de BTCPay (`BTCPayServer.Plugins.Monero`), no un servicio `monero-wallet-rpc` propio.** Reutiliza la misma instancia BTCPay ya decidida para BTC/Lightning en vez de sumar y operar una pieza de infraestructura separada; el plugin es menos maduro que el soporte BTC nativo de BTCPay, riesgo aceptado a cambio de superficie operativa mínima. **v1 lanza solo con XMR + BTC/Lightning — ETH y otras altcoins quedan diferidas explícitamente**, coherente con que BTC/ETH son pseudónimos y no privados por diseño (§12), y evita meter una integración no nativa de BTCPay en el camino crítico de monetización antes del lanzamiento. Ninguna de las dos piezas está implementada todavía — esto cierra la decisión de arquitectura, no el trabajo de construcción (modelo de datos aislado, integración `bh-api`, UI de tienda en el cliente siguen pendientes).
