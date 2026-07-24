# Multi-dispositivo por delegación (modelo hub)

Fecha: 2026-07-24
Estado: diseño aprobado, pendiente de implementación
Riesgo que ataca: `docs/THREAT_MODEL.md` §4 riesgo abierto #14

## 1. Problema

`crates/bh-api/src/device_link.rs` documenta el bloqueo así: el mailbox
`Direct` es delete-on-read/single-consumer, así que dos daemons con la
misma identidad de cuenta se pisan al hacer `pull`, y el que pierde la
carrera se come el mensaje. Por eso `finish_link` deliberadamente no
instala la identidad de la cuenta en el dispositivo nuevo.

Ese es el problema más chico, y tiene solución conocida dentro de este
mismo repo: `message_receive.rs::receive_group_messages` ya resuelve
exactamente esa forma para grupos — nunca borra, y lleva un cursor por
consumidor (`GroupRegistry::already_attempted_group_message`).

El problema grande está una capa más abajo, en
`crates/bh-crypto/src/ratchet.rs:531`:

```rust
pub struct Session {
    associated_data, root_key, dh_self_secret, dh_self_public,
    dh_remote_public, sending_chain_key, receiving_chain_key,
    send_count, recv_count, prev_chain_len, skipped_keys,
}
```

El Double Ratchet es estado mutable de avance monótono, persistido en
`sessions.ratchet_state` por `(contact_id, device_id)`. Dos dispositivos
que comparten una identidad de cuenta no comparten ese estado:

- **En recepción** el daño es recuperable — ambos procesan los mismos
  ciphertexts y convergen al mismo estado.
- **En envío no.** Si el dispositivo A cifra, avanza `sending_chain_key`
  y `send_count`. El dispositivo B no se entera, así que su siguiente
  envío reutiliza la misma posición del ratchet: **reutilización de
  clave de mensaje**. Eso no es "se pierden mensajes", es una rotura
  criptográfica.

Conclusión: hacer el mailbox multi-consumidor es condición necesaria
pero no suficiente. Cualquier diseño que comparta una identidad de cuenta
entre dos dispositivos que ambos envían está roto por construcción.

## 2. Enfoques considerados

**A — Delegación al primario (elegido).** El secundario tiene identidad
propia de dispositivo y nunca instala la de la cuenta. Para enviar, le
pide al primario que envíe por él. El primario es el único que toca las
sesiones de ratchet de los contactos y el único estado MLS de los grupos.

**B — Sesiones propias del secundario contra cada contacto.** Menos
latencia y sobrevive a un primario apagado, pero el contacto recibe
mensajes de una identidad que no conoce: le aparece como solicitud de
mensaje de un desconocido, no como "el mismo interlocutor desde otro
dispositivo". Arreglarlo exige un directorio de dispositivos firmado
publicado en la DHT — el modelo de Signal, con su costo de metadata (el
número de dispositivos de alguien pasa a ser observable) y N copias de
ciphertext por mensaje. Es el escalón siguiente, no este.

**C — Replicar el estado del ratchet entre dispositivos.** Descartado:
es literalmente la reutilización de `sending_chain_key`/`send_count`
descrita en §1. Queda escrito para que no se reproponga.

### Por qué A y no B

El requisito que decide es: **¿el secundario tiene que recibir con el
primario apagado?** La respuesta acordada es no. Con eso, A domina a B en
todo lo demás:

- Cero metadata nueva expuesta. No hay directorio de dispositivos, no hay
  conteo de dispositivos observable, no hay copias extra de ciphertext en
  la DHT. Desde afuera, una cuenta con cinco dispositivos es
  indistinguible de una con uno. Esto es una propiedad de privacidad
  ganada, no un accidente del diseño más simple.
- Una sola ruta de cifrado en todo el sistema. El secundario nunca toca
  material de clave de ningún contacto ni de ningún grupo.
- Los grupos salen gratis (§4). Bajo B, cada dispositivo tendría que ser
  miembro MLS por separado, con su propio estado de época.

### Lo que A no compra

- El secundario no recibe nada con el primario apagado.
- El push relay despierta al primario, nunca al secundario.
- El primario es punto único de fallo **de producto**. No de seguridad:
  el hub es un dispositivo del propio usuario, no un servidor, así que la
  propiedad "el operador no puede leer nada" queda intacta.

Por eso el riesgo #14 del THREAT_MODEL pasa a **MITIGADO**, no a FIXED.

## 3. Modelo

**Una cuenta = una identidad, y vive solo en el primario.**

El secundario tiene identidad propia de dispositivo — `bh_crypto::
device_link::NewDevice::device_identity`, un par firma Ed25519 +
acuerdo X25519 que ya se genera hoy durante la ceremonia y se descarta al
terminar. Es direccionable por `recipient_key_hash(device_signing ||
device_agreement)`, exactamente el layout de 64 bytes que
`device_sync.rs` ya usa al armar su `Contact` pseudo.

**El direccionamiento hacia el primario cae solo.** El secundario le
escribe al mailbox de la identidad *de la cuenta*, que ya recibió en
`finish_link` (`linked_signing_key_hex`/`linked_agreement_key_hex`) y que
el primario ya escucha en su receive loop. No hace falta inventar una
dirección de primario: la identidad de la cuenta *es* el primario, porque
es el único que la usa. El X3DH del secundario hacia el primario usa el
prekey bundle de la cuenta que el primario ya publica en
`prekey_directory`.

**El direccionamiento hacia el secundario ya existe.**
`device_sync::sync_device_over_network` arma el `Contact` pseudo desde la
fila `Device` y llama a `message_crypto::send_encrypted_over_network`.
Falta una sola pieza: el secundario debe publicar su propio prekey bundle
bajo su hash de dispositivo, porque hoy nadie lo hace y el X3DH del
primario hacia él lo necesita.

**Nadie afuera se entera.** Contactos, grupos y llamadas siguen viendo
exactamente una identidad.

## 4. Grupos y "Notes to self"

Bajo el modelo hub, el secundario **nunca es miembro MLS de nada**. El
primario cifra con `bh_crypto::mls::Group::encrypt` y le espeja al
secundario el texto ya descifrado; el secundario delega sus envíos y el
primario los cifra. Los grupos pasan a ser el mismo mecanismo que
`Direct`, cambiando solamente qué primitiva elige el primario al cifrar.

Esto es lo que hace que incluir grupos en esta ronda sume superficie y no
un subsistema nuevo. `SelfNotes` es todavía más simple: no tiene
contraparte ni cifrado de sesión, solo hay que espejar filas.

## 5. Componentes

### 5.1 `bh-storage` — schema v21, rol secundario

Hoy `finish_link` (`device_link.rs:404`) devuelve las claves en el JSON
de respuesta y tira la sesión de memoria. El daemon "nuevo dispositivo"
queda sin `own_identity`, sin su identidad de dispositivo guardada, sin
saber que es un secundario y sin dirección del primario. Y
`message_receive.rs:92` hace `pull` sobre
`recipient_key_hash(own_identity)`, que en el secundario no existe — ese
daemon no escucha nada.

Tabla nueva de una sola fila, misma convención que `own_identity`:

| columna | contenido |
|---|---|
| `device_signing_private_key` | identidad de dispositivo propia (privada) |
| `device_agreement_private_key` | idem, leg X25519 |
| `account_signing_public_key` | clave pública de la cuenta a la que pertenece |
| `account_agreement_public_key` | idem, leg X25519 |
| `linked_at` | timestamp |

Un daemon con esta fila y sin `own_identity` es, por definición, un
secundario. La clave pública de la cuenta cumple doble función: verificar
que lo que llega viene del primario, y direccionar hacia él.

### 5.2 `bh-crypto::envelope` — variantes nuevas

Todas viajan dentro de la sesión cifrada ya existente, así que desde
afuera son indistinguibles de un mensaje de chat — el mismo principio que
`Envelope::Call` y `Envelope::Receipt` ya establecieron.

- `OutboundRequest { request_id, target, body, reply_to_message_id }` —
  secundario → primario. `target` distingue conversación `Direct` (por
  `contact_id`), `Group` (por `group_id`) y `SelfNotes`.
- `OutboundResult { request_id, message_id, error }` — primario →
  secundario. `error: Option<String>`; `None` es éxito.
- `ContactSync { contacts }` — primario → secundario. Sin esto el
  secundario muestra identificadores en vez de nombres.
- `DeviceSyncMessage` (ya existe) se extiende con el origen de
  conversación para cubrir `Group` y `SelfNotes`, no solo `Direct`.

Cuidado con el tamaño: `Envelope::encode` rellena por buckets hasta 64
KiB y después crece de a bloques enteros. `ContactSync` se emite por
lotes acotados, no como una lista única.

### 5.3 `bh-api` — cuatro piezas

**Módulo de rol secundario.** Persiste el rol en `finish_link`, publica
el prekey bundle propio bajo el hash de dispositivo, corre un receive
loop sobre ese hash, y expone el estado por HTTP.

**`conversations::send_message`.** Detecta el rol secundario y delega en
vez de cifrar. El mensaje se persiste local con estado pendiente y se
confirma al llegar el `OutboundResult`.

**`message_receive.rs`.** Dispatch de las variantes nuevas. Del lado del
primario, reconocer que un `OutboundRequest` viene de una fila `devices`
propia y no de un desconocido — hoy `process_one` devuelve
`UnknownSender` para cualquier remitente que no sea un `Contact`, y deja
la entrada en el mailbox.

**`device_sync.rs`.** De "Sync now" manual y solo-`Direct` a loop
automático que cubre `Direct`, `Group`, `SelfNotes` y contactos.

### 5.4 Revocación

Un secundario tiene el historial completo en su propia base SQLCipher y
puede hacer que el primario envíe en su nombre. Sin un "desvincular
dispositivo" que corte el sync y rechace sus `OutboundRequest`, la
feature agrega superficie de endpoint sin manera de cerrarla. Se
implementa como parte de esta ronda, no como follow-up.

## 6. Manejo de errores

- **Primario inalcanzable.** El `OutboundRequest` queda en el mailbox del
  primario hasta su TTL (`MAILBOX_TTL_SECONDS`, 7 días). El secundario
  muestra el mensaje como pendiente y reintenta; no se pierde, se
  demora. Es exactamente la semántica store-and-forward que el resto del
  sistema ya tiene.
- **`OutboundRequest` duplicado.** `request_id` es idempotente del lado
  del primario: un id ya procesado devuelve el `OutboundResult` original
  en vez de enviar dos veces.
- **Delegación rechazada.** Canal de broadcast donde el secundario no es
  dueño, grupo del que el primario ya no es miembro, contacto bloqueado:
  el primario responde `OutboundResult` con `error`, y el secundario lo
  muestra como fallo en vez de dejarlo pendiente para siempre.
- **Dispositivo revocado.** El primario descarta sus `OutboundRequest`
  como `Unprocessable` (se borra del mailbox, no se ancla ahí).

## 7. Pruebas

Test de tres daemons reales sobre red real, siguiendo el precedente de
`group_membership_and_messages_travel_a_real_network_between_three_daemons`:

1. Primario y secundario completan la ceremonia de enlace por red.
2. El secundario persiste su rol y publica su bundle.
3. El secundario delega un envío hacia un contacto.
4. El tercer daemon (el contacto) lo recibe y lo descifra.
5. El primario espeja de vuelta al secundario lo que recibe del contacto.

Más pruebas unitarias de: idempotencia de `request_id`, rechazo tras
revocación, y round-trip de las variantes de envelope nuevas.

## 8. Impacto en documentación

- `docs/SPEC.md` §19 nuevo describiendo la ronda.
- `docs/THREAT_MODEL.md`: reescribir el riesgo #14 como MITIGADO con el
  alcance real (no FIXED), y añadir una subsección §3.16 con el análisis
  STRIDE del rol secundario — sobre todo la superficie duplicada de
  endpoint y la delegación como capacidad de un secundario comprometido.
- `CLAUDE.md`: actualizar las entradas de `bh-api` y `client/desktop`.

## 9. Fuera de alcance

- Directorio de dispositivos firmado (enfoque B). Es la ronda siguiente
  si alguna vez se quiere independencia del primario.
- Llamadas desde el secundario. Requieren medios en tiempo real, no
  encajan en la delegación store-and-forward.
- Cliente móvil. Esto lo desbloquea; no lo incluye.
