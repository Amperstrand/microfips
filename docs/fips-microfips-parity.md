# FIPS ↔ microfips parity mapping

Source baseline:
- FIPS: `/home/ubuntu/src/fips/` @ branch `ble-transport-reliability`
- microfips: `/home/ubuntu/src2/microfips/crates/`

Legend: ✅ full/near-full parity, ⚠️ partial/split/minimal parity, ❌ missing

## 1. Architecture Overview

| FIPS module/crate | microfips crate/module | Parity | Notes |
|---|---|---:|---|
| `src/noise/*` | `crates/microfips-core/src/noise.rs` | ⚠️ | Same IK/XK/noise primitives, much smaller surface in microfips |
| `src/node/wire.rs` + `src/protocol/link.rs` | `crates/microfips-core/src/wire.rs` | ⚠️ | Compatible FMP framing subset; adds test/benchmark helpers |
| `src/node/session_wire.rs` + `src/protocol/session.rs` | `crates/microfips-core/src/fsp.rs` | ⚠️ | Compatible FSP subset focused on leaf sessions |
| `src/identity/*` | `crates/microfips-core/src/identity.rs` + `hex.rs` | ⚠️ | Same NodeAddr/FipsAddress derivation core; fewer auth/signature helpers |
| `src/mmp/*` | `crates/microfips-core/src/mmp/*` + `crates/microfips-protocol/src/mmp/*` | ⚠️ | Same report wire format + core algorithms; reduced session/path-MTU extras |
| `src/peer/*` | `crates/microfips-protocol/src/peer_policy.rs` + `node.rs` | ❌ | No separate peer object model; leaf runtime folds peer state into `Node` |
| `src/node/*` | `crates/microfips-protocol/src/node.rs` + `fsp_handler.rs` | ⚠️ | Leaf-only runtime, no mesh/router subsystems |
| `src/transport/*` | `crates/microfips-protocol/src/transport.rs`, `microfips-esp-transport/*`, `microfips-esp-common/*` | ⚠️ | Narrow async transport trait; concrete leaf transports only |
| mesh/tree/filter/discovery/TUN/routing subsystems | none / omitted | ❌ | Listed in Section 11 |
| service boundary above protocol | no direct FIPS equivalent | ⚠️ | `microfips-service` is microfips-only adapter layer |
| optional HTTP adapter | no direct FIPS equivalent | ⚠️ | `microfips-http-demo` demo-only |

Public symbol inventory totals used in this document:

| Surface | Public functions | Public consts | Public types |
|---|---:|---:|---:|
| FIPS scoped parity surfaces (`noise`,`identity`,`protocol`,`mmp`,`peer`,`node`,`transport`) | 881 | 97 | 191 |
| microfips scoped parity surfaces (`core`,`protocol`,`service`,`esp-transport`,`esp-common`) | 230 | 167 | 96 |

## 2. Noise Protocol Layer

### 2.1 Type mapping

| FIPS type | microfips type | Parity | Notes |
|---|---|---:|---|
| `NoiseError` | `NoiseError` | ✅ | Shared error domain intent |
| `CipherState` | internal AEAD helpers + finalized key tuples | ⚠️ | microfips does not expose standalone cipher-state type |
| `HandshakeState` | `NoiseIkInitiator`, `NoiseIkResponder`, `NoiseXkInitiator`, `NoiseXkResponder` | ⚠️ | FIPS keeps one polymorphic handshake state; microfips splits by role/pattern |
| `NoiseSession` | finalized link/session key tuples + `FspSession` / `FspInitiatorSession` users | ⚠️ | microfips does not expose a full reusable `NoiseSession` wrapper |
| `ReplayWindow` | none | ❌ | No standalone replay-window object |
| `HandshakeRole` | implicit in concrete initiator/responder types | ⚠️ | role is not a separate exported enum |
| `NoisePattern` | implicit (`IK`,`XK`) | ⚠️ | no exported pattern enum |
| `HandshakeProgress` | implicit state in concrete handshake structs | ⚠️ | no exported progress enum |

### 2.2 Constant comparison

| FIPS constant | Value | microfips equivalent | Value | Parity |
|---|---:|---|---:|---:|
| `MAX_MESSAGE_SIZE` | `65535` | none | — | ❌ |
| `TAG_SIZE` | `16` | `TAG_SIZE` | `16` | ✅ |
| `PUBKEY_SIZE` | `33` | `PUBKEY_SIZE` | `33` | ✅ |
| `EPOCH_SIZE` | `8` | `EPOCH_SIZE` | `8` | ✅ |
| `EPOCH_ENCRYPTED_SIZE` | `24` | derived/use-site constant | `24` | ⚠️ |
| `HANDSHAKE_MSG1_SIZE` | `106` | FMP wire layer constant | `106` | ✅ |
| `HANDSHAKE_MSG2_SIZE` | `57` | FMP wire layer constant | `57` | ✅ |
| `XK_HANDSHAKE_MSG1_SIZE` | `33` | `XK_HANDSHAKE_MSG1_SIZE` | `33` | ✅ |
| `XK_HANDSHAKE_MSG2_SIZE` | `57` | `XK_HANDSHAKE_MSG2_SIZE` | `57` | ✅ |
| `XK_HANDSHAKE_MSG3_SIZE` | `73` | `XK_HANDSHAKE_MSG3_SIZE` | `73` | ✅ |
| `REPLAY_WINDOW_SIZE` | `2048` | none | — | ❌ |
| protocol name IK | `Noise_IK_secp256k1_ChaChaPoly_SHA256` | `PROTOCOL_NAME` | same | ✅ |
| protocol name XK | `Noise_XK_secp256k1_ChaChaPoly_SHA256` | `PROTOCOL_NAME_XK` | same | ✅ |
| nonce size | internal | `NONCE_SIZE` | `12` | ⚠️ |

### 2.3 Function mapping

| FIPS function/method | microfips function/method | Parity | Notes |
|---|---|---:|---|
| `HandshakeState::new_initiator` | `NoiseIkInitiator::new` | ✅ | IK initiator setup |
| `HandshakeState::new_responder` | `NoiseIkResponder::new` | ✅ | IK responder setup |
| `HandshakeState::new_xk_initiator` | `NoiseXkInitiator::new` | ✅ | XK initiator setup |
| `HandshakeState::new_xk_responder` | `NoiseXkResponder::new` | ✅ | XK responder setup |
| `write_message_1` | `NoiseIkInitiator::write_message1` | ✅ | IK msg1 |
| `read_message_1` | `NoiseIkResponder::read_message1` | ✅ | IK msg1 parse |
| `write_message_2` | `NoiseIkResponder::write_message2` | ✅ | IK msg2 |
| `read_message_2` | `NoiseIkInitiator::read_message2` | ✅ | IK msg2 parse |
| `write_xk_message_1` | `NoiseXkInitiator::write_message1` | ✅ | XK msg1 |
| `read_xk_message_1` | `NoiseXkResponder::read_message1` | ✅ | XK msg1 parse |
| `write_xk_message_2` | `NoiseXkResponder::write_message2` | ✅ | XK msg2 |
| `read_xk_message_2` | `NoiseXkInitiator::read_message2` | ✅ | XK msg2 parse |
| `write_xk_message_3` | `NoiseXkInitiator::write_message3` | ✅ | XK msg3 |
| `read_xk_message_3` | `NoiseXkResponder::read_message3` | ✅ | XK msg3 parse |
| `into_session` | `finalize` methods | ⚠️ | microfips returns key tuples, not `NoiseSession` |
| `CipherState::encrypt` | `aead_encrypt` | ⚠️ | standalone helper rather than stateful object |
| `CipherState::decrypt` | `aead_decrypt` | ⚠️ | standalone helper |
| `CipherState::encrypt_with_aad` | `aead_encrypt` | ⚠️ | AAD passed directly |
| `CipherState::decrypt_with_counter_and_aad` | `aead_decrypt` | ⚠️ | counter/AAD passed directly |
| `ReplayWindow::{new,check,accept,highest,reset}` | none | ❌ | no exported replay window |
| `NoiseSession::{encrypt,decrypt,...}` | none | ❌ | no exported reusable link-session wrapper |
| key logging helpers | none | ❌ | no microfips equivalent |
| `parity_normalize` equivalent usage in FIPS internals | `parity_normalize` | ✅ | explicit helper exported by microfips |
| x-only ECDH internal logic | `x_only_ecdh` | ✅ | explicit helper exported by microfips |
| pubkey derivation internals | `ecdh_pubkey` | ✅ | explicit helper exported by microfips |

### 2.4 Deviation notes

| ID | Status | Mapping |
|---|---|---|
| `D1` | present in both | Handshake AEAD uses empty AAD rather than transcript hash |
| `D2` | present in both | IK uses custom `se` ordering matching FIPS interoperability behavior |
| `D3` | present in both | ECDH shared secret is x-only + SHA256 normalized |

### 2.5 Exhaustive public noise symbol inventory

**FIPS public consts**: `MAX_MESSAGE_SIZE`, `TAG_SIZE`, `PUBKEY_SIZE`, `EPOCH_SIZE`, `EPOCH_ENCRYPTED_SIZE`, `HANDSHAKE_MSG1_SIZE`, `HANDSHAKE_MSG2_SIZE`, `XK_HANDSHAKE_MSG1_SIZE`, `XK_HANDSHAKE_MSG2_SIZE`, `XK_HANDSHAKE_MSG3_SIZE`, `REPLAY_WINDOW_SIZE`.

**FIPS public types**: `ReplayWindow`, `HandshakeState`, `NoiseSession`, `NoiseError`, `HandshakeRole`, `NoisePattern`, `HandshakeProgress`, `CipherState`.

**FIPS public functions/methods**: `ReplayWindow::{new,check,accept,highest,reset}`; `HandshakeState::{new_initiator,new_responder,new_xk_initiator,new_xk_responder,role,progress,is_complete,remote_static,set_local_epoch,remote_epoch,write_message_1,read_message_1,write_message_2,read_message_2,write_xk_message_1,read_xk_message_1,write_xk_message_2,read_xk_message_2,write_xk_message_3,read_xk_message_3,into_session,handshake_hash}`; `CipherState::{encrypt,decrypt,decrypt_with_counter,encrypt_with_aad,decrypt_with_counter_and_aad,nonce,has_key}`; `NoiseSession::{encrypt,current_send_counter,decrypt,check_replay,decrypt_with_replay_check,encrypt_with_aad,decrypt_with_replay_check_and_aad,highest_received_counter,reset_replay_window,handshake_hash,remote_static,remote_static_xonly,role,send_nonce,recv_nonce}`; `log_link_keys`, `log_session_keys`.

**microfips public consts**: `TAG_SIZE`, `EPOCH_SIZE`, `NONCE_SIZE`, `PUBKEY_SIZE`, `PROTOCOL_NAME`, `PROTOCOL_NAME_XK`.

**microfips public types**: `NoiseError`, `NoiseIkInitiator`, `NoiseIkResponder`, `NoiseXkInitiator`, `NoiseXkResponder`.

**microfips public functions/methods**: `parity_normalize`, `x_only_ecdh`, `ecdh_pubkey`, `aead_encrypt`, `aead_decrypt`; `NoiseIkInitiator::{new,write_message1,read_message2,finalize}`; `NoiseIkResponder::{new,read_message1,write_message2,finalize}`; `NoiseXkInitiator::{new,write_message1,read_message2,write_message3,finalize}`; `NoiseXkResponder::{new,read_message1,write_message2,read_message3,finalize}`.

## 3. FMP Link Layer

### 3.1 Wire format comparison

| Field | FIPS | microfips | Parity |
|---|---|---|---:|
| version nibble | `FMP_VERSION=0` | `FMP_VERSION=0` | ✅ |
| common prefix size | `4` | `4` | ✅ |
| established header size | `16` | `16` | ✅ |
| inner header size | `5` | `5` | ✅ |
| msg1 wire size | `114` | `114` | ✅ |
| msg2 wire size | `69` | `69` | ✅ |
| established encrypted minimum | `32` | `32` | ✅ |

### 3.2 Message type mapping

| FIPS link/session message | Byte | microfips constant/type | Parity |
|---|---:|---|---:|
| `SessionDatagram` | `0x00` | `MSG_SESSION_DATAGRAM` | ✅ |
| `SenderReport` | `0x01` | `MSG_SENDER_REPORT` | ✅ |
| `ReceiverReport` | `0x02` | `MSG_RECEIVER_REPORT` | ✅ |
| `TreeAnnounce` | `0x10` | none | ❌ |
| `FilterAnnounce` | `0x20` | none | ❌ |
| `LookupRequest` | `0x30` | none | ❌ |
| `LookupResponse` | `0x31` | none | ❌ |
| `Disconnect` | `0x50` | `MSG_DISCONNECT` + reason constants | ✅ |
| `Heartbeat` | `0x51` | `MSG_HEARTBEAT` | ✅ |
| `EchoRequest` | `0xFF` | `MSG_ECHO_REQUEST` | ⚠️ |
| `EchoResponse` | `0xFE` | `MSG_ECHO_RESPONSE` | ⚠️ |
| `ThroughputRequest` | `0xFD` | `MSG_THROUGHPUT_REQUEST` | ⚠️ |
| `ThroughputStream` | `0xFC` | `MSG_THROUGHPUT_STREAM` | ⚠️ |
| `ThroughputReport` | `0xFB` | `MSG_THROUGHPUT_REPORT` | ⚠️ |

### 3.3 Header/constructor comparison

| FIPS | microfips | Parity | Notes |
|---|---|---:|---|
| `CommonPrefix::parse` | `parse_prefix`, `CommonPrefix` | ✅ | same fields |
| `EncryptedHeader::parse` | `parse_message`, `EncryptedHeader` | ✅ | same established-frame layout |
| `Msg1Header::parse` | `parse_message`, `Msg1Header` | ✅ | same wire split |
| `Msg2Header::parse` | `parse_message`, `Msg2Header` | ✅ | same wire split |
| `build_msg1` | `build_msg1` | ✅ | same layout |
| `build_msg2` | `build_msg2` | ✅ | same layout |
| `build_established_header` | `build_established_header` | ✅ | same layout |
| `build_encrypted` | `build_encrypted` | ✅ | same framing |
| `prepend_inner_header` | `prepend_inner_header` | ✅ | same timestamp+msg body model |
| `strip_inner_header` | `strip_inner_header` | ✅ | same parse |
| `SessionDatagram::{encode,decode}` | `build_session_datagram_body` + FSP/session helpers | ⚠️ | microfips encodes body directly, not a separate FMP datagram object |
| `Disconnect::{encode,decode}` | reason consts + caller-side composition | ⚠️ | no separate disconnect struct |

### 3.4 Constant comparison

| FIPS constant | microfips equivalent | Parity |
|---|---|---:|
| `FMP_VERSION` | `FMP_VERSION` | ✅ |
| `PHASE_ESTABLISHED` | `PHASE_ESTABLISHED` | ✅ |
| `PHASE_MSG1` | `PHASE_MSG1` | ✅ |
| `PHASE_MSG2` | `PHASE_MSG2` | ✅ |
| `COMMON_PREFIX_SIZE` | `COMMON_PREFIX_SIZE` | ✅ |
| `ESTABLISHED_HEADER_SIZE` | `ESTABLISHED_HEADER_SIZE` | ✅ |
| `MSG1_WIRE_SIZE` | `MSG1_WIRE_SIZE` | ✅ |
| `MSG2_WIRE_SIZE` | `MSG2_WIRE_SIZE` | ✅ |
| `ENCRYPTED_MIN_SIZE` | `ENCRYPTED_MIN_SIZE` | ✅ |
| `INNER_HEADER_SIZE` | `INNER_HEADER_SIZE` | ✅ |
| `FLAG_KEY_EPOCH` | `FLAG_KEY_EPOCH` | ✅ |
| `FLAG_CE` | `FLAG_CE` | ✅ |
| `FLAG_SP` | `FLAG_SP` | ✅ |
| disconnect reason enum values | `DISC_REASON_*` consts | ✅ |

### 3.5 Exhaustive public FMP/link inventory

**FIPS protocol/link public types**: `HandshakeMessageType`, `LinkMessageType`, `DisconnectReason`, `Disconnect`, `SessionDatagram`, `MessageType`.

**FIPS protocol/link public functions/methods**: `HandshakeMessageType::{from_byte,to_byte,is_handshake}`; `LinkMessageType::{from_byte,to_byte}`; `DisconnectReason::{from_byte,to_byte}`; `Disconnect::{new,encode,decode}`; `SessionDatagram::{new,with_ttl,with_path_mtu,decrement_ttl,can_forward,encode,decode}`.

**FIPS node/wire public consts**: `FMP_VERSION`, `PHASE_ESTABLISHED`, `PHASE_MSG1`, `PHASE_MSG2`, `COMMON_PREFIX_SIZE`, `ESTABLISHED_HEADER_SIZE`, `MSG1_WIRE_SIZE`, `MSG2_WIRE_SIZE`, `ENCRYPTED_MIN_SIZE`, `INNER_HEADER_SIZE`, `FLAG_KEY_EPOCH`, `FLAG_CE`, `FLAG_SP`.

**FIPS node/wire public types/functions**: `CommonPrefix`, `EncryptedHeader`, `Msg1Header`, `Msg2Header`; `CommonPrefix::parse`; `EncryptedHeader::{parse,ciphertext_offset,ciphertext}`; `Msg1Header::{parse,noise_msg1}`; `Msg2Header::{parse,noise_msg2}`; `build_msg1`, `build_msg2`, `build_established_header`, `build_encrypted`, `prepend_inner_header`, `strip_inner_header`.

**microfips wire public consts**: `FMP_VERSION`, `COMMON_PREFIX_SIZE`, `IDX_SIZE`, `ESTABLISHED_HEADER_SIZE`, `INNER_HEADER_SIZE`, `ENCRYPTED_MIN_SIZE`, `HANDSHAKE_MSG1_SIZE`, `HANDSHAKE_MSG2_SIZE`, `EPOCH_ENCRYPTED_SIZE`, `MSG1_WIRE_SIZE`, `MSG2_WIRE_SIZE`, `PHASE_ESTABLISHED`, `PHASE_MSG1`, `PHASE_MSG2`, `MSG_HEARTBEAT`, `MSG_SESSION_DATAGRAM`, `MSG_SENDER_REPORT`, `MSG_RECEIVER_REPORT`, `MSG_DISCONNECT`, `MSG_ECHO_REQUEST`, `MSG_ECHO_RESPONSE`, `MSG_THROUGHPUT_REQUEST`, `MSG_THROUGHPUT_STREAM`, `MSG_THROUGHPUT_REPORT`, `ECHO_REQUEST_MIN_SIZE`, `ECHO_RESPONSE_MIN_SIZE`, `ECHO_MAX_PAYLOAD`, `THROUGHPUT_REQUEST_SIZE`, `THROUGHPUT_STREAM_MIN_SIZE`, `THROUGHPUT_REPORT_SIZE`, `DISC_REASON_SHUTDOWN`, `DISC_REASON_RESTART`, `DISC_REASON_PROTOCOL_ERROR`, `DISC_REASON_TRANSPORT_FAILURE`, `DISC_REASON_RESOURCE_EXHAUSTION`, `DISC_REASON_SECURITY_VIOLATION`, `DISC_REASON_CONFIGURATION_CHANGE`, `DISC_REASON_TIMEOUT`, `DISC_REASON_OTHER`, `FLAG_KEY_EPOCH`, `FLAG_CE`, `FLAG_SP`.

**microfips wire public types/functions**: `SessionIndex`, `FmpMessage`, `CommonPrefix`, `EncryptedHeader`, `Msg1Header`, `Msg2Header`; `parse_echo_request`, `build_echo_response`, `parse_throughput_request`, `parse_throughput_stream`, `build_throughput_report`, `build_prefix`, `parse_prefix`, `build_msg1`, `build_msg2`, `build_established_header`, `prepend_inner_header`, `strip_inner_header`, `build_encrypted`, `encrypt_and_assemble`, `parse_message`.

## 4. FSP Session Layer

### 4.1 Session establishment flow

| Step | FIPS | microfips | Parity |
|---|---|---|---:|
| SessionSetup | `SessionSetup` + `build_session_setup` path | `build_session_setup` | ✅ |
| SessionAck | `SessionAck` + `build_session_ack` path | `build_session_ack` | ✅ |
| SessionMsg3 | `SessionMsg3` + handler path | `build_session_msg3` | ✅ |
| Established data | `FspEncryptedHeader` + inner header | `build_fsp_data_message` / `parse_fsp_encrypted_header` | ✅ |
| Session responder state | FIPS node/session handlers | `FspSession` | ⚠️ |
| Session initiator state | FIPS node/session handlers | `FspInitiatorSession` | ⚠️ |
| Unified handler result | FIPS node internals | `FspHandlerResult` / `handle_fsp_datagram` | ⚠️ |

### 4.2 XK handshake message comparison

| Message | FIPS size | microfips size | Parity |
|---|---:|---:|---:|
| XK msg1 | `33` | `33` | ✅ |
| XK msg2 | `57` | `57` | ✅ |
| XK msg3 | `73` | `73` | ✅ |

### 4.3 FSP wire format tables

| Field | FIPS | microfips | Parity |
|---|---|---|---:|
| `FSP_VERSION` | `0` | `0` | ✅ |
| common prefix | 4 bytes | 4 bytes | ✅ |
| encrypted header | 12 bytes | 12 bytes | ✅ |
| inner header | 6 bytes | 6 bytes | ✅ |
| encrypted minimum | 28 bytes | 28 bytes | ✅ |
| `FSP_PORT_IPV6_SHIM` | `256` | `256` | ✅ |
| CP/K/U flags | `0x01/0x02/0x04` | `FLAG_COORDS_PRESENT/FLAG_KEY_EPOCH/FLAG_UNENCRYPTED` | ✅ |

### 4.4 Session datagram comparison

| Aspect | FIPS | microfips | Parity |
|---|---|---|---:|
| body size | `35` | `35` | ✅ |
| header size | `36` | `36` | ✅ |
| hop-limit byte | `64` default | `64` default | ✅ |
| path MTU default | `u16::MAX` | `u16::MAX` | ✅ |
| source/dest NodeAddr | 16B + 16B | 16B + 16B | ✅ |

### 4.5 Exhaustive public FSP/session inventory

**FIPS protocol/session public types**: `SessionMessageType`, `SessionFlags`, `FspFlags`, `FspInnerFlags`, `SessionSetup`, `SessionAck`, `SessionMsg3`, `SessionSenderReport`, `SessionReceiverReport`, `PathMtuNotification`, `CoordsRequired`, `PathBroken`, `MtuExceeded`.

**FIPS protocol/session public consts**: `SESSION_SENDER_REPORT_SIZE`, `SESSION_RECEIVER_REPORT_SIZE`, `PATH_MTU_NOTIFICATION_SIZE`, `COORDS_REQUIRED_SIZE`, `MTU_EXCEEDED_SIZE`, plus `SESSION_DATAGRAM_HEADER_SIZE` in `protocol/link.rs`.

**FIPS protocol/session public functions/methods**: `SessionMessageType::{from_byte,to_byte}`; `SessionFlags::{new,with_ack,bidirectional,to_byte,from_byte}`; `FspFlags::{new,to_byte,from_byte}`; `FspInnerFlags::{new,to_byte,from_byte}`; `SessionSetup::{new,with_flags,with_handshake,encode,decode}`; `SessionAck::{new,with_handshake,encode,decode}`; `SessionMsg3::{new,encode,decode}`; `SessionSenderReport::{encode,decode}`; `SessionReceiverReport::{encode,decode}`; `PathMtuNotification::{new,encode,decode}`; `CoordsRequired::{new,encode,decode}`; `PathBroken::{new,with_last_coords,encode,decode}`; `MtuExceeded::{new,encode,decode}`.

**FIPS node/session_wire public consts**: `FSP_VERSION`, `FSP_PHASE_ESTABLISHED`, `FSP_PHASE_MSG1`, `FSP_PHASE_MSG2`, `FSP_PHASE_MSG3`, `FSP_COMMON_PREFIX_SIZE`, `FSP_HEADER_SIZE`, `FSP_INNER_HEADER_SIZE`, `FSP_ENCRYPTED_MIN_SIZE`, `FSP_PORT_HEADER_SIZE`, `FSP_PORT_IPV6_SHIM`, `FSP_FLAG_CP`, `FSP_FLAG_K`, `FSP_FLAG_U`, `FSP_INNER_FLAG_SP`.

**FIPS node/session_wire public types/functions**: `FspCommonPrefix`, `FspEncryptedHeader`; `FspCommonPrefix::{parse,is_unencrypted,has_coords}`; `FspEncryptedHeader::{parse,has_coords,data_offset}`; `build_fsp_header`, `build_fsp_encrypted`, `build_fsp_handshake_prefix`, `build_fsp_error_prefix`, `fsp_prepend_inner_header`, `fsp_strip_inner_header`, `parse_encrypted_coords`.

**microfips fsp public consts**: `FSP_VERSION`, `FSP_COMMON_PREFIX_SIZE`, `FSP_HEADER_SIZE`, `FSP_INNER_HEADER_SIZE`, `FSP_ENCRYPTED_MIN_SIZE`, `FSP_PORT_IPV6_SHIM`, `XK_HANDSHAKE_MSG1_SIZE`, `XK_HANDSHAKE_MSG2_SIZE`, `XK_HANDSHAKE_MSG3_SIZE`, `PHASE_ESTABLISHED`, `PHASE_SESSION_SETUP`, `PHASE_SESSION_ACK`, `PHASE_SESSION_MSG3`, `FSP_MSG_DATA`, `FLAG_COORDS_PRESENT`, `FLAG_KEY_EPOCH`, `FLAG_UNENCRYPTED`, `FIPS_UDP_PORT`, `FIPS_IPV6_OVERHEAD`, `FSP_DATAGRAM_HEADER_SIZE`, `NODE_ADDR_SIZE`, `SESSION_DATAGRAM_BODY_SIZE`, `SESSION_DATAGRAM_HEADER_SIZE`.

**microfips fsp public types/functions**: `FspError`, `FspDatagram`, `Ipv6Shim`, `FspSessionState`, `FspSessionError`, `FspSession`, `FspInitiatorState`, `FspInitiatorError`, `FspInitiatorSession`, `FspHandlerResult`, `FspHandlerError`; `build_session_datagram_body`, `build_session_setup`, `parse_session_setup`, `build_session_ack`, `parse_session_ack`, `build_session_msg3`, `parse_session_msg3`, `build_fsp_header`, `build_fsp_encrypted`, `fsp_prepend_inner_header`, `build_fsp_data_message`, `fsp_strip_inner_header`, `parse_fsp_encrypted_header`, `handle_fsp_datagram`.

## 5. Identity System

### 5.1 Type mapping

| FIPS type | microfips type | Parity | Notes |
|---|---|---:|---|
| `NodeAddr` | `NodeAddr` | ✅ | same 16-byte node address concept |
| `FipsAddress` | `FipsAddress` | ✅ | same 16-byte address concept |
| `Identity` | none | ❌ | no full local identity object |
| `PeerIdentity` | none | ❌ | no peer identity wrapper object |
| `IdentityError` | none | ❌ | microfips uses panics/Option for many identity helpers |
| `AuthChallenge` / `AuthResponse` | none | ❌ | omitted |

### 5.2 Function mapping

| FIPS function/method | microfips equivalent | Parity | Notes |
|---|---|---:|---|
| `NodeAddr::from_pubkey` | `NodeAddr::from_pubkey_x` | ✅ | x-only input in microfips |
| `NodeAddr::{from_bytes,from_slice,as_bytes}` | `NodeAddr::{as_bytes}` + tuple constructor semantics | ⚠️ | fewer constructors exported |
| `FipsAddress::from_node_addr` | `FipsAddress::from_node_addr` | ✅ | same derivation intent |
| `encode_nsec` | `encode_nsec` | ⚠️ | microfips emits hex bytes, not bech32 nsec |
| `encode_npub` | none | ❌ | no core helper |
| `decode_npub` | none | ❌ | no core helper |
| `decode_nsec` | none | ❌ | no core helper |
| `Identity::from_secret_bytes` | `load_secret` / config constants | ⚠️ | no local identity wrapper |
| `PeerIdentity::from_pubkey_full` | `load_peer_pub` + manual node derivation | ⚠️ | no wrapper type |
| `sha256` internal uses | `sha256` | ✅ |
| hex encoders | `hex_encode` | ✅ |

### 5.3 Constants comparison

| FIPS constant | microfips equivalent | Parity |
|---|---|---:|
| `FIPS_ADDRESS_PREFIX` | implicit in `FipsAddress::from_node_addr` | ⚠️ |
| device key constants in app config | `STM32_NSEC`, `VPS_NPUB`, `STM32_NPUB`, `STM32_NODE_ADDR`, `ESP32_NPUB`, `ESP32_NODE_ADDR` | ⚠️ |

### 5.4 Exhaustive public identity inventory

**FIPS public consts**: `FIPS_ADDRESS_PREFIX`.

**FIPS public types**: `FipsAddress`, `IdentityError`, `AuthChallenge`, `AuthResponse`, `NodeAddr`, `Identity`, `PeerIdentity`.

**FIPS public functions/methods**: `FipsAddress::{from_bytes,from_slice,from_node_addr,as_bytes,to_ipv6}`; `encode_npub`, `decode_npub`, `encode_nsec`, `decode_nsec`, `decode_secret`; `AuthChallenge::{generate,from_bytes,as_bytes,verify}`; `Identity::{generate,from_keypair,from_secret_key,from_secret_bytes,from_secret_str,keypair,pubkey,pubkey_full,npub,node_addr,address,sign,sign_challenge}`; `NodeAddr::{from_bytes,from_slice,from_pubkey,as_bytes,as_slice,short_hex}`; `PeerIdentity::{from_pubkey,from_pubkey_full,from_npub,pubkey,pubkey_full,npub,short_npub,node_addr,address,verify}`.

**microfips public consts**: `STM32_NSEC`, `VPS_NPUB`, `STM32_NPUB`, `STM32_NODE_ADDR`, `ESP32_NPUB`, `ESP32_NODE_ADDR`.

**microfips public types/functions**: `NodeAddr`, `FipsAddress`; `NodeAddr::{from_pubkey_x,as_bytes}`; `FipsAddress::{from_node_addr,as_bytes}`; `sha256`, `load_secret`, `load_peer_pub`, `hex_encode`, `encode_nsec`.

## 6. Transport Layer

### 6.1 Transport trait comparison

| FIPS | microfips | Parity | Notes |
|---|---|---:|---|
| `transport::Transport` rich runtime trait | `microfips_protocol::transport::Transport` | ⚠️ | microfips trait is minimal: `wait_ready/send/recv` |
| packet/disconnect channels | none | ❌ | no global transport event bus |
| link/address/transport state model | none | ❌ | microfips keeps simpler direct transport object |
| MTU/congestion/discovery interfaces | partial in concrete transports | ⚠️ | minimal leaf transport configuration |

### 6.2 Concrete transport mapping

| FIPS transport | microfips equivalent | Parity | Notes |
|---|---|---:|---|
| UDP | `microfips-esp-common::udp_transport::UdpTransport`, sim UDP transport | ✅ | raw frame mode supported |
| BLE L2CAP | `l2cap_host.rs` + `l2cap_transport.rs` | ✅ | same PSM `0x0085`, 2-byte BE SDU prefix |
| BLE GATT | `ble_host.rs` + `ble_transport.rs` | ⚠️ | microfips uses host bridge transport, not full FIPS daemon BLE stack |
| TCP | none | ❌ |
| Tor | none | ❌ |
| Ethernet | none | ❌ |
| UART/USB serial framed transport | microfips-only | ⚠️ | no direct FIPS equivalent |
| WiFi direct UDP | `wifi_transport.rs` | ⚠️ | leaf-specific direct UDP transport |

### 6.3 BLE L2CAP framing/constants

| Constant | FIPS | microfips | Parity |
|---|---:|---:|---:|
| PSM | `0x0085` | `133` / `0x0085` | ✅ |
| frame prefix length | `2` BE | `2` BE | ✅ |
| service UUID | `0x9c90...8f4c` | `L2CAP_FIPS_SERVICE_UUID_LE` / same UUID | ✅ |
| capability UUID | `FI` / GATT PSM chars on daemon side | `FIPS_CAPS_SERVICE_UUID`=`FI` | ✅ |
| frame cap | daemon MTU `2048`, app-specific limits | `L2CAP_FRAME_CAP=768` | ⚠️ |
| MTU | `2048` | `2048` target stack MTU, frame cap lower | ⚠️ |

### 6.4 Frame reader/writer comparison

| FIPS | microfips | Parity |
|---|---|---:|
| BLE/TCP stream framing helpers internal to transport implementations | `FrameWriter`, `FrameReader` | ⚠️ |
| BLE SDU 2-byte BE prefix | `SharedL2capTransport` host adapters | ✅ |
| UART/USB serial LE 2-byte length prefix | `FrameWriter`, `FrameReader`, `UartTransport`, `UsbTransport` | microfips-only |

### 6.5 Exhaustive public transport inventory

**FIPS transport public consts**: `DEFAULT_PSM`, `ETHERNET_BROADCAST`, `FIPS_SERVICE_UUID_RAW`, `FIPS_GATT_PSM_SERVICE_UUID_RAW`, `FIPS_GATT_PSM_CHAR_UUID_RAW`, `DISCOVERY_VERSION`, `FRAME_TYPE_BEACON`, `FRAME_TYPE_DATA`, `BEACON_SIZE`, `BLE_FRAME_PREFIX_LEN`, `MAX_RATE_BPS`, plus transport/node helper constants listed in Section 10.

**FIPS transport public types**: `ReceivedPacket`, `PacketTx`, `PacketRx`, `TransportDisconnect`, `DisconnectTx`, `DisconnectRx`, `TransportId`, `LinkId`, `TransportError`, `TransportType`, `TransportState`, `LinkState`, `LinkDirection`, `TransportAddr`, `LinkStats`, `Link`, `DiscoveredPeer`, `Transport`, `ConnectionState`, `TransportCongestion`, `TransportHandle`, `UdpTransport`, `BleTransport`, `BleAddr`, `PeerCapabilities`, `BleConnection`, `ConnectionPool`, `PeerBackoff`, `BleStats`, `BleStatsSnapshot`, `SendRateLimiter`, `BleRateAdapter`, `TcpTransport`, `TcpStats`, `TcpStatsSnapshot`, `TorAddr`, `TorTransport`, `TorStats`, `TorStatsSnapshot`, `TorControlError`, `ControlAuth`, `TorMonitoringInfo`, `TorControlClient`, `EthernetTransport`, `EthernetStats`, `EthernetStatsSnapshot`, `DiscoveryBuffer`, `PacketSocket`, `AsyncPacketSocket`, `StreamError`, multiple mock/test IO types.

**microfips protocol transport public types/functions**: `Transport`, `FrameWriter`, `FrameReader`.

**microfips esp/common public consts**: `VPS_HOST`, `VPS_PORT`, `WIFI_DHCP_TIMEOUT_SECS`, `DNS_TIMEOUT_SECS`, `DNS_PORT`, `DNS_QUERY_ID`; `LED_OFF`, `LED_ON`, `WAIT_READY_DELAY_MS`, `RECV_RETRY_DELAY_MS`, `PANIC_BLINK_CYCLES`, `UART_FIFO_THRESHOLD`, `UART_BAUDRATE`, `BLE_MAX_FRAME`, `FIPS_SERVICE_UUID_LE`, `USE_PUBLIC_BLE_ADDRESS`, `L2CAP_FRAME_CAP`, `L2CAP_PSM`, `FIPS_BLE_ADDR`, `FIPS_ALLOWED_PUBKEYS`, `FIPS_CAPS_SERVICE_UUID`, `L2CAP_FIPS_SERVICE_UUID_LE`, `DEVICE_NSEC`, `BLE_DEVICE_NAME`, `DEVICE_NAME`, `UART0_BASE`, `GPIO_FUNC_IN_SEL_BASE`, `UART_RX_GPIO_NUM`, `RESET_REGISTER`.

**microfips esp/common public types/functions**: `UdpTransport`, `WifiTransport`, `UartTransport`, `UsbTransport`, `SharedBleTransport`, `SharedL2capTransport`, `BleHostAdapter`, `L2capHostAdapter`, `BleError`, `L2capError`, `L2capRole`, `L2capDisconnectCode`, `L2capStatsSnapshot`, `BleStats`, `Led`, `EspRng`, `NodeIdentity`, `PeerInfo`; `compute_node_identity`, `init`, `set_peer_pub`, `init_control`, `ble_task_started`, `ble_link_up`, `l2cap_task_started`, `l2cap_link_up`, `l2cap_stats_snapshot`, `build_demo_fsp`, `build_demo_fsp_default`.

## 7. MMP Metrics Protocol

### 7.1 Sender/receiver report wire format

| Item | FIPS | microfips | Parity |
|---|---:|---:|---:|
| sender report body | `47` | `47` | ✅ |
| receiver report body | `67` | `67` | ✅ |
| sender report encoded message | `48` incl type/pad | `48` | ✅ |
| receiver report encoded message | `68` incl type/pad | `68` | ✅ |

### 7.2 Algorithm comparison

| FIPS | microfips | Parity |
|---|---|---:|
| `JitterEstimator` | `JitterEstimator` | ✅ |
| `SrttEstimator` | `SrttEstimator` | ✅ |
| `DualEwma` | `DualEwma` | ✅ |
| `OwdTrendDetector` | `OwdTrendDetector` | ✅ |
| `compute_etx` | `compute_etx` | ✅ |
| `SpinBitState` | none | ❌ |
| `MmpConfig` / `MmpSessionState` / `PathMtuState` | partial per-peer sender/receiver/metrics only | ⚠️ |

### 7.3 Constants comparison

| FIPS constant | microfips equivalent | Parity |
|---|---|---:|
| `SENDER_REPORT_BODY_SIZE` | `SENDER_REPORT_BODY_SIZE` | ✅ |
| `RECEIVER_REPORT_BODY_SIZE` | `RECEIVER_REPORT_BODY_SIZE` | ✅ |
| `SENDER_REPORT_WIRE_SIZE` | `SENDER_REPORT_SIZE` | ✅ |
| `RECEIVER_REPORT_WIRE_SIZE` | `RECEIVER_REPORT_SIZE` | ✅ |
| `DEFAULT_COLD_START_INTERVAL_MS` | `DEFAULT_COLD_START_INTERVAL_MS` | ✅ |
| `MIN_REPORT_INTERVAL_MS` | `MIN_REPORT_INTERVAL_MS` | ✅ |
| `MAX_REPORT_INTERVAL_MS` | `MAX_REPORT_INTERVAL_MS` | ✅ |
| `COLD_START_SAMPLES` | `COLD_START_SAMPLES` | ✅ |
| `DEFAULT_OWD_WINDOW_SIZE` | `DEFAULT_OWD_WINDOW_SIZE` | ✅ |
| `DEFAULT_LOG_INTERVAL_SECS` | none | ❌ |
| `MIN_SESSION_REPORT_INTERVAL_MS` | none | ❌ |
| `MAX_SESSION_REPORT_INTERVAL_MS` | none | ❌ |
| `SESSION_COLD_START_INTERVAL_MS` | none | ❌ |
| `JITTER_ALPHA_SHIFT` | in algorithm implementation | ⚠️ |
| `SRTT_ALPHA_SHIFT` | in algorithm implementation | ⚠️ |
| `RTTVAR_BETA_SHIFT` | in algorithm implementation | ⚠️ |
| `EWMA_SHORT_ALPHA` | in algorithm implementation | ⚠️ |
| `EWMA_LONG_ALPHA` | in algorithm implementation | ⚠️ |

### 7.4 Exhaustive public MMP inventory

**FIPS public types**: `ReceiverState`, `JitterEstimator`, `SrttEstimator`, `DualEwma`, `OwdTrendDetector`, `SpinBitState`, `MmpMetrics`, `MmpMode`, `MmpConfig`, `MmpPeerState`, `MmpSessionState`, `PathMtuState`, `SenderState`, `SenderReport`, `ReceiverReport`.

**FIPS public functions/methods**: `ReceiverState::{new,new_with_cold_start,reset_for_rekey,record_recv,build_report,should_send_report,update_report_interval_from_srtt,update_report_interval_with_bounds,cumulative_packets_recv,cumulative_bytes_recv,highest_counter,jitter_us,report_interval,last_recv_time,ecn_ce_count}`; `JitterEstimator::{new,update,jitter_us}`; `SrttEstimator::{new,update,srtt_us,rttvar_us,initialized,rto_us}`; `DualEwma::{new,update,short,long,initialized}`; `OwdTrendDetector::{new,clear,push,trend_us_per_sec,len,is_empty}`; `compute_etx`; `SpinBitState::{new,is_initiator,tx_bit,rx_observe}`; `MmpMetrics::{reset_for_rekey,new,process_receiver_report,update_reverse_delivery,srtt_ms,loss_rate,smoothed_loss,smoothed_etx,goodput_bps,last_ecn_ce_count}`; `MmpPeerState::{new,reset_for_rekey,mode,should_log,mark_logged}`; `MmpSessionState::{new,reset_for_rekey,mode,should_log,mark_logged}`; `PathMtuState::{new,current_mtu,last_observed_mtu,update_interval_from_srtt,seed_source_mtu,observe_incoming_mtu,should_send_notification,build_notification,apply_notification}`; `SenderState::{new,new_with_cold_start,record_sent,build_report,should_send_report,record_send_failure,record_send_success,send_failure_backoff_multiplier,update_report_interval_from_srtt,update_report_interval_with_bounds,cumulative_packets_sent,cumulative_bytes_sent,report_interval,consecutive_send_failures}`; `SenderReport::{encode,decode}`; `ReceiverReport::{encode,decode}`.

**microfips public consts/types/functions**: `DEFAULT_COLD_START_INTERVAL_MS`, `MIN_REPORT_INTERVAL_MS`, `MAX_REPORT_INTERVAL_MS`, `COLD_START_SAMPLES`, `DEFAULT_OWD_WINDOW_SIZE`, `SENDER_REPORT_SIZE`, `RECEIVER_REPORT_SIZE`, `SENDER_REPORT_BODY_SIZE`, `RECEIVER_REPORT_BODY_SIZE`; `SenderReport`, `ReceiverReport`, `JitterEstimator`, `SrttEstimator`, `DualEwma`, `OwdTrendDetector`, `SenderState`, `ReceiverState`, `MmpMetrics`, `MmpPeerState`; `compute_etx`; `SenderReport::{encode,decode}`; `ReceiverReport::{encode,decode}`; `SenderState::{new,new_with_cold_start,record_sent,build_report,should_send_report,record_send_failure,record_send_success,send_failure_backoff_multiplier,update_report_interval_from_srtt,update_report_interval_with_bounds,cumulative_packets_sent,cumulative_bytes_sent,report_interval,consecutive_send_failures}`; `ReceiverState::{new,new_with_cold_start,reset_for_rekey,record_recv,build_report,should_send_report,update_report_interval_from_srtt,update_report_interval_with_bounds,cumulative_packets_recv,cumulative_bytes_recv,highest_counter,jitter_us,report_interval}`; `MmpMetrics::{new,reset_for_rekey,process_receiver_report,update_reverse_delivery,srtt_ms,loss_rate,goodput_bps,smoothed_etx}`; `MmpPeerState::{new,snapshot_stats}`; `mmp::stats::{update,srtt_ms,loss_pct,goodput_kbps,jitter_us}`.

## 8. Peer Management

| FIPS peer surface | microfips equivalent | Parity | Notes |
|---|---|---:|---|
| `PeerConnection` handshake object | `Node` internal handshake slots | ⚠️ | no exported connection object |
| `ActivePeer` authenticated peer object | `Node` established peer state + `FspDualHandler` state | ⚠️ | no exported active-peer type |
| `PeerSlot` | none | ❌ |
| `PeerError` / `PromotionResult` | `ProtocolError`, `PolicyVerdict`, `HandleResult` | ⚠️ |
| `ConnectivityState` | `NodeEvent::{Connected,Disconnected,Error}` + stats state | ⚠️ |
| `cross_connection_winner` | `MAX_COMPETING_MSG1` and simple leaf competition handling | ⚠️ |
| replay/decrypt failure tracking | `PeerPolicy` bad-frame and failure thresholds | ⚠️ |

**microfips peer policy consts**: `MIN_RECONNECT_MS`, `MAX_RECONNECT_MS`, `RECONNECT_BACKOFF_BASE_MS`, `FRAME_RATE_WINDOW_MS`, `FRAME_RATE_MAX`, `SILENT_PEER_SECS`, `SILENT_PEER_MIN_DATA_RATIO`, `MAX_CONSECUTIVE_BAD`, `MAX_CONSECUTIVE_FAILURES`.

**microfips peer policy public types/functions**: `PeerPolicy`, `PolicyVerdict`.

**FIPS peer public inventory**

- `ConnectivityState::{can_send,is_terminal,is_healthy}`
- `ActivePeer` methods: `new`, `with_stats`, `with_session`, `identity`, `node_addr`, `address`, `pubkey`, `npub`, `link_id`, `connectivity`, `can_send`, `is_healthy`, `is_disconnected`, `has_session`, `noise_session`, `noise_session_mut`, `our_index`, `their_index`, `set_their_index`, `replace_session`, `transport_id`, `current_addr`, `set_current_addr`, `set_handshake_msg2`, `handshake_msg2`, `clear_handshake_msg2`, `increment_replay_suppressed`, `reset_replay_suppressed`, `replay_suppressed_count`, `increment_decrypt_failures`, `reset_decrypt_failures`, `consecutive_decrypt_failures`, `remote_epoch`, `coords`, `declaration`, `has_tree_position`, `inbound_filter`, `filter_sequence`, `filter_is_stale`, `may_reach`, `needs_filter_update`, `link_stats`, `link_stats_mut`, `mmp`, `mmp_mut`, `link_cost`, `has_srtt`, `authenticated_at`, `last_seen`, `idle_time`, `connection_duration`, `session_elapsed_ms`, `session_start`, `last_heartbeat_sent`, `mark_heartbeat_sent`, `touch`, `mark_stale`, `mark_reconnecting`, `mark_disconnected`, `mark_connected`, `set_link_id`, `update_tree_position`, `clear_tree_position`, `set_tree_announce_min_interval_ms`, `last_tree_announce_sent_ms`, `set_last_tree_announce_sent_ms`, `can_send_tree_announce`, `record_tree_announce_sent`, `mark_tree_announce_pending`, `has_pending_tree_announce`, `update_filter`, `clear_filter`, `mark_filter_update_needed`, `clear_filter_update_needed`, `session_established_at`, `current_k_bit`, `rekey_in_progress`, `set_rekey_in_progress`, `is_rekey_dampened`, `record_peer_rekey`, `pending_our_index`, `pending_their_index`, `previous_our_index`, `previous_session`, `previous_session_mut`, `pending_new_session`, `set_pending_session`, `cutover_to_new_session`, `handle_peer_kbit_flip`, `drain_expired`, `is_draining`, `complete_drain`, `abandon_rekey`, `set_rekey_state`, `rekey_our_index`, `complete_rekey_msg2`, `needs_msg1_resend`, `rekey_msg1`, `set_msg1_next_resend`.
- `PeerConnection` methods: `outbound`, `inbound`, `inbound_with_transport`, `link_id`, `direction`, `handshake_state`, `expected_identity`, `is_outbound`, `is_inbound`, `is_in_progress`, `is_complete`, `is_failed`, `started_at`, `last_activity`, `duration`, `idle_time`, `link_stats`, `link_stats_mut`, `our_index`, `set_our_index`, `their_index`, `set_their_index`, `transport_id`, `set_transport_id`, `source_addr`, `set_source_addr`, `remote_epoch`, `set_handshake_msg1`, `set_handshake_msg2`, `handshake_msg1`, `handshake_msg2`, `resend_count`, `next_resend_at_ms`, `record_resend`, `start_handshake`, `receive_handshake_init`, `complete_handshake`, `take_session`, `has_session`, `mark_failed`, `touch`, `is_timed_out`.
- `PeerSlot` methods: `outbound`, `inbound`, `active`, `is_connecting`, `is_active`, `link_id`, `as_connection`, `as_connection_mut`, `as_active`, `as_active_mut`, `node_addr`.

## 9. Node State Machine

### 9.1 Lifecycle comparison

| FIPS | microfips | Parity | Notes |
|---|---|---:|---|
| `NodeState` operational model | implicit runtime in `Node::run` + `NodeEvent` | ⚠️ |
| configured startup + transports + static peers | `Node::new` + transport + peer pubkey | ⚠️ | single-peer leaf boot path |
| mesh forwarding loop | none | ❌ |
| discovery/tree/bloom/TUN coordination | none | ❌ |
| heartbeat loop | `HB_SECS`, `NodeEvent::Heartbeat*` | ✅ |
| reconnect/backoff | `RETRY_SECS`, `BACKOFF_MAX_SECS`, `PeerPolicy` | ⚠️ |
| handler callbacks | `NodeHandler::{on_event,on_message,poll_at,on_tick}` | ✅ |

### 9.2 Node constants

| microfips constant | Value | FIPS nearest equivalent | Parity |
|---|---:|---|---:|
| `HB_SECS` | `10` | FIPS heartbeat cadence in node loop | ✅ |
| `RECV_TIMEOUT_MS` | `30000` | FIPS link dead timeout behavior | ⚠️ |
| `RETRY_SECS` | `3` | FIPS retry/backoff machinery | ⚠️ |
| `BACKOFF_MAX_SECS` | `60` | FIPS `RetryState`/backoff controls | ⚠️ |
| `MSG1_RESEND_SECS` | `3` | FIPS handshake resend scheduling | ✅ |
| `MSG1_RESEND_MAX` | `10` | FIPS resend limit concept | ⚠️ |
| `CONNECT_DELAY_MS` | `500` | FIPS startup/send pacing | ⚠️ |
| `MAX_COMPETING_MSG1` | `3` | FIPS cross-connection resolution | ⚠️ |
| `RECV_BUF_SIZE` | `1500` | FIPS transport MTU-sized recv buffers | ⚠️ |

### 9.3 Exhaustive node/public runtime inventory

**microfips public types**: `NodeEvent`, `HandleResult`, `NodeHandler`, `NoopHandler`, `Node`, `ProtocolError`, `FspAppResult`, `FspAppHandler`, `NoopFspApp`, `FspDualHandler`.

**microfips node/public functions**: `framing::compact`; `Node` exported runtime via constructor/run methods in source plus handler trait; `mmp::stats::{update,srtt_ms,loss_pct,goodput_kbps,jitter_us}`.

**FIPS node public consts**: `FMP_VERSION`, `PHASE_ESTABLISHED`, `PHASE_MSG1`, `PHASE_MSG2`, `COMMON_PREFIX_SIZE`, `ESTABLISHED_HEADER_SIZE`, `MSG1_WIRE_SIZE`, `MSG2_WIRE_SIZE`, `ENCRYPTED_MIN_SIZE`, `INNER_HEADER_SIZE`, `FLAG_KEY_EPOCH`, `FLAG_CE`, `FLAG_SP`, `DEFAULT_BURST_CAPACITY`, `DEFAULT_REFILL_RATE`, `FAST_RING_CAPACITY`, `SLOW_RING_CAPACITY`, `DOWNSAMPLE_FACTOR`, `PEER_EVICTION_SECS`, `DEFAULT_PEERS_ALLOW_PATH`, `DEFAULT_PEERS_DENY_PATH`, `FSP_VERSION`, `FSP_PHASE_ESTABLISHED`, `FSP_PHASE_MSG1`, `FSP_PHASE_MSG2`, `FSP_PHASE_MSG3`, `FSP_COMMON_PREFIX_SIZE`, `FSP_HEADER_SIZE`, `FSP_INNER_HEADER_SIZE`, `FSP_ENCRYPTED_MIN_SIZE`, `FSP_PORT_HEADER_SIZE`, `FSP_PORT_IPV6_SHIM`, `FSP_FLAG_CP`, `FSP_FLAG_K`, `FSP_FLAG_U`, `FSP_INNER_FLAG_SP`.

**FIPS node public types**: `RoutingErrorRateLimiter`, `RetryState`, `CommonPrefix`, `EncryptedHeader`, `Msg1Header`, `Msg2Header`, `ForwardingStats`, `DiscoveryStats`, `TreeStats`, `BloomStats`, `ErrorSignalStats`, `CongestionStats`, `NodeStats`, snapshots for each, `DiscoveryBackoff`, `DiscoveryForwardRateLimiter`, `PeerAclDecision`, `PeerAclContext`, `PeerAclStatus`, `PeerAcl`, `PeerAclReloader`, `FspCommonPrefix`, `FspEncryptedHeader`, `PendingLookup`, `Metric`, `PeerMetric`, `Aggregation`, `Snapshot`, `PeerSnapshot`, `Granularity`, `Series`, `PeerStatsRings`, `StatsHistory`, `TokenBucket`, `HandshakeRateLimiter`, `NodeError`, `NodeState`, `Node`.

**FIPS node public functions/methods (top-level inventory)**: `RoutingErrorRateLimiter::{new,with_interval,should_send,len}`; `RetryState::{new,backoff_ms}`; node/wire parse/build helpers; stats record/snapshot methods; discovery backoff/rate-limit methods; ACL/reloader methods; session-wire parse/build helpers; `PendingLookup::new`; `NodeState::{is_operational,can_start,can_stop}`; `Node::{new,with_identity,leaf_only,identity,node_addr,npub,config,effective_ipv6_mtu,transport_mtu,state,uptime,is_running,is_leaf_only,tree_state,tree_state_mut,bloom_state,bloom_state_mut,estimated_mesh_size,coord_cache,coord_cache_mut,stats,stats_history,tun_state,tun_name,refresh_tun_mss,set_max_connections,set_max_peers,set_max_links,connection_count,peer_count,link_count,transport_count,allocate_transport_id,get_transport,get_transport_mut,transport_ids,packet_rx,allocate_link_id,add_link,get_link,get_link_mut,find_link_by_addr,remove_link,links,add_connection,get_connection,get_connection_mut,remove_connection,connections,get_peer,get_peer_mut,remove_peer,peers,peer_ids,sendable_peers,sendable_peer_count,session_count,identity_cache_len,identity_cache_iter,identity_cache_max,pending_lookup_count,pending_lookups_iter,recent_request_count,pending_tun_destinations,pending_tun_total_packets,retry_state_iter,find_next_hop,destination_in_filters,tun_tx}`; stats-history query methods; token-bucket/handshake-rate-limiter methods.

## 10. Protocol Constants Master Table

| FIPS constant | Value | microfips equivalent | Value | Parity |
|---|---:|---|---:|---:|
| `noise::MAX_MESSAGE_SIZE` | `65535` | none | — | ❌ |
| `noise::TAG_SIZE` | `16` | `noise::TAG_SIZE` | `16` | ✅ |
| `noise::PUBKEY_SIZE` | `33` | `noise::PUBKEY_SIZE` | `33` | ✅ |
| `noise::EPOCH_SIZE` | `8` | `noise::EPOCH_SIZE` | `8` | ✅ |
| `noise::EPOCH_ENCRYPTED_SIZE` | `24` | `wire::EPOCH_ENCRYPTED_SIZE` | `24` | ✅ |
| `noise::HANDSHAKE_MSG1_SIZE` | `106` | `wire::HANDSHAKE_MSG1_SIZE` | `106` | ✅ |
| `noise::HANDSHAKE_MSG2_SIZE` | `57` | `wire::HANDSHAKE_MSG2_SIZE` | `57` | ✅ |
| `noise::XK_HANDSHAKE_MSG1_SIZE` | `33` | `fsp::XK_HANDSHAKE_MSG1_SIZE` | `33` | ✅ |
| `noise::XK_HANDSHAKE_MSG2_SIZE` | `57` | `fsp::XK_HANDSHAKE_MSG2_SIZE` | `57` | ✅ |
| `noise::XK_HANDSHAKE_MSG3_SIZE` | `73` | `fsp::XK_HANDSHAKE_MSG3_SIZE` | `73` | ✅ |
| `noise::REPLAY_WINDOW_SIZE` | `2048` | none | — | ❌ |
| `identity::FIPS_ADDRESS_PREFIX` | `0xfd` | implicit | — | ⚠️ |
| `protocol::PROTOCOL_VERSION` | `1` | none | — | ❌ |
| `protocol::link::SESSION_DATAGRAM_HEADER_SIZE` | `36` | `fsp::SESSION_DATAGRAM_HEADER_SIZE` | `36` | ✅ |
| `protocol::session::SESSION_SENDER_REPORT_SIZE` | `46` | `mmp::SENDER_REPORT_BODY_SIZE` payload + wrapper | `47/48` | ⚠️ |
| `protocol::session::SESSION_RECEIVER_REPORT_SIZE` | `66` | `mmp::RECEIVER_REPORT_BODY_SIZE` payload + wrapper | `67/68` | ⚠️ |
| `protocol::session::PATH_MTU_NOTIFICATION_SIZE` | `2` | none | — | ❌ |
| `protocol::session::COORDS_REQUIRED_SIZE` | `34` | none | — | ❌ |
| `protocol::session::MTU_EXCEEDED_SIZE` | `36` | none | — | ❌ |
| `mmp::SENDER_REPORT_BODY_SIZE` | `47` | `mmp::SENDER_REPORT_BODY_SIZE` | `47` | ✅ |
| `mmp::RECEIVER_REPORT_BODY_SIZE` | `67` | `mmp::RECEIVER_REPORT_BODY_SIZE` | `67` | ✅ |
| `mmp::SENDER_REPORT_WIRE_SIZE` | `52` | `mmp::SENDER_REPORT_SIZE` | `48` | ⚠️ |
| `mmp::RECEIVER_REPORT_WIRE_SIZE` | `72` | `mmp::RECEIVER_REPORT_SIZE` | `68` | ⚠️ |
| `mmp::JITTER_ALPHA_SHIFT` | `4` | in code | — | ⚠️ |
| `mmp::SRTT_ALPHA_SHIFT` | `3` | in code | — | ⚠️ |
| `mmp::RTTVAR_BETA_SHIFT` | `2` | in code | — | ⚠️ |
| `mmp::EWMA_SHORT_ALPHA` | `0.25` | in code | `0.25` | ⚠️ |
| `mmp::EWMA_LONG_ALPHA` | `1/32` | in code | `1/32` | ⚠️ |
| `mmp::DEFAULT_COLD_START_INTERVAL_MS` | `200` | same | `200` | ✅ |
| `mmp::MIN_REPORT_INTERVAL_MS` | `1000` | same | `1000` | ✅ |
| `mmp::MAX_REPORT_INTERVAL_MS` | `5000` | same | `5000` | ✅ |
| `mmp::COLD_START_SAMPLES` | `5` | same | `5` | ✅ |
| `mmp::DEFAULT_OWD_WINDOW_SIZE` | `32` | same | `32` | ✅ |
| `mmp::DEFAULT_LOG_INTERVAL_SECS` | `30` | none | — | ❌ |
| `mmp::MIN_SESSION_REPORT_INTERVAL_MS` | `500` | none | — | ❌ |
| `mmp::MAX_SESSION_REPORT_INTERVAL_MS` | `10000` | none | — | ❌ |
| `mmp::SESSION_COLD_START_INTERVAL_MS` | `1000` | none | — | ❌ |
| `node::wire::FMP_VERSION` | `0` | `wire::FMP_VERSION` | `0` | ✅ |
| `node::wire::PHASE_ESTABLISHED` | `0x0` | `wire::PHASE_ESTABLISHED` | `0x00` | ✅ |
| `node::wire::PHASE_MSG1` | `0x1` | `wire::PHASE_MSG1` | `0x01` | ✅ |
| `node::wire::PHASE_MSG2` | `0x2` | `wire::PHASE_MSG2` | `0x02` | ✅ |
| `node::wire::COMMON_PREFIX_SIZE` | `4` | `wire::COMMON_PREFIX_SIZE` | `4` | ✅ |
| `node::wire::ESTABLISHED_HEADER_SIZE` | `16` | `wire::ESTABLISHED_HEADER_SIZE` | `16` | ✅ |
| `node::wire::MSG1_WIRE_SIZE` | `114` | `wire::MSG1_WIRE_SIZE` | `114` | ✅ |
| `node::wire::MSG2_WIRE_SIZE` | `69` | `wire::MSG2_WIRE_SIZE` | `69` | ✅ |
| `node::wire::ENCRYPTED_MIN_SIZE` | `32` | `wire::ENCRYPTED_MIN_SIZE` | `32` | ✅ |
| `node::wire::INNER_HEADER_SIZE` | `5` | `wire::INNER_HEADER_SIZE` | `5` | ✅ |
| `node::wire::FLAG_KEY_EPOCH` | `0x01` | `wire::FLAG_KEY_EPOCH` | `0x01` | ✅ |
| `node::wire::FLAG_CE` | `0x02` | `wire::FLAG_CE` | `0x02` | ✅ |
| `node::wire::FLAG_SP` | `0x04` | `wire::FLAG_SP` | `0x04` | ✅ |
| `node::rate_limit::DEFAULT_BURST_CAPACITY` | `100` | none | — | ❌ |
| `node::rate_limit::DEFAULT_REFILL_RATE` | `10.0` | none | — | ❌ |
| `node::acl::DEFAULT_PEERS_ALLOW_PATH` | `/etc/fips/peers.allow` | none | — | ❌ |
| `node::acl::DEFAULT_PEERS_DENY_PATH` | `/etc/fips/peers.deny` | none | — | ❌ |
| `node::stats_history::FAST_RING_CAPACITY` | `3600` | none | — | ❌ |
| `node::stats_history::SLOW_RING_CAPACITY` | `1440` | none | — | ❌ |
| `node::stats_history::DOWNSAMPLE_FACTOR` | `60` | none | — | ❌ |
| `node::stats_history::PEER_EVICTION_SECS` | `86400` | none | — | ❌ |
| `node::session_wire::FSP_VERSION` | `0` | `fsp::FSP_VERSION` | `0` | ✅ |
| `node::session_wire::FSP_PHASE_ESTABLISHED` | `0x0` | `fsp::PHASE_ESTABLISHED` | `0x00` | ✅ |
| `node::session_wire::FSP_PHASE_MSG1` | `0x1` | `fsp::PHASE_SESSION_SETUP` | `0x01` | ✅ |
| `node::session_wire::FSP_PHASE_MSG2` | `0x2` | `fsp::PHASE_SESSION_ACK` | `0x02` | ✅ |
| `node::session_wire::FSP_PHASE_MSG3` | `0x3` | `fsp::PHASE_SESSION_MSG3` | `0x03` | ✅ |
| `node::session_wire::FSP_COMMON_PREFIX_SIZE` | `4` | `fsp::FSP_COMMON_PREFIX_SIZE` | `4` | ✅ |
| `node::session_wire::FSP_HEADER_SIZE` | `12` | `fsp::FSP_HEADER_SIZE` | `12` | ✅ |
| `node::session_wire::FSP_INNER_HEADER_SIZE` | `6` | `fsp::FSP_INNER_HEADER_SIZE` | `6` | ✅ |
| `node::session_wire::FSP_ENCRYPTED_MIN_SIZE` | `28` | `fsp::FSP_ENCRYPTED_MIN_SIZE` | `28` | ✅ |
| `node::session_wire::FSP_PORT_HEADER_SIZE` | `4` | `fsp::FSP_DATAGRAM_HEADER_SIZE` | `4` | ✅ |
| `node::session_wire::FSP_PORT_IPV6_SHIM` | `256` | `fsp::FSP_PORT_IPV6_SHIM` | `256` | ✅ |
| `node::session_wire::FSP_FLAG_CP` | `0x01` | `fsp::FLAG_COORDS_PRESENT` | `0x01` | ✅ |
| `node::session_wire::FSP_FLAG_K` | `0x02` | `fsp::FLAG_KEY_EPOCH` | `0x02` | ✅ |
| `node::session_wire::FSP_FLAG_U` | `0x04` | `fsp::FLAG_UNENCRYPTED` | `0x04` | ✅ |
| `node::session_wire::FSP_INNER_FLAG_SP` | `0x01` | none exported | — | ❌ |
| `transport::ble::DEFAULT_PSM` | `0x0085` | `config::L2CAP_PSM` | `133` | ✅ |
| `transport::ble::io::FIPS_SERVICE_UUID_RAW` | `0x9c90...8f4c` | `config::L2CAP_FIPS_SERVICE_UUID_LE` / `FIPS_SERVICE_UUID_LE` | same | ✅ |
| `transport::ble::pool::BLE_FRAME_PREFIX_LEN` | `2` | L2CAP framing prefix | `2` | ✅ |
| `transport::ble::rate_limit::MAX_RATE_BPS` | `80000` | none | — | ❌ |
| `transport::ethernet::discovery::DISCOVERY_VERSION` | `0x01` | none | — | ❌ |
| `transport::ethernet::discovery::FRAME_TYPE_BEACON` | `0x01` | none | — | ❌ |
| `transport::ethernet::discovery::FRAME_TYPE_DATA` | `0x00` | none | — | ❌ |
| `transport::ethernet::discovery::BEACON_SIZE` | `34` | none | — | ❌ |
| `transport::ethernet::socket::ETHERNET_BROADCAST` | `[0xff;6]` | none | — | ❌ |
| `protocol/link` disconnect values `0x00..0x07,0xFF` | enum values | `wire::DISC_REASON_*` | same | ✅ |
| `microfips-protocol::framing::MAX_FRAME` | — | `1500` | FIPS nearest MTU-like buffer only | ⚠️ |
| `microfips-protocol::node::HB_SECS` | — | `10` | FIPS runtime timing equivalent | ⚠️ |
| `microfips-protocol::node::RECV_TIMEOUT_MS` | — | `30000` | FIPS timeout equivalent | ⚠️ |
| `microfips-protocol::node::RETRY_SECS` | — | `3` | FIPS retry equivalent | ⚠️ |
| `microfips-protocol::node::BACKOFF_MAX_SECS` | — | `60` | FIPS retry/backoff equivalent | ⚠️ |
| `microfips-protocol::node::MSG1_RESEND_SECS` | — | `3` | FIPS resend equivalent | ⚠️ |
| `microfips-protocol::node::MSG1_RESEND_MAX` | — | `10` | FIPS resend equivalent | ⚠️ |
| `microfips-protocol::node::CONNECT_DELAY_MS` | — | `500` | FIPS pacing equivalent | ⚠️ |
| `microfips-protocol::node::MAX_COMPETING_MSG1` | — | `3` | FIPS cross-connect resolution equivalent | ⚠️ |
| `microfips-protocol::node::RECV_BUF_SIZE` | — | `1500` | FIPS recv buffer equivalent | ⚠️ |
| `microfips-protocol::peer_policy::*` | — | policy timing/thresholds | FIPS nearest `PeerBackoff`,`RetryState`,`ACL` | ⚠️ |
| `microfips-service::SERVICE_VERSION` | microfips-only | none | — | ⚠️ |
| `microfips-service::SERVICE_KIND_REQUEST` | microfips-only | none | — | ⚠️ |
| `microfips-service::SERVICE_KIND_RESPONSE` | microfips-only | none | — | ⚠️ |
| `microfips-service::SERVICE_REQUEST_HEADER_LEN` | microfips-only | none | — | ⚠️ |
| `microfips-service::SERVICE_RESPONSE_HEADER_LEN` | microfips-only | none | — | ⚠️ |

## 11. Features NOT in microfips (leaf-only gaps)

| FIPS feature | Status tag |
|---|---|
| mesh forwarding / next-hop routing | `leaf-doesn't-need` |
| spanning tree protocol / `TreeAnnounce` | `leaf-doesn't-need` |
| bloom filter reachability / `FilterAnnounce` | `leaf-doesn't-need` |
| discovery protocol / `LookupRequest` / `LookupResponse` | `leaf-doesn't-need` |
| coordinate cache and coordinate repair | `leaf-doesn't-need` |
| transit error signals `CoordsRequired`, `PathBroken`, `MtuExceeded` | `leaf-doesn't-need` |
| TUN integration / IPv6 data-plane plumbing | `leaf-doesn't-need` |
| Tor transport | `future-work` |
| TCP transport | `future-work` |
| Ethernet transport / beacon discovery | `future-work` |
| BLE daemon-side connection pool | `leaf-doesn't-need` |
| transport discovery interfaces | `leaf-doesn't-need` |
| ACL file loader / peers.allow / peers.deny | `future-work` |
| identity auth challenge/response signing | `future-work` |
| full `PeerIdentity` / `Identity` object model | `future-work` |
| replay window public object | `future-work` |
| stats history ring buffers | `leaf-doesn't-need` |
| congestion token bucket/routing error limiters | `leaf-doesn't-need` |
| session/path-MTU adaptive control plane (`PathMtuNotification`, `PathMtuState`) | `future-work` |
| spin-bit state | `future-work` |
| keylog helpers | `future-work` |

## 12. Wire Format Compatibility Matrix

### 12.1 Link handshake frames

| Message | Bytes | Layout | Compatibility |
|---|---:|---|---:|
| MSG1 | `114` | `[prefix:4][sender_idx:4 LE][noise_ik_msg1:106]` | ✅ |
| MSG2 | `69` | `[prefix:4][sender_idx:4 LE][receiver_idx:4 LE][noise_ik_msg2:57]` | ✅ |

### 12.2 Established FMP frame

| Offset | Size | Field | Compatibility |
|---:|---:|---|---:|
| `0` | `1` | `version<<4 | phase` | ✅ |
| `1` | `1` | flags (`K`,`CE`,`SP`) | ✅ |
| `2` | `2` | payload_len LE | ✅ |
| `4` | `4` | receiver_idx LE | ✅ |
| `8` | `8` | counter LE | ✅ |
| `16` | `N` | ciphertext incl AEAD tag | ✅ |

### 12.3 FMP established plaintext inner payload

| Offset | Size | Field | Compatibility |
|---:|---:|---|---:|
| `0` | `4` | timestamp_ms LE | ✅ |
| `4` | `1` | message type | ✅ |
| `5..` | `N` | message body | ✅ |

### 12.4 Session datagram body

| Offset | Size | Field | Compatibility |
|---:|---:|---|---:|
| `0` | `1` | hop limit | ✅ |
| `1` | `2` | path MTU LE | ✅ |
| `3` | `16` | source NodeAddr | ✅ |
| `19` | `16` | dest NodeAddr | ✅ |

### 12.5 FSP handshake frames

| Message | Prefix phase | Layout | Compatibility |
|---|---:|---|---:|
| SessionSetup | `0x01` | `[fsp_prefix:4][session_flags:1][src_count:2 LE][src_coords:16*n][dst_count:2 LE][dst_coords:16*n][hs_len:2 LE][xk_msg1]` | ✅ |
| SessionAck | `0x02` | `[fsp_prefix:4][reserved/status:1][src_count][src_coords][dst_count][dst_coords][hs_len][xk_msg2]` | ✅ |
| SessionMsg3 | `0x03` | `[fsp_prefix:4][xk_msg3]` | ✅ |

### 12.6 FSP established encrypted frame

| Offset | Size | Field | Compatibility |
|---:|---:|---|---:|
| `0` | `1` | `FSP_VERSION<<4 | phase(0)` | ✅ |
| `1` | `1` | flags (`CP`,`K`,`U`) | ✅ |
| `2` | `2` | payload_len LE | ✅ |
| `4` | `8` | counter LE | ✅ |
| `12..` | `N` | ciphertext incl tag | ✅ |

### 12.7 FSP inner header

| Offset | Size | Field | Compatibility |
|---:|---:|---|---:|
| `0` | `4` | timestamp_ms LE | ✅ |
| `4` | `1` | msg_type (`0x10` data) | ✅ |
| `5` | `1` | inner flags | ⚠️ |
| `6..` | `N` | service/app payload | ✅ |

### 12.8 MMP reports

| Message | Layout | Compatibility |
|---|---|---:|
| SenderReport | `[type:1][pad:3][interval_start_counter:8][interval_end_counter:8][interval_start_ts:4][interval_end_ts:4][interval_bytes_sent:4][cumulative_packets_sent:8][cumulative_bytes_sent:8]` | ✅ |
| ReceiverReport | `[type:1][pad:3][highest_counter:8][cumulative_packets_recv:8][cumulative_bytes_recv:8][timestamp_echo:4][dwell_time:2][max_burst_loss:2][mean_burst_loss:2][pad:2][jitter:4][ecn_ce_count:4][owd_trend:4][burst_loss_count:4][cumulative_reorder_count:4][interval_packets_recv:4][interval_bytes_recv:4]` | ✅ |

### 12.9 BLE L2CAP pubkey exchange

| Layout | Compatibility |
|---|---:|
| `[len:2 BE=34][0x00][x_only_pubkey:32][caps:1]` | ✅ |
| legacy accepted form `[len:2 BE=33][0x00][x_only_pubkey:32]` | ✅ |

## 13. Summary Statistics

| Metric | Value |
|---|---:|
| FIPS scoped public functions inventoried | `881` |
| FIPS scoped public consts inventoried | `97` |
| FIPS scoped public types inventoried | `191` |
| microfips scoped public functions inventoried | `230` |
| microfips scoped public consts inventoried | `167` |
| microfips scoped public types inventoried | `96` |
| Core wire/protocol constants with direct compatible match | `48` |
| Core wire/protocol constants partial/mapped by subset or implicit implementation | `28` |
| Core wire/protocol constants missing | `21` |
| High-confidence wire-format compatibility for MSG1/MSG2/FMP/FSP/MMP/L2CAP pubkey exchange | `6/6 surfaces` |
| Major omitted FIPS feature groups | `20` |

Parity rollup used in this document:

| Category | Count |
|---|---:|
| ✅ direct/compatible | `48` |
| ⚠️ partial/subset/split | `28` |
| ❌ missing | `21` |
| Direct parity percentage over master-constant sample | `49.5%` |
| Direct+partial coverage percentage over master-constant sample | `78.4%` |
