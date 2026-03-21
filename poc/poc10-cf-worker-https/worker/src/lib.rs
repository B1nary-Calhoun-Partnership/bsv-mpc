//! POC 10: CF Worker Key Share Service over real HTTPS
//!
//! Minimal CF Worker that validates:
//! 1. MPC protocol (DKG + signing) works over real HTTPS
//! 2. Durable Object storage works for share persistence
//! 3. Latency is acceptable for production use
//! 4. No CORS, header size, or cold start issues
//!
//! Architecture: Worker holds share_A (party 0), client holds share_B (party 1).
//! Protocol messages are exchanged over HTTPS using deterministic replay:
//! each request contains all accumulated client messages, Worker replays
//! the protocol from scratch with a deterministic RNG (same seed = same
//! server messages), and returns all server messages produced so far.

use rand::SeedableRng;
use round_based::state_machine::{ProceedResult, StateMachine};
use serde::{Deserialize, Serialize};
use worker::*;

// ============================================================================
// Wire message types (from POC 5)
// ============================================================================

#[derive(Serialize, Deserialize, Clone, Debug)]
struct WireMessage {
    sender: u16,
    is_broadcast: bool,
    msg: serde_json::Value,
}

fn outgoing_to_wire<M: Serialize>(sender: u16, out: round_based::Outgoing<M>) -> WireMessage {
    WireMessage {
        sender,
        is_broadcast: out.recipient.is_broadcast(),
        msg: serde_json::to_value(&out.msg).unwrap(),
    }
}

fn wire_to_incoming<M: serde::de::DeserializeOwned>(
    wire: WireMessage,
    id: u64,
) -> round_based::Incoming<M> {
    round_based::Incoming {
        id,
        sender: wire.sender,
        msg_type: if wire.is_broadcast {
            round_based::MessageType::Broadcast
        } else {
            round_based::MessageType::P2P
        },
        msg: serde_json::from_value(wire.msg).unwrap(),
    }
}

fn parse_seed(hex_str: &str) -> std::result::Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("bad hex: {e}"))?;
    if bytes.len() != 32 {
        return Err("seed must be 32 bytes".into());
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

// ============================================================================
// Request/Response types
// ============================================================================

#[derive(Serialize, Deserialize)]
struct DkgRoundRequest {
    session_seed: String, // hex, 32 bytes — deterministic RNG seed
    n: u16,
    t: u16,
    client_messages: Vec<WireMessage>,
}

#[derive(Serialize, Deserialize)]
struct DkgRoundResponse {
    status: String, // "in_progress" or "complete"
    server_messages: Vec<WireMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    joint_pubkey: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct SignRoundRequest {
    session_seed: String,
    data_to_sign_hex: String, // raw message bytes to hash and sign
    key_share_json: String,   // serialized KeyShare<Secp256k1>
    client_messages: Vec<WireMessage>,
}

#[derive(Serialize, Deserialize)]
struct SignRoundResponse {
    status: String,
    server_messages: Vec<WireMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature_hex: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct DoKvPut {
    key: String,
    value: String,
}

#[derive(Serialize, Deserialize)]
struct DoKvGet {
    key: String,
}

// ============================================================================
// Worker entry point
// ============================================================================

#[event(fetch)]
async fn fetch(mut req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    let method = req.method();
    let path = req.path();

    let response = match (method, path.as_str()) {
        // CORS preflight
        (Method::Options, _) => Response::empty(),

        // Health check
        (Method::Get, "/health") => Response::from_json(&serde_json::json!({
            "status": "ok",
            "service": "poc10-mpc-worker",
            "timestamp": js_sys::Date::now() as u64,
        })),

        // Echo — returns body as-is (for latency measurement)
        (Method::Post, "/echo") => {
            let body = req.bytes().await.map_err(|e| Error::from(format!("{e}")))?;
            Response::from_bytes(body)
        }

        // Durable Object routes — proxied to MpcStorage DO
        (Method::Post, p) if p.starts_with("/do/") => {
            let namespace = env.durable_object("MPC_STORAGE")?;
            let id = namespace.id_from_name("default")?;
            let stub = id.get_stub()?;
            stub.fetch_with_request(req).await
        }

        // MPC protocol routes
        (Method::Post, "/mpc/dkg-round") => handle_dkg_round(req).await,
        (Method::Post, "/mpc/sign-round") => handle_sign_round(req).await,

        _ => Response::error("Not Found", 404),
    };

    // Add CORS headers to all responses
    response.map(|mut r| {
        let headers = r.headers_mut();
        let _ = headers.set("Access-Control-Allow-Origin", "*");
        let _ = headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        let _ = headers.set("Access-Control-Allow-Headers", "Content-Type");
        r
    })
}

// ============================================================================
// MPC DKG keygen round handler (deterministic replay)
//
// Each request: client sends ALL accumulated messages so far.
// Worker replays protocol from scratch with deterministic RNG.
// Returns ALL server messages produced (client ignores already-seen ones).
// ============================================================================

async fn handle_dkg_round(mut req: Request) -> Result<Response> {
    let body: DkgRoundRequest = req
        .json()
        .await
        .map_err(|e| Error::from(format!("bad request: {e}")))?;

    let seed = parse_seed(&body.session_seed).map_err(Error::from)?;
    let eid = cggmp24::ExecutionId::new(&seed);
    let n = body.n;
    let t = body.t;
    let client_messages = body.client_messages;

    use cggmp24::supported_curves::Secp256k1;

    // Create state machine with deterministic RNG — same seed produces same messages
    let mut sm = round_based::state_machine::wrap_protocol(|party| async move {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
        cggmp24::keygen::<Secp256k1>(eid, 0, n)
            .set_threshold(t)
            .start(&mut rng, party)
            .await
    });

    // Drive the state machine, feeding all accumulated client messages
    let mut server_messages = Vec::new();
    let mut client_idx = 0;
    let mut msg_id = 0u64;

    loop {
        match sm.proceed() {
            ProceedResult::SendMsg(outgoing) => {
                server_messages.push(outgoing_to_wire(0, outgoing));
            }
            ProceedResult::NeedsOneMoreMessage => {
                if client_idx >= client_messages.len() {
                    break; // Need more client messages — return what we have
                }
                msg_id += 1;
                let incoming = wire_to_incoming(client_messages[client_idx].clone(), msg_id);
                sm.received_msg(incoming)
                    .map_err(|_| Error::from("SM rejected message".to_string()))?;
                client_idx += 1;
            }
            ProceedResult::Yielded => {}
            ProceedResult::Output(result) => {
                let share: cggmp24::IncompleteKeyShare<Secp256k1> =
                    result.map_err(|e| Error::from(format!("DKG error: {e:?}")))?;
                let pubkey_bytes = share.shared_public_key.to_bytes(true);
                return Response::from_json(&DkgRoundResponse {
                    status: "complete".into(),
                    server_messages,
                    joint_pubkey: Some(hex::encode(&pubkey_bytes)),
                });
            }
            ProceedResult::Error(err) => {
                return Response::error(format!("Protocol error: {err}"), 500);
            }
        }
    }

    Response::from_json(&DkgRoundResponse {
        status: "in_progress".into(),
        server_messages,
        joint_pubkey: None,
    })
}

// ============================================================================
// MPC Signing round handler (deterministic replay)
//
// Same pattern as DKG: deterministic replay from scratch each request.
// Key share is passed in the request body (serialized JSON).
// ============================================================================

async fn handle_sign_round(mut req: Request) -> Result<Response> {
    let body: SignRoundRequest = req
        .json()
        .await
        .map_err(|e| Error::from(format!("bad request: {e}")))?;

    let seed = parse_seed(&body.session_seed).map_err(Error::from)?;
    let eid = cggmp24::ExecutionId::new(&seed);

    let data_bytes = hex::decode(&body.data_to_sign_hex)
        .map_err(|e| Error::from(format!("bad data_to_sign: {e}")))?;

    // Deserialize key share from JSON
    let key_share: cggmp24::KeyShare<cggmp24::supported_curves::Secp256k1> =
        serde_json::from_str(&body.key_share_json)
            .map_err(|e| Error::from(format!("bad key_share: {e}")))?;

    let participants: Vec<u16> = vec![0, 1];
    let client_messages = body.client_messages;

    use cggmp24::signing::DataToSign;
    use cggmp24::supported_curves::Secp256k1;
    use sha2::Sha256;

    let data_to_sign = DataToSign::digest::<Sha256>(&data_bytes);

    let mut sm = round_based::state_machine::wrap_protocol(|party| async move {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
        cggmp24::signing(eid, 0, &participants, &key_share)
            .sign(&mut rng, party, &data_to_sign)
            .await
    });

    let mut server_messages = Vec::new();
    let mut client_idx = 0;
    let mut msg_id = 0u64;

    loop {
        match sm.proceed() {
            ProceedResult::SendMsg(outgoing) => {
                server_messages.push(outgoing_to_wire(0, outgoing));
            }
            ProceedResult::NeedsOneMoreMessage => {
                if client_idx >= client_messages.len() {
                    break;
                }
                msg_id += 1;
                let incoming = wire_to_incoming(client_messages[client_idx].clone(), msg_id);
                sm.received_msg(incoming)
                    .map_err(|_| Error::from("SM rejected message".to_string()))?;
                client_idx += 1;
            }
            ProceedResult::Yielded => {}
            ProceedResult::Output(result) => {
                let sig: cggmp24::Signature<Secp256k1> =
                    result.map_err(|e| Error::from(format!("Signing error: {e:?}")))?;
                let mut sig_bytes = [0u8; 64];
                sig.write_to_slice(&mut sig_bytes);
                return Response::from_json(&SignRoundResponse {
                    status: "complete".into(),
                    server_messages,
                    signature_hex: Some(hex::encode(sig_bytes)),
                });
            }
            ProceedResult::Error(err) => {
                return Response::error(format!("Protocol error: {err}"), 500);
            }
        }
    }

    Response::from_json(&SignRoundResponse {
        status: "in_progress".into(),
        server_messages,
        signature_hex: None,
    })
}

// ============================================================================
// Durable Object: MpcStorage
//
// Stores key shares and protocol state in DO KV storage.
// Also attempts DO SQLite for POC validation.
// ============================================================================

#[durable_object]
pub struct MpcStorage {
    state: State,
    env: Env,
}

impl DurableObject for MpcStorage {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let path = req.path();

        match path.as_str() {
            "/do/put" => {
                let body: DoKvPut = req.json().await?;
                self.state.storage().put(&body.key, &body.value).await?;
                Response::from_json(&serde_json::json!({
                    "status": "ok",
                    "key": body.key
                }))
            }
            "/do/get" => {
                let body: DoKvGet = req.json().await?;
                let value: Option<String> = self.state.storage().get(&body.key).await?;
                Response::from_json(&serde_json::json!({
                    "key": body.key,
                    "value": value.unwrap_or_default()
                }))
            }
            "/do/delete" => {
                let body: DoKvGet = req.json().await?;
                self.state.storage().delete(&body.key).await?;
                Response::from_json(&serde_json::json!({
                    "status": "ok",
                    "key": body.key
                }))
            }
            _ => Response::error("Not Found", 404),
        }
    }
}
