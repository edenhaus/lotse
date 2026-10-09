//! A control-API client for the load generator: one WebSocket on the
//! daemon's Unix socket for every command and subscription, as a
//! long-lived client holds one.
//!
//! One task owns the connection. It numbers commands in the order it sends
//! them (ids strictly increase per connection, §Message format), routes each
//! `result` to its caller by id and each `event` to its subscription, and
//! drops a subscription after its `closed` event (§WebRTC sessions).

use std::collections::HashMap;
use std::path::Path;

use futures_util::{SinkExt as _, StreamExt as _};
use lotse_core::task::spawn_named;
use serde_json::{Map, Value};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

/// A command's outcome: the id it was sent under and its `result` frame's
/// payload, or the error's `code: message`.
pub type Outcome = Result<(u64, Value), String>;

/// A command on its way to the connection task.
#[derive(Debug)]
struct Pending {
    /// The command without its `id`.
    frame: Map<String, Value>,
    /// Where its result goes.
    result: oneshot::Sender<Outcome>,
    /// Where its events go, for a subscription.
    events: Option<mpsc::UnboundedSender<Value>>,
}

/// The client.
#[derive(Debug)]
pub struct Control {
    /// Commands for the connection task.
    commands: mpsc::UnboundedSender<Pending>,
    /// The connection task; it ends when the daemon closes or the client
    /// is dropped.
    task: JoinHandle<()>,
}

impl Control {
    /// Connects to the control socket at `path` and reads `hello`, which
    /// it returns with the client.
    pub async fn connect(path: &Path) -> Result<(Self, Value), String> {
        let socket = UnixStream::connect(path)
            .await
            .map_err(|err| format!("the control socket {}: {err}", path.display()))?;
        let (mut ws, _response) = tokio_tungstenite::client_async(
            &format!("ws://lotse{}", lotse_api_types::WS_PATH),
            socket,
        )
        .await
        .map_err(|err| format!("the WebSocket upgrade: {err}"))?;
        let hello = loop {
            match ws.next().await {
                Some(Ok(Message::Text(text))) => {
                    break serde_json::from_str::<Value>(&text)
                        .map_err(|err| format!("hello: {err}"))?;
                }
                Some(Ok(_)) => {}
                Some(Err(err)) => return Err(format!("hello: {err}")),
                None => return Err("the daemon closed before hello".to_owned()),
            }
        };
        if hello.get("type").and_then(Value::as_str) != Some("hello") {
            return Err(format!("expected hello, got {hello}"));
        }
        let (commands, inbox) = mpsc::unbounded_channel();
        let task = spawn_named("load.control", run(ws, inbox));
        Ok((Self { commands, task }, hello))
    }

    /// Sends `frame` (a JSON object without `id`) and waits for its
    /// result.
    pub async fn command(&self, frame: Value) -> Outcome {
        self.send(frame, None).await
    }

    /// Sends a subscription command and waits for its result; its events
    /// arrive on the receiver, `closed` last.
    pub async fn subscribe(
        &self,
        frame: Value,
    ) -> Result<(u64, Value, mpsc::UnboundedReceiver<Value>), String> {
        let (events, receiver) = mpsc::unbounded_channel();
        let (id, result) = self.send(frame, Some(events)).await?;
        Ok((id, result, receiver))
    }

    /// Hands a command to the connection task.
    async fn send(&self, frame: Value, events: Option<mpsc::UnboundedSender<Value>>) -> Outcome {
        let Value::Object(frame) = frame else {
            return Err("a command is a JSON object".to_owned());
        };
        let (result, outcome) = oneshot::channel();
        self.commands
            .send(Pending {
                frame,
                result,
                events,
            })
            .map_err(|_closed| "the control connection is closed".to_owned())?;
        outcome
            .await
            .map_err(|_closed| "the control connection closed before the result".to_owned())?
    }

    /// Closes the connection.
    pub async fn close(self) {
        drop(self.commands);
        let _joined = self.task.await;
    }
}

/// The connection task: sends commands, routes results and events, until
/// the daemon or the client goes.
async fn run<S>(
    mut ws: tokio_tungstenite::WebSocketStream<S>,
    mut inbox: mpsc::UnboundedReceiver<Pending>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut next_id = 1_u64;
    let mut waiting: HashMap<u64, oneshot::Sender<Outcome>> = HashMap::new();
    let mut subscriptions: HashMap<u64, mpsc::UnboundedSender<Value>> = HashMap::new();
    loop {
        tokio::select! {
            pending = inbox.recv() => {
                let Some(Pending { mut frame, result, events }) = pending else {
                    let _closed = ws.close(None).await;
                    return;
                };
                let id = next_id;
                next_id = next_id.saturating_add(1);
                frame.insert("id".to_owned(), Value::from(id));
                if let Some(events) = events {
                    subscriptions.insert(id, events);
                }
                waiting.insert(id, result);
                if ws.send(Message::text(Value::Object(frame).to_string())).await.is_err() {
                    return;
                }
            }
            frame = ws.next() => {
                let Some(Ok(message)) = frame else {
                    return;
                };
                let Message::Text(text) = message else {
                    continue;
                };
                let Ok(frame) = serde_json::from_str::<Value>(&text) else {
                    continue;
                };
                route(&frame, &mut waiting, &mut subscriptions);
            }
        }
    }
}

/// Delivers one frame from the daemon.
fn route(
    frame: &Value,
    waiting: &mut HashMap<u64, oneshot::Sender<Outcome>>,
    subscriptions: &mut HashMap<u64, mpsc::UnboundedSender<Value>>,
) {
    let Some(id) = frame.get("id").and_then(Value::as_u64) else {
        return;
    };
    match frame.get("type").and_then(Value::as_str) {
        Some("result") => {
            let Some(result) = waiting.remove(&id) else {
                return;
            };
            let outcome = if frame.get("success").and_then(Value::as_bool) == Some(true) {
                Ok((id, frame.get("result").cloned().unwrap_or(Value::Null)))
            } else {
                subscriptions.remove(&id);
                let error = frame.get("error");
                let field = |name| {
                    error
                        .and_then(|error| error.get(name))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned()
                };
                Err(format!("{}: {}", field("code"), field("message")))
            };
            let _gone = result.send(outcome);
        }
        Some("event") => {
            let Some(event) = frame.get("event") else {
                return;
            };
            let closed = event.get("type").and_then(Value::as_str) == Some("closed");
            if let Some(events) = subscriptions.get(&id) {
                let _gone = events.send(event.clone());
            }
            if closed {
                subscriptions.remove(&id);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use serde_json::json;

    use super::*;

    #[test]
    fn results_and_events_reach_their_command_by_id() {
        let mut waiting = HashMap::new();
        let mut subscriptions = HashMap::new();
        let (ok_tx, mut ok_rx) = oneshot::channel();
        let (err_tx, mut err_rx) = oneshot::channel();
        let (sub_tx, mut sub_rx) = oneshot::channel();
        let (events, mut event_rx) = mpsc::unbounded_channel();
        let (failed_events, mut failed_rx) = mpsc::unbounded_channel();
        waiting.insert(1, ok_tx);
        waiting.insert(2, err_tx);
        waiting.insert(3, sub_tx);
        subscriptions.insert(2, failed_events);
        subscriptions.insert(3, events);

        route(&json!({"type": "hello"}), &mut waiting, &mut subscriptions);
        route(
            &json!({"id": 9, "type": "result", "success": true}),
            &mut waiting,
            &mut subscriptions,
        );
        route(
            &json!({"id": 1, "type": "result", "success": true, "result": {"created": true}}),
            &mut waiting,
            &mut subscriptions,
        );
        assert_eq!(ok_rx.try_recv().unwrap(), Ok((1, json!({"created": true}))));
        route(
            &json!({"id": 2, "type": "result", "success": false,
                    "error": {"code": "limit_reached", "message": "too many"}}),
            &mut waiting,
            &mut subscriptions,
        );
        assert_eq!(
            err_rx.try_recv().unwrap(),
            Err("limit_reached: too many".to_owned())
        );
        assert!(
            !subscriptions.contains_key(&2),
            "a failed subscription has no events"
        );
        drop(failed_rx.try_recv());

        route(
            &json!({"id": 3, "type": "result", "success": true}),
            &mut waiting,
            &mut subscriptions,
        );
        assert_eq!(sub_rx.try_recv().unwrap(), Ok((3, Value::Null)));
        route(
            &json!({"id": 3, "type": "event", "event": {"type": "answer", "sdp": "v=0"}}),
            &mut waiting,
            &mut subscriptions,
        );
        route(
            &json!({"id": 3, "type": "event"}),
            &mut waiting,
            &mut subscriptions,
        );
        route(
            &json!({"id": 3, "type": "event", "event": {"type": "closed", "code": "session_closed"}}),
            &mut waiting,
            &mut subscriptions,
        );
        assert_eq!(event_rx.try_recv().unwrap()["type"], "answer");
        assert_eq!(event_rx.try_recv().unwrap()["type"], "closed");
        assert!(subscriptions.is_empty(), "closed ends the subscription");
        assert!(waiting.is_empty());
    }
}
