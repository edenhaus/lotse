//! The JSON Schema bundle: every message's schema, generated from the types
//! and committed as `schema/api.json`, returned by the `schema` command and
//! diffed in CI so an incompatible change cannot slip through.
//!
//! Regenerate with `cargo run -p lotse-api-types --example schema >
//! crates/lotse-api-types/schema/api.json`.

use schemars::JsonSchema;
use schemars::generate::{SchemaGenerator, SchemaSettings};
use serde_json::{Map, Value, json};

use crate::API_VERSION;
use crate::command::Command;
use crate::frame::{Empty, EventFrame, Failure, Hello, Pong, Shutdown, Success};
use crate::info::{InfoResult, Metrics};
use crate::session::{Session, SessionEvent, SessionList};
use crate::stream::{BackchannelReleaseResult, Stream, StreamEvent, StreamList, StreamPutResult};

/// The committed bundle, byte for byte.
pub const COMMITTED: &str = include_str!("../schema/api.json");

/// A `$ref` to `T`'s schema, which `generator` keeps in its definitions.
fn reference<T: JsonSchema>(generator: &mut SchemaGenerator) -> Value {
    serde_json::to_value(generator.subschema_for::<T>()).unwrap_or(Value::Null)
}

/// The bundle: frames, commands, their results, and events, each a `$ref`
/// into one shared `$defs`, so the bundle is a single valid JSON Schema
/// document that tools (the Python client's generator) read as it is.
pub fn bundle() -> Value {
    let mut generator = SchemaSettings::draft2020_12().into_generator();
    let mut results = Map::new();
    results.insert("ping".into(), reference::<Pong>(&mut generator));
    results.insert(
        "info".into(),
        reference::<Success<InfoResult>>(&mut generator),
    );
    results.insert(
        "metrics/get".into(),
        reference::<Success<Metrics>>(&mut generator),
    );
    results.insert("schema".into(), reference::<Success<Value>>(&mut generator));
    results.insert(
        "stream/put".into(),
        reference::<Success<StreamPutResult>>(&mut generator),
    );
    results.insert(
        "stream/get".into(),
        reference::<Success<Stream>>(&mut generator),
    );
    results.insert(
        "stream/list".into(),
        reference::<Success<StreamList>>(&mut generator),
    );
    for name in [
        "stream/delete",
        "stream/subscribe",
        "unsubscribe",
        "webrtc/offer",
        "webrtc/candidate",
        "session/close",
        "session/adopt",
    ] {
        results.insert(name.into(), reference::<Success<Empty>>(&mut generator));
    }
    results.insert(
        "session/get".into(),
        reference::<Success<Session>>(&mut generator),
    );
    results.insert(
        "session/list".into(),
        reference::<Success<SessionList>>(&mut generator),
    );
    results.insert(
        "backchannel/release".into(),
        reference::<Success<BackchannelReleaseResult>>(&mut generator),
    );
    let hello = reference::<Hello>(&mut generator);
    let shutdown = reference::<Shutdown>(&mut generator);
    let command = reference::<Command>(&mut generator);
    let failure = reference::<Failure>(&mut generator);
    let stream_events = reference::<EventFrame<StreamEvent>>(&mut generator);
    let session_events = reference::<EventFrame<SessionEvent>>(&mut generator);
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "lotse control API",
        "api": API_VERSION,
        "hello": hello,
        "shutdown": shutdown,
        "command": command,
        "failure": failure,
        "results": results,
        "events": {
            "stream/subscribe": stream_events,
            "webrtc/offer": session_events,
            "session/adopt": session_events,
        },
        "$defs": generator.take_definitions(true),
    })
}

/// The bundle as pretty JSON with a trailing newline, as committed.
pub fn bundle_text() -> String {
    let mut text = serde_json::to_string_pretty(&bundle()).unwrap_or_default();
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;

    #[test]
    fn the_committed_bundle_matches_the_types() {
        assert_eq!(
            COMMITTED,
            bundle_text(),
            "schema/api.json is stale: regenerate with `cargo run -p lotse-api-types --example schema > crates/lotse-api-types/schema/api.json`"
        );
    }

    /// `schema` itself, or the shared definition its `$ref` names.
    fn resolve<'a>(bundle: &'a Value, schema: &'a Value) -> &'a Value {
        match schema["$ref"].as_str() {
            Some(reference) => {
                let name = reference
                    .strip_prefix("#/$defs/")
                    .expect("a $defs reference");
                &bundle["$defs"][name]
            }
            None => schema,
        }
    }

    /// The one value a frame's `type` may take, whether the schema spells
    /// it `const`, a one-element `enum` or a one-constant `oneOf`.
    fn tag_of(bundle: &Value, schema: &Value) -> String {
        let property = resolve(bundle, &resolve(bundle, schema)["properties"]["type"]);
        let tag = property["const"]
            .as_str()
            .or_else(|| property["enum"][0].as_str())
            .or_else(|| property["oneOf"][0]["const"].as_str());
        assert!(tag.is_some(), "no tag in {property}");
        tag.unwrap().to_owned()
    }

    /// Every `$ref` anywhere under `value`.
    fn references(value: &Value, found: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                if let Some(Value::String(reference)) = map.get("$ref") {
                    found.push(reference.clone());
                }
                map.values().for_each(|v| references(v, found));
            }
            Value::Array(items) => items.iter().for_each(|v| references(v, found)),
            _ => {}
        }
    }

    #[test]
    fn the_bundle_is_one_document_whose_references_all_resolve() {
        let bundle = bundle();
        let mut found = Vec::new();
        references(&bundle, &mut found);
        assert!(found.len() > 30, "{found:?}");
        for reference in found {
            let name = reference.strip_prefix("#/$defs/").expect("into $defs");
            assert!(bundle["$defs"][name].is_object(), "{reference} resolves");
        }
        assert!(
            !bundle["$defs"]
                .as_object()
                .unwrap()
                .values()
                .any(|d| d.get("$defs").is_some()),
            "definitions are not nested"
        );
    }

    #[test]
    fn the_bundle_carries_every_command_and_the_frame_tags() {
        let bundle = bundle();
        assert_eq!(bundle["api"], API_VERSION);
        let command = resolve(&bundle, &bundle["command"]);
        let variants = command["oneOf"].as_array().expect("tagged enum as oneOf");
        let names: Vec<&str> = variants
            .iter()
            .map(|v| {
                resolve(&bundle, v)["properties"]["type"]["const"]
                    .as_str()
                    .expect("type const")
            })
            .collect();
        assert_eq!(names, Command::NAMES);
        for name in Command::NAMES {
            assert!(
                resolve(&bundle, &bundle["results"][name]).is_object(),
                "{name}"
            );
        }
        assert_eq!(tag_of(&bundle, &bundle["hello"]), "hello");
        let failure = resolve(&bundle, &bundle["failure"]);
        assert_eq!(failure["properties"]["success"]["type"], "boolean");
        assert_eq!(tag_of(&bundle, &bundle["failure"]), "result");
        assert_eq!(tag_of(&bundle, &bundle["results"]["stream/get"]), "result");
        assert_eq!(tag_of(&bundle, &bundle["results"]["ping"]), "pong");
        assert_eq!(tag_of(&bundle, &bundle["shutdown"]), "shutdown");
        for name in ["stream/subscribe", "webrtc/offer", "session/adopt"] {
            assert_eq!(tag_of(&bundle, &bundle["events"][name]), "event", "{name}");
        }
        let put = variants
            .iter()
            .find(|v| v["properties"]["type"]["const"] == "stream/put")
            .unwrap();
        assert_eq!(
            put["additionalProperties"], false,
            "unknown fields are rejected"
        );
        assert!(
            put["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r == "stream_id")
        );
    }
}
