//! The factory registries the binary fills at startup: sources by
//! protocol, those lotse connects to by URL and those whose signaling the
//! client relays, outputs by kind, transcoders as a list, the recording
//! container in its own slot. Nothing else in the tree names a concrete
//! source or output.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::output::OutputFactory;
use crate::recording::RecordingMuxerFactory;
use crate::source::{SignaledSourceFactory, SourceFactory};
use crate::transcode::{Transcoder, UplinkFactory};

/// Why a registration was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    /// Two factories claim the same protocol, of either kind.
    #[error("protocol {0} is already registered")]
    DuplicateProtocol(&'static str),
    /// Two factories claim the same output kind.
    #[error("output kind {0} is already registered")]
    DuplicateOutput(&'static str),
    /// A factory declares no protocol at all.
    #[error("source factory declares no protocol")]
    NoProtocol,
}

/// Source factories by protocol, one namespace for both kinds: those of
/// sources lotse connects to by URL, whose protocols are their URLs'
/// schemes, and those of signaled sources. A protocol has one factory.
#[derive(Debug, Default)]
pub struct SourceRegistry {
    /// URL protocol → factory.
    by_url: BTreeMap<&'static str, Arc<dyn SourceFactory>>,
    /// Signaled protocol → factory.
    by_signaled: BTreeMap<&'static str, Arc<dyn SignaledSourceFactory>>,
}

impl SourceRegistry {
    /// Whether `protocol` is taken, by a factory of either kind.
    fn taken(&self, protocol: &str) -> bool {
        self.by_url.contains_key(protocol) || self.by_signaled.contains_key(protocol)
    }

    /// Registers `factory` for every protocol it declares.
    pub fn register(&mut self, factory: Arc<dyn SourceFactory>) -> Result<(), RegistryError> {
        let protocols = factory.protocols();
        let Some((last, rest)) = protocols.split_last() else {
            return Err(RegistryError::NoProtocol);
        };
        if let Some(taken) = protocols.iter().find(|protocol| self.taken(protocol)) {
            return Err(RegistryError::DuplicateProtocol(taken));
        }
        for protocol in rest {
            self.by_url.insert(protocol, Arc::clone(&factory));
        }
        self.by_url.insert(last, factory);
        Ok(())
    }

    /// The URL factory for `protocol`, if one is registered.
    pub fn get(&self, protocol: &str) -> Option<&Arc<dyn SourceFactory>> {
        self.by_url.get(protocol)
    }

    /// Registers the signaled `factory` under its protocol.
    pub fn register_signaled(
        &mut self,
        factory: Arc<dyn SignaledSourceFactory>,
    ) -> Result<(), RegistryError> {
        let protocol = factory.protocol();
        if self.taken(protocol) {
            return Err(RegistryError::DuplicateProtocol(protocol));
        }
        self.by_signaled.insert(protocol, factory);
        Ok(())
    }

    /// The signaled factory for `protocol`, if one is registered.
    pub fn signaled(&self, protocol: &str) -> Option<&Arc<dyn SignaledSourceFactory>> {
        self.by_signaled.get(protocol)
    }

    /// Every registered protocol, of both kinds, sorted: `info.protocols`.
    pub fn protocols(&self) -> Vec<&'static str> {
        let mut protocols: Vec<_> = self
            .by_url
            .keys()
            .chain(self.by_signaled.keys())
            .copied()
            .collect();
        protocols.sort_unstable();
        protocols
    }
}

/// Output factories by kind.
#[derive(Debug, Default)]
pub struct OutputRegistry {
    /// Kind → factory. Sorted, so `kinds()` is stable.
    by_kind: BTreeMap<&'static str, Arc<dyn OutputFactory>>,
}

impl OutputRegistry {
    /// Registers `factory` under its kind.
    pub fn register(&mut self, factory: Arc<dyn OutputFactory>) -> Result<(), RegistryError> {
        let kind = factory.kind();
        if self.by_kind.contains_key(kind) {
            return Err(RegistryError::DuplicateOutput(kind));
        }
        self.by_kind.insert(kind, factory);
        Ok(())
    }

    /// The factory for `kind`, if one is registered.
    pub fn get(&self, kind: &str) -> Option<&Arc<dyn OutputFactory>> {
        self.by_kind.get(kind)
    }

    /// Every registered kind, sorted: `info.outputs`.
    pub fn kinds(&self) -> Vec<&'static str> {
        self.by_kind.keys().copied().collect()
    }
}

/// The transcoders available, in registration order (the order negotiation
/// tries them).
#[derive(Debug, Default)]
pub struct TranscoderRegistry {
    /// The transcoders.
    list: Vec<Arc<dyn Transcoder>>,
}

impl TranscoderRegistry {
    /// Adds a transcoder.
    pub fn register(&mut self, transcoder: Arc<dyn Transcoder>) {
        self.list.push(transcoder);
    }

    /// The transcoders, in registration order.
    pub fn all(&self) -> &[Arc<dyn Transcoder>] {
        &self.list
    }
}

/// Everything the binary registers, handed to the supervisor and the worker.
#[derive(Debug, Default)]
pub struct Registries {
    /// Sources by protocol.
    pub sources: SourceRegistry,
    /// Outputs by kind.
    pub outputs: OutputRegistry,
    /// Transcoders.
    pub transcoders: TranscoderRegistry,
    /// The talk-back transcoder, apart from `transcoders` so negotiation
    /// never offers a viewer a talk-back conversion; `None` forwards only
    /// an uplink already in the device's codec.
    pub uplink: Option<Arc<dyn UplinkFactory>>,
    /// The container event recordings are written in, apart from `outputs`
    /// since a recording is no session; `None` runs no recording.
    pub recording: Option<Arc<dyn RecordingMuxerFactory>>,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;
    use crate::test_util::{
        FakeOutputFactory, FakeSignaledSourceFactory, FakeSourceFactory, FakeTranscoder,
    };

    #[test]
    fn sources_register_by_protocol_once() {
        let mut registry = SourceRegistry::default();
        registry
            .register(Arc::new(FakeSourceFactory::new(&["fakes", "fake"])))
            .unwrap();
        assert_eq!(registry.protocols(), ["fake", "fakes"]);
        assert!(registry.get("fake").is_some());
        assert!(registry.get("rtsp").is_none());
        assert_eq!(
            registry
                .register(Arc::new(FakeSourceFactory::new(&["other", "fake"])))
                .unwrap_err(),
            RegistryError::DuplicateProtocol("fake")
        );
        assert!(
            registry.get("other").is_none(),
            "nothing of a refused factory"
        );
        assert_eq!(
            registry
                .register(Arc::new(FakeSourceFactory::new(&[])))
                .unwrap_err(),
            RegistryError::NoProtocol
        );
    }

    #[test]
    fn url_and_signaled_protocols_share_one_namespace() {
        let mut registry = SourceRegistry::default();
        registry
            .register(Arc::new(FakeSourceFactory::new(&["fake"])))
            .unwrap();
        registry
            .register_signaled(Arc::new(FakeSignaledSourceFactory::new("fake-signaled")))
            .unwrap();
        registry
            .register_signaled(Arc::new(FakeSignaledSourceFactory::new("another")))
            .unwrap();
        assert_eq!(registry.protocols(), ["another", "fake", "fake-signaled"]);
        assert_eq!(
            registry.signaled("fake-signaled").unwrap().protocol(),
            "fake-signaled"
        );
        assert!(registry.signaled("fake").is_none(), "a URL protocol");
        assert!(registry.get("fake-signaled").is_none(), "a signaled one");
        // One protocol, one factory: a protocol taken by either kind.
        for taken in ["fake-signaled", "fake"] {
            assert_eq!(
                registry
                    .register_signaled(Arc::new(FakeSignaledSourceFactory::new(taken)))
                    .unwrap_err(),
                RegistryError::DuplicateProtocol(taken)
            );
        }
        assert_eq!(
            registry
                .register(Arc::new(FakeSourceFactory::new(&["other", "another"])))
                .unwrap_err(),
            RegistryError::DuplicateProtocol("another")
        );
        assert!(
            registry.get("other").is_none(),
            "nothing of a refused factory"
        );
        assert_eq!(
            RegistryError::DuplicateProtocol("x").to_string(),
            "protocol x is already registered"
        );
    }

    #[test]
    fn outputs_register_by_kind_once() {
        let mut registry = OutputRegistry::default();
        registry
            .register(Arc::new(FakeOutputFactory("webrtc")))
            .unwrap();
        assert_eq!(registry.kinds(), ["webrtc"]);
        assert_eq!(registry.get("webrtc").unwrap().kind(), "webrtc");
        assert_eq!(
            registry
                .register(Arc::new(FakeOutputFactory("webrtc")))
                .unwrap_err(),
            RegistryError::DuplicateOutput("webrtc")
        );
    }

    #[test]
    fn transcoders_keep_registration_order() {
        let mut registries = Registries::default();
        registries
            .transcoders
            .register(Arc::new(FakeTranscoder::aac_to_opus()));
        registries
            .transcoders
            .register(Arc::new(FakeTranscoder::aac_to_opus()));
        assert_eq!(registries.transcoders.all().len(), 2);
        assert!(
            registries.uplink.is_none(),
            "no talk-back transcoder by default"
        );
        assert!(
            registries.recording.is_none(),
            "no recording container by default"
        );
        assert_eq!(registries.sources.protocols(), Vec::<&str>::new());
        assert_eq!(registries.outputs.kinds(), Vec::<&str>::new());
        assert_eq!(
            RegistryError::DuplicateOutput("x").to_string(),
            "output kind x is already registered"
        );
        assert_eq!(
            RegistryError::NoProtocol.to_string(),
            "source factory declares no protocol"
        );
    }
}
