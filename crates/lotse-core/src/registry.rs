//! The factory registries the binary fills at startup: sources by scheme,
//! outputs by kind, transcoders as a list. Nothing else in the tree names
//! a concrete source or output.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::output::OutputFactory;
use crate::source::SourceFactory;
use crate::transcode::{Transcoder, UplinkFactory};

/// Why a registration was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    /// Two factories claim the same scheme.
    #[error("scheme {0} is already registered")]
    DuplicateScheme(&'static str),
    /// Two factories claim the same output kind.
    #[error("output kind {0} is already registered")]
    DuplicateOutput(&'static str),
    /// A factory declares no scheme at all.
    #[error("source factory declares no scheme")]
    NoScheme,
}

/// Source factories by scheme.
#[derive(Debug, Default)]
pub struct SourceRegistry {
    /// Scheme → factory. Sorted, so `schemes()` is stable.
    by_scheme: BTreeMap<&'static str, Arc<dyn SourceFactory>>,
}

impl SourceRegistry {
    /// Registers `factory` for every scheme it declares.
    pub fn register(&mut self, factory: Arc<dyn SourceFactory>) -> Result<(), RegistryError> {
        let schemes = factory.schemes();
        let Some((last, rest)) = schemes.split_last() else {
            return Err(RegistryError::NoScheme);
        };
        if let Some(taken) = schemes
            .iter()
            .find(|scheme| self.by_scheme.contains_key(*scheme))
        {
            return Err(RegistryError::DuplicateScheme(taken));
        }
        for scheme in rest {
            self.by_scheme.insert(scheme, Arc::clone(&factory));
        }
        self.by_scheme.insert(last, factory);
        Ok(())
    }

    /// The factory for `scheme`, if one is registered.
    pub fn get(&self, scheme: &str) -> Option<&Arc<dyn SourceFactory>> {
        self.by_scheme.get(scheme)
    }

    /// Every registered scheme, sorted: `info.schemes`.
    pub fn schemes(&self) -> Vec<&'static str> {
        self.by_scheme.keys().copied().collect()
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
    /// Sources by scheme.
    pub sources: SourceRegistry,
    /// Outputs by kind.
    pub outputs: OutputRegistry,
    /// Transcoders.
    pub transcoders: TranscoderRegistry,
    /// The talk-back transcoder, apart from `transcoders` so negotiation
    /// never offers a viewer a talk-back conversion; `None` forwards only
    /// an uplink already in the device's codec.
    pub uplink: Option<Arc<dyn UplinkFactory>>,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;
    use crate::output::OutputShape;
    use crate::test_util::{FakeOutputFactory, FakeSourceFactory, FakeTranscoder};

    #[test]
    fn sources_register_by_scheme_once() {
        let mut registry = SourceRegistry::default();
        registry
            .register(Arc::new(FakeSourceFactory::new(&["fake", "fakes"])))
            .unwrap();
        assert_eq!(registry.schemes(), ["fake", "fakes"]);
        assert!(registry.get("fake").is_some());
        assert!(registry.get("rtsp").is_none());
        assert_eq!(
            registry
                .register(Arc::new(FakeSourceFactory::new(&["other", "fake"])))
                .unwrap_err(),
            RegistryError::DuplicateScheme("fake")
        );
        assert!(
            registry.get("other").is_none(),
            "nothing of a refused factory"
        );
        assert_eq!(
            registry
                .register(Arc::new(FakeSourceFactory::new(&[])))
                .unwrap_err(),
            RegistryError::NoScheme
        );
    }

    #[test]
    fn outputs_register_by_kind_once() {
        let mut registry = OutputRegistry::default();
        registry
            .register(Arc::new(FakeOutputFactory("webrtc", OutputShape::Session)))
            .unwrap();
        assert_eq!(registry.kinds(), ["webrtc"]);
        assert_eq!(
            registry.get("webrtc").unwrap().shape(),
            OutputShape::Session
        );
        assert_eq!(
            registry
                .register(Arc::new(FakeOutputFactory("webrtc", OutputShape::Request)))
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
        assert!(registries.sources.schemes().is_empty());
        assert!(registries.outputs.kinds().is_empty());
        assert_eq!(
            RegistryError::DuplicateScheme("x").to_string(),
            "scheme x is already registered"
        );
        assert_eq!(
            RegistryError::DuplicateOutput("x").to_string(),
            "output kind x is already registered"
        );
        assert_eq!(
            RegistryError::NoScheme.to_string(),
            "source factory declares no scheme"
        );
    }
}
