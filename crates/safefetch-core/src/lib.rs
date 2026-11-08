//! SafeFetch core: download → quarantine → scan → verdict → delivery.
//!
//! This crate has no GUI dependency; the Tauri app is a thin adapter.

pub mod archive;
pub mod delivery;
pub mod download;
pub mod engine;
pub mod error;
pub mod fsutil;
pub mod hash;
pub mod history;
pub mod input;
pub mod net;
pub mod quarantine;
pub mod sanitize;
pub mod scanners;
pub mod secrets;
pub mod settings;
pub mod verdict;

pub use engine::{Engine, EngineConfig, EventSink, JobSnapshot, NullSink, Outcome, Stage};
pub use error::{Error, Result};
