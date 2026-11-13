#![forbid(unsafe_code)]

pub mod agent;
pub mod auth;
pub mod channel;
pub mod client;
pub mod cpu;
pub mod error;
pub mod exec;
pub mod host_key;
pub mod kex;
pub mod known_hosts;
pub mod session;
pub mod stream;
pub mod terminal;
pub mod wire;

pub use auth::Identity;
pub use client::{ClientConfig, Connection, RekeyLimits};
pub use error::{Certainty, Error};
pub use exec::{ExecOptions, ExecResult, ExecStatus};
pub use session::{PtyRequest, SessionEvents, SessionRequest, TerminalSize};
pub use stream::{FileSink, InputSource, OutputSink, StreamOptions};
pub use wire::Interrupt;
pub use host_key::{Fingerprint, HostTrust};
pub use known_hosts::KnownHosts;
pub use oxish_graviola::DEFAULT_PROVIDER;
pub use oxish_proto;
