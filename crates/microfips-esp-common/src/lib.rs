//! Chip-agnostic ESP32 utilities: DNS resolver, config constants, UDP transport, node identity, and stats counters.

#![no_std]

extern crate alloc;

pub mod config;
pub mod dns;
pub mod node_info;
pub mod stats;
pub mod udp_transport;
