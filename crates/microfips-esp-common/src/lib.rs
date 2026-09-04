//! Chip-agnostic ESP32 utilities: DNS resolver, config constants, UDP transport, node identity, and stats counters.

#![no_std]

extern crate alloc;

pub mod config;
pub mod dhcp_server;
pub mod dns;
pub mod espnow_frag;
pub mod espnow_peer;
pub mod mdns;
pub mod mdns_responder;
pub mod node_info;
pub mod stats;
pub mod udp_transport;
