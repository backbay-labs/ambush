//! The console's daemon surface: one client module, one route table.
//!
//! Everything the console sends to a daemon host goes through
//! [`daemon_client`]; INV-01's five-route write table lives there and nothing
//! outside it opens a socket to the daemon.

pub mod daemon_client;
