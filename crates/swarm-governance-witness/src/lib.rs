#![forbid(unsafe_code)]

//! Downstream transport boundary for the authenticated governance witness.
//!
//! Stage One intentionally contains no JetStream adapter, service process, or
//! binary target. Transport implementations are added only after dependency
//! direction and package closure have been independently accepted.
