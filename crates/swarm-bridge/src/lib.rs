//! Legacy PyO3 bridge.
//!
//! The production direction is now Rust-first, but the bridge remains as a
//! compatibility shim while ideas from the older Python control plane are
//! translated into native Rust services.

use pyo3::prelude::*;

#[pymodule]
fn _bridge(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    // Intentionally minimal while the runtime migrates toward pure Rust.
    Ok(())
}
