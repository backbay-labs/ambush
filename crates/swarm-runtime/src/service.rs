use crate::config::RuntimeSettings;
use crate::{RuntimeMode, SwarmRuntime};
use swarm_policy::ApprovalGate;
use swarm_response::ResponseExecutor;

/// Thin service wrapper around the first Rust-only runtime slice.
pub struct RuntimeService<P, E> {
    pub config: RuntimeSettings,
    pub runtime: SwarmRuntime<P, E>,
}

impl<P, E> RuntimeService<P, E>
where
    P: ApprovalGate,
    E: ResponseExecutor,
{
    pub fn new(config: RuntimeSettings, runtime: SwarmRuntime<P, E>) -> Self {
        Self { config, runtime }
    }

    pub fn mode(&self) -> RuntimeMode {
        self.runtime.mode()
    }
}
