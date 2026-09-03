//! Thin `ambush-admin deletions` adapter.

pub use ambush_deletion::Command as DeletionsCommand;

/// Delegate to the shared durable deletion engine.
pub async fn run(command: DeletionsCommand) -> anyhow::Result<i32> {
    ambush_deletion::run(command).await
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    #[test]
    fn continuous_worker_command_is_not_exposed() {
        let command = crate::Cli::try_parse_from(["ambush-admin", "deletions", "worker"]);
        assert!(command.is_err());
    }
}
