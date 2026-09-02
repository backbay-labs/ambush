#![forbid(unsafe_code)]

use swarm_governance_witness::{
    initialize_store, load_store_initializer_process_config, load_store_proxy_process_config,
    run_store_proxy_process,
};

enum Command {
    Serve(std::ffi::OsString),
    Init(std::ffi::OsString),
}

fn command_from<I>(mut arguments: I) -> Result<Command, &'static str>
where
    I: Iterator<Item = std::ffi::OsString>,
{
    let first = arguments
        .next()
        .ok_or("a configuration path or `init` command is required")?;
    let command = if first == "init" {
        Command::Init(
            arguments
                .next()
                .ok_or("`init` requires exactly one configuration path")?,
        )
    } else {
        Command::Serve(first)
    };
    if arguments.next().is_some() {
        return Err("exactly one configuration path is required");
    }
    Ok(command)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os();
    let _binary = arguments.next();
    match command_from(arguments)? {
        Command::Serve(path) => {
            let config = load_store_proxy_process_config(path)?;
            run_store_proxy_process(config).await?;
        }
        Command::Init(path) => {
            let config = load_store_initializer_process_config(path)?;
            let ready = initialize_store(config).await?;
            let output = serde_json::to_vec(&ready)?;
            use std::io::Write;
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(&output)?;
            stdout.write_all(b"\n")?;
            stdout.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_init_and_legacy_serve_forms_without_ambiguity() {
        assert!(matches!(
            command_from(["init".into(), "init.json".into()].into_iter()),
            Ok(Command::Init(path)) if path == "init.json"
        ));
        assert!(matches!(
            command_from(["serve.json".into()].into_iter()),
            Ok(Command::Serve(path)) if path == "serve.json"
        ));
        assert!(command_from(["init".into()].into_iter()).is_err());
        assert!(command_from(["init".into(), "a".into(), "b".into()].into_iter()).is_err());
    }
}
