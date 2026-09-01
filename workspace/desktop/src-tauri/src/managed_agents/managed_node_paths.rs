use std::path::PathBuf;

pub(crate) fn ambush_managed_npm_prefix() -> Option<PathBuf> {
    dirs::data_dir().map(|dir| dir.join("Ambush").join("node-tools"))
}

const AMBUSH_MANAGED_NODE_VERSION: &str = "v24.18.0";

pub(crate) fn ambush_managed_node_root() -> Option<PathBuf> {
    dirs::data_dir().map(|dir| dir.join("Ambush").join("runtimes").join("node"))
}

pub(crate) fn ambush_managed_node_bin_dir() -> Option<PathBuf> {
    let (platform, bin_subdir): (&str, Option<&str>) =
        match (std::env::consts::OS, std::env::consts::ARCH) {
            ("macos", "aarch64") => ("darwin-arm64", Some("bin")),
            ("macos", "x86_64") => ("darwin-x64", Some("bin")),
            ("linux", "x86_64") => ("linux-x64", Some("bin")),
            ("linux", "aarch64") => ("linux-arm64", Some("bin")),
            // Windows zips have node.exe + npm.cmd at the archive root — no bin/ subdir
            ("windows", "x86_64") => ("win-x64", None),
            ("windows", "aarch64") => ("win-arm64", None),
            _ => return None,
        };
    ambush_managed_node_root().map(|root| {
        let dir = root.join(AMBUSH_MANAGED_NODE_VERSION).join(platform);
        match bin_subdir {
            Some(sub) => dir.join(sub),
            None => dir,
        }
    })
}

pub(crate) fn ambush_managed_node_bin_path() -> Option<PathBuf> {
    ambush_managed_node_bin_dir().map(|bin| {
        #[cfg(windows)]
        {
            bin.join("node.exe")
        }
        #[cfg(not(windows))]
        {
            bin.join("node")
        }
    })
}

pub(crate) fn ambush_managed_npm_bin_dir() -> Option<PathBuf> {
    ambush_managed_npm_prefix().map(|prefix| {
        #[cfg(windows)]
        {
            prefix
        }
        #[cfg(not(windows))]
        {
            prefix.join("bin")
        }
    })
}

pub(crate) fn ambush_managed_command_path(command: &str, basename: &str) -> Option<PathBuf> {
    if command.contains(std::path::MAIN_SEPARATOR)
        || !matches!(
            command,
            "codex-acp" | "claude-agent-acp" | "claude-code-acp" | "node" | "npm"
        )
    {
        return None;
    }

    let mut dirs = Vec::new();
    if let Some(managed_bin) = ambush_managed_npm_bin_dir() {
        dirs.push(managed_bin);
    }
    if let Some(managed_node_bin) = ambush_managed_node_bin_dir() {
        dirs.push(managed_node_bin);
    }

    dirs.into_iter()
        .map(|dir| dir.join(basename))
        .find(|candidate| is_executable_file(candidate))
}

fn is_executable_file(path: &std::path::Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }

    #[cfg(not(unix))]
    {
        true
    }
}
