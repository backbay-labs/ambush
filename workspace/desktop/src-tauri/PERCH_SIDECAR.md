# Bundling the laptop detector

`swarm_detect` is **not** in the default `externalBin` list, and that is
deliberate. Tauri fails a build when a declared external binary is missing, so
adding it to `tauri.conf.json` would break every build that has not first run
the engine workspace's release build — which is most of them. And a security
daemon shipped inside a chat app that nobody asked for is a surprise, not a
feature.

To build with it:

```bash
# The engine workspace, at the repository ROOT — a different Rust toolchain and
# edition than the desktop app's.
cargo build --release -p swarm-runtime-http --bin swarm_detect

cd workspace
PERCH_SIDECAR=1 bash scripts/bundle-sidecars.sh
cd desktop
pnpm tauri build --config src-tauri/tauri.perch.conf.json
```

`tauri.perch.conf.json` is an overlay carrying only the `externalBin` list with
`binaries/swarm_detect` appended; everything else comes from
`tauri.conf.json`.

Without it, the three `perch_sidecar_*` commands still exist and
`perch_sidecar_start` answers `the swarm_detect sidecar is not bundled in this
build`. The settings panel renders that message rather than a broken control.
