//! ADR 0014 C1 obligation 3: the set of commands that must call the gate is
//! asserted, not remembered. Every `#[tauri::command]` anywhere under `src/`
//! that signs renderer-supplied content — its body reaches a signing path
//! (`state.signing_keys()`, a `submit_event*` funnel, `sign_with_keys(`, or a
//! `submit_signed_event*` publish) and it takes a `content` of a
//! renderer-text type (`String`, `Option<String>`, `&str`, or their `Option`/
//! borrow spellings), either as a direct parameter or through a struct-typed
//! parameter carrying that field — must call `perch_sign_gate(` in the same
//! function body.
//!
//! Re-measured on 2026-09-03 against the real crate (the plan's five sites
//! were counted with stale line numbers): `sign_event`,
//! `send_channel_message`, `send_managed_agent_channel_message` (signs with the
//! managed agent's key), `edit_message` and
//! `publish_project_owner_announcement` (content arrives in an input struct),
//! plus `set_canvas` and `publish_note`, which sign renderer content through
//! the `submit_event` funnel that resolves `state.signing_keys()` itself.
//!
//! Scope was widened on 2026-09-03 after review: the scan previously walked
//! only `src/commands/`, matched the literal `#[tauri::command]` (so an
//! attribute carrying arguments — `#[tauri::command(rename_all = …)]` — left
//! the audit silently), and required the literal `content: String`. Roughly
//! twenty command-bearing files live elsewhere under `src/`
//! (`unread_catch_up.rs`, `huddle/*.rs`, `archive/sync.rs`,
//! `terminal_runtime.rs`, `builderlab.rs`), and each of those three narrowings
//! was a way for a content-signing command to be exempt without anyone
//! deciding it should be.
//!
//! Known limit of a textual scan: a command that hands its content to a
//! private helper which signs (`archive_identity` → `archive_identity_core`)
//! shows no needle in its own body and is not audited. Those helpers sign
//! non-chat kinds today; a new helper-shaped chat producer must be added to the
//! gate by hand and would then be caught here only if it names a funnel.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

/// A body naming any of these reaches a signing identity.
const SIGNING_NEEDLES: &[&str] = &[
    "signing_keys()",
    "submit_event",
    "submit_signed_event",
    "sign_with_keys(",
];

const GATE_CALL: &str = "perch_sign_gate(";

/// Prefix of the Tauri command attribute, with or without arguments.
const COMMAND_ATTRIBUTE: &str = "#[tauri::command";

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Every `.rs` file under `dir`, recursively, skipping test modules
/// (`*_tests.rs`, `tests.rs`, and `tests/` directories).
fn command_source_files(dir: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read {dir:?}: {e}"));
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() {
                if name != "tests" {
                    walk(&path, out);
                }
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs")
                && !name.ends_with("_tests.rs")
                && name != "tests.rs"
            {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, &mut out);
    out.sort();
    out
}

/// `(command name, source text from `#[tauri::command…]` to the closing brace)`.
///
/// Matched on the attribute **prefix**, so a command carrying attribute
/// arguments (`#[tauri::command(rename_all = "snake_case")]`) stays in the
/// audit instead of dropping out of it unnoticed.
fn command_bodies(src: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut idx = 0;
    while let Some(pos) = src[idx..].find(COMMAND_ATTRIBUTE) {
        let start = idx + pos;
        let sig_start = src[start..].find("fn ").map(|p| start + p).unwrap_or(start);
        let name_end = src[sig_start + 3..]
            .find(['(', '<'])
            .map(|p| sig_start + 3 + p)
            .unwrap_or(sig_start + 3);
        let name = src[sig_start + 3..name_end].trim().to_string();
        let body_end = src[start..]
            .find("\n}\n")
            .map(|p| start + p + 3)
            .unwrap_or(src.len());
        out.push((name, src[start..body_end].to_string()));
        idx = body_end;
    }
    out
}

/// `struct Name { ... }` bodies in `src`, keyed by name. Command parameters
/// may be typed with an input struct declared in another `commands/` file, so
/// callers accumulate one map over every scanned file.
fn collect_struct_bodies(src: &str, out: &mut HashMap<String, String>) {
    let mut idx = 0;
    while let Some(pos) = src[idx..].find("struct ") {
        let keyword_start = idx + pos;
        let name_start = keyword_start + "struct ".len();
        // `reconstruct ` in prose is not a declaration.
        let glued_to_word = keyword_start > 0
            && src
                .as_bytes()
                .get(keyword_start - 1)
                .is_some_and(|b| is_ident_byte(*b));
        if glued_to_word {
            idx = name_start;
            continue;
        }
        let name_len = src[name_start..]
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(0);
        let name = &src[name_start..name_start + name_len];
        idx = name_start + name_len;
        if name.is_empty() {
            continue;
        }
        // A brace-bodied struct opens before any `;` (tuple/unit structs end
        // there instead); generics may sit between the name and the brace.
        let Some(open) = src[idx..].find('{') else {
            break;
        };
        if src[idx..idx + open].contains(';') {
            continue;
        }
        let body_start = idx + open;
        let body_end = src[body_start..]
            .find('}')
            .map(|p| body_start + p)
            .unwrap_or(src.len());
        out.insert(name.to_string(), src[body_start..body_end].to_string());
        idx = body_end;
    }
}

/// The type spelling that follows a `content:` binding, whitespace and
/// lifetimes removed, cut at the first `,`/`)`/`}`/newline. `content: String`
/// yields `String`; the struct-literal member `content: String::new()` yields
/// `String::new(`, which matches no declared type.
fn normalized_content_type(rest: &str) -> String {
    let end = rest.find([',', ')', '}', '\n']).unwrap_or(rest.len());
    let mut out = String::new();
    let mut chars = rest[..end].chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\'' {
            // Drop a lifetime token so `&'a str` normalizes to `&str`.
            while chars
                .peek()
                .is_some_and(|n| n.is_ascii_alphanumeric() || *n == '_')
            {
                chars.next();
            }
            continue;
        }
        if !c.is_whitespace() {
            out.push(c);
        }
    }
    out
}

/// Parameter and field types that carry renderer-supplied text. `String` alone
/// missed `Option<String>` and the borrowed forms, so a command taking either
/// signed renderer content outside the audit.
const CONTENT_TYPES: &[&str] = &[
    "String",
    "Option<String>",
    "&String",
    "&str",
    "Option<&str>",
    "Cow<str>",
    "Option<Cow<str>>",
];

/// True when `text` declares a `content` field or parameter of a renderer-text
/// type (not a `content: String::new()` struct-literal member).
fn declares_content_string(text: &str) -> bool {
    let needle = "content:";
    let mut idx = 0;
    while let Some(pos) = text[idx..].find(needle) {
        let after = idx + pos + needle.len();
        let candidate = normalized_content_type(&text[after..]);
        if CONTENT_TYPES.contains(&candidate.as_str()) {
            return true;
        }
        idx = after;
    }
    false
}

/// Identifiers used as parameter types in the command's signature
/// (`input: EditMessageInput` → `EditMessageInput`; generics and lifetimes
/// are dropped after the first path segment).
fn parameter_type_names(body: &str) -> Vec<String> {
    let sig_end = body.find('{').unwrap_or(body.len());
    let signature = &body[..sig_end];
    let mut out = Vec::new();
    let mut idx = 0;
    while let Some(pos) = signature[idx..].find(": ") {
        let type_start = idx + pos + 2;
        let type_len = signature[type_start..]
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(signature.len() - type_start);
        let name = &signature[type_start..type_start + type_len];
        if !name.is_empty() {
            out.push(name.to_string());
        }
        idx = type_start + type_len;
    }
    out
}

fn takes_content(body: &str, structs: &HashMap<String, String>) -> bool {
    declares_content_string(body)
        || parameter_type_names(body).iter().any(|name| {
            structs
                .get(name)
                .is_some_and(|s| declares_content_string(s))
        })
}

fn signs(body: &str) -> bool {
    SIGNING_NEEDLES.iter().any(|needle| body.contains(needle))
}

struct Audit {
    /// `file::command` for every command the scan holds to the obligation.
    audited: Vec<String>,
    /// The audited commands whose body never calls the gate.
    violations: Vec<String>,
}

/// Pure scan core over `(relative path, content)` pairs.
fn audit(files: &[(String, String)]) -> Audit {
    let mut structs = HashMap::new();
    for (_, src) in files {
        collect_struct_bodies(src, &mut structs);
    }
    let mut audited = Vec::new();
    let mut violations = Vec::new();
    for (rel, src) in files {
        for (name, body) in command_bodies(src) {
            if signs(&body) && takes_content(&body, &structs) {
                let site = format!("{rel}::{name}");
                if !body.contains(GATE_CALL) {
                    violations.push(site.clone());
                }
                audited.push(site);
            }
        }
    }
    Audit {
        audited,
        violations,
    }
}

/// Every non-test `.rs` file in the crate, not just `src/commands/` —
/// command-bearing modules live all over `src/`.
fn read_command_files() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = root.join("src");
    command_source_files(&dir)
        .into_iter()
        .map(|path| {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let content = fs::read_to_string(&path).unwrap_or_default();
            (rel, content)
        })
        .collect()
}

#[test]
fn every_content_signing_command_calls_the_gate() {
    let Audit {
        audited,
        violations,
    } = audit(&read_command_files());
    assert!(
        audited.len() >= 7,
        "baseline on 2026-09-03 was seven commands, re-measured the same after \
         the scan widened to all of `src/`; found {}: {audited:?}",
        audited.len()
    );
    assert!(
        violations.is_empty(),
        "commands signing renderer content without the gate: {violations:?}"
    );
}

/// Mutation-style proof of the tripwire: a gate call deleted from an audited
/// command is reported.
#[test]
fn inventory_scan_catches_a_removed_gate_call() {
    let mut files = read_command_files();
    let identity = files
        .iter_mut()
        .find(|(rel, _)| rel.ends_with("src/commands/identity.rs"))
        .unwrap_or_else(|| panic!("identity.rs must be in the scan set"));
    identity.1 = identity.1.replacen(GATE_CALL, "removed_gate(", 1);
    let Audit { violations, .. } = audit(&files);
    assert!(
        violations
            .iter()
            .any(|v| v.ends_with("identity.rs::sign_event")),
        "a removed gate call in sign_event must trip the scan: {violations:?}"
    );
}

/// The scan's reach, asserted rather than assumed. Twenty-six command-bearing
/// files live outside `src/commands/` (`unread_catch_up.rs`, `huddle/*.rs`,
/// `archive/sync.rs`, `terminal_runtime.rs`, `builderlab.rs`, …). A walk
/// narrowed back to `commands/` would drop every one of them from the audit
/// with nothing going red, which is how the scope defect got in.
#[test]
fn inventory_scan_reaches_beyond_the_commands_directory() {
    let files = read_command_files();
    let commands_outside = files
        .iter()
        .filter(|(rel, _)| !rel.starts_with("src/commands/"))
        .filter(|(_, src)| !command_bodies(src).is_empty())
        .count();
    assert!(
        commands_outside >= 20,
        "the scan must cover the whole crate, not just src/commands/; only \
         {commands_outside} command-bearing files were found outside it"
    );
}

/// The three widenings, each proved on synthetic source: a command outside
/// `src/commands/`, an attribute carrying arguments, and the `content` shapes
/// beyond a bare `String`. Each was previously a silent exemption — a command
/// with any of these shapes signed renderer content outside the audit.
#[test]
fn inventory_scan_covers_widened_command_shapes() {
    fn file(rel: &str, attribute: &str, name: &str, content_type: &str) -> (String, String) {
        (
            rel.to_string(),
            format!(
                "{attribute}\npub async fn {name}(content: {content_type}, state: State<'_, AppState>) -> Result<(), String> {{\n    let _keys = state.signing_keys()?;\n    Ok(())\n}}\n"
            ),
        )
    }

    let files = vec![
        // Outside `src/commands/`, where roughly twenty command files live.
        file(
            "src/huddle/commands.rs",
            "#[tauri::command]",
            "post_from_huddle",
            "String",
        ),
        // The attribute carries arguments.
        file(
            "src/commands/renamed.rs",
            "#[tauri::command(rename_all = \"snake_case\")]",
            "post_renamed",
            "String",
        ),
        // Content shapes the `content: String` literal missed.
        file(
            "src/commands/optional.rs",
            "#[tauri::command]",
            "post_optional",
            "Option<String>",
        ),
        file(
            "src/commands/borrowed.rs",
            "#[tauri::command]",
            "post_borrowed",
            "&str",
        ),
    ];

    let Audit {
        audited,
        violations,
    } = audit(&files);
    assert_eq!(
        audited.len(),
        4,
        "every widened shape must be audited: {audited:?}"
    );
    assert_eq!(
        violations, audited,
        "none of them calls the gate, so all four are violations"
    );
}

/// Content that arrives through an input struct — the `edit_message` and
/// `publish_project_owner_announcement` shape — is audited, and a
/// `content: String::new()` struct literal in a read-only command is not.
#[test]
fn inventory_scan_resolves_struct_typed_content_parameters() {
    let source = concat!(
        "#[derive(serde::Deserialize)]\n",
        "pub struct NoteInput {\n",
        "    pub content: String,\n",
        "}\n",
        "\n",
        "#[tauri::command]\n",
        "pub async fn post_note(input: NoteInput, state: State<'_, AppState>) -> Result<(), String> {\n",
        "    submit_event(builder, &state).await\n",
        "}\n",
        "\n",
        "#[tauri::command]\n",
        "pub async fn read_note(state: State<'_, AppState>) -> Result<Note, String> {\n",
        "    let keys = state.signing_keys()?;\n",
        "    Ok(Note { content: String::new() })\n",
        "}\n",
    );
    let files = vec![("src/commands/synthetic.rs".to_string(), source.to_string())];
    let Audit {
        audited,
        violations,
    } = audit(&files);
    assert_eq!(audited, vec!["src/commands/synthetic.rs::post_note"]);
    assert_eq!(violations, audited);
}
