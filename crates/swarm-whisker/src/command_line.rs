use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandLineNormalizationProfile {
    #[serde(default = "default_enabled")]
    pub strip_caret_escapes: bool,
    #[serde(default = "default_enabled")]
    pub expand_environment_variables: bool,
    #[serde(default = "default_enabled")]
    pub normalize_unicode_homoglyphs: bool,
    #[serde(default = "default_enabled")]
    pub decode_encoded_arguments: bool,
}

impl Default for CommandLineNormalizationProfile {
    fn default() -> Self {
        Self {
            strip_caret_escapes: default_enabled(),
            expand_environment_variables: default_enabled(),
            normalize_unicode_homoglyphs: default_enabled(),
            decode_encoded_arguments: default_enabled(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CommandLineAnalysis {
    pub normalized: String,
    pub match_text: String,
    pub decoded_segments: Vec<String>,
    pub transforms: Vec<String>,
}

pub fn analyze_command_line(
    raw: &str,
    profile: &CommandLineNormalizationProfile,
) -> CommandLineAnalysis {
    let (normalized, initial_transforms) = normalize_surface(raw, profile);
    let mut transforms = initial_transforms
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let mut decoded_segments = Vec::new();

    if profile.decode_encoded_arguments {
        for segment in extract_decoded_segments(&normalized) {
            push_transform(&mut transforms, segment.transform);
            let (normalized_segment, segment_transforms) =
                normalize_surface(&segment.text, profile);
            for transform in segment_transforms {
                push_transform(&mut transforms, transform);
            }
            let trimmed = normalized_segment.trim();
            if !trimmed.is_empty() {
                decoded_segments.push(trimmed.to_string());
            }
        }
    }

    let mut match_text = normalized.to_ascii_lowercase();
    for decoded in &decoded_segments {
        if !match_text.is_empty() {
            match_text.push(' ');
        }
        match_text.push_str(&decoded.to_ascii_lowercase());
    }

    CommandLineAnalysis {
        normalized,
        match_text,
        decoded_segments,
        transforms,
    }
}

#[derive(Debug)]
struct DecodedSegment {
    text: String,
    transform: &'static str,
}

fn normalize_surface(
    raw: &str,
    profile: &CommandLineNormalizationProfile,
) -> (String, Vec<&'static str>) {
    let mut value = raw.to_string();
    let mut transforms = Vec::new();

    if profile.strip_caret_escapes {
        let stripped = value.replace('^', "");
        if stripped != value {
            value = stripped;
            transforms.push("stripped_caret_escapes");
        }
    }

    if profile.expand_environment_variables {
        let expanded = expand_environment_variables(&value);
        if expanded != value {
            value = expanded;
            transforms.push("expanded_environment_variables");
        }
    }

    if profile.normalize_unicode_homoglyphs {
        let normalized = normalize_unicode_homoglyphs(&value);
        if normalized != value {
            value = normalized;
            transforms.push("normalized_unicode_homoglyphs");
        }
    }

    (value, transforms)
}

fn extract_decoded_segments(command_line: &str) -> Vec<DecodedSegment> {
    let mut segments = Vec::new();

    if let Some(decoded) = extract_encoded_argument(command_line) {
        segments.push(DecodedSegment {
            text: decoded,
            transform: "decoded_encoded_argument",
        });
    }

    for decoded in extract_from_base64_string_literals(command_line) {
        segments.push(DecodedSegment {
            text: decoded,
            transform: "decoded_frombase64string_literal",
        });
    }

    segments
}

fn extract_encoded_argument(command_line: &str) -> Option<String> {
    let tokens = command_line.split_whitespace().collect::<Vec<_>>();
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index];
        let token_lower = token.to_ascii_lowercase();
        let candidate = if matches!(
            token_lower.as_str(),
            "-enc" | "/enc" | "-ec" | "/ec" | "-encodedcommand" | "/encodedcommand"
        ) {
            tokens.get(index + 1).copied()
        } else if has_encoded_prefix(&token_lower) {
            split_encoded_argument(token)
        } else {
            None
        };

        if let Some(value) = candidate.and_then(decode_base64_candidate) {
            return Some(value);
        }

        index += 1;
    }
    None
}

fn has_encoded_prefix(token_lower: &str) -> bool {
    [
        "-enc:",
        "-enc=",
        "/enc:",
        "/enc=",
        "-ec:",
        "-ec=",
        "/ec:",
        "/ec=",
        "-encodedcommand:",
        "-encodedcommand=",
        "/encodedcommand:",
        "/encodedcommand=",
    ]
    .iter()
    .any(|prefix| token_lower.starts_with(prefix))
}

fn split_encoded_argument(token: &str) -> Option<&str> {
    token
        .split_once([':', '='])
        .map(|(_, value)| value)
        .filter(|value| !value.is_empty())
}

fn extract_from_base64_string_literals(command_line: &str) -> Vec<String> {
    let lowercase = command_line.to_ascii_lowercase();
    let mut decoded = Vec::new();
    let mut offset = 0;

    while let Some(found) = lowercase[offset..].find("frombase64string") {
        let start = offset + found;
        let Some(open_paren_rel) = command_line[start..].find('(') else {
            break;
        };
        let mut cursor = start + open_paren_rel + 1;
        while let Some(ch) = command_line[cursor..].chars().next() {
            if ch.is_whitespace() {
                cursor += ch.len_utf8();
                continue;
            }
            break;
        }

        let Some(quote) = command_line[cursor..].chars().next() else {
            break;
        };
        if quote != '\'' && quote != '"' {
            offset = cursor.saturating_add(1);
            continue;
        }
        cursor += quote.len_utf8();
        let Some(end_rel) = command_line[cursor..].find(quote) else {
            break;
        };
        let encoded = &command_line[cursor..cursor + end_rel];
        if let Some(value) = decode_base64_candidate(encoded) {
            decoded.push(value);
        }
        offset = cursor + end_rel + quote.len_utf8();
    }

    decoded
}

fn decode_base64_candidate(candidate: &str) -> Option<String> {
    let compact = sanitize_base64_candidate(candidate);
    if compact.len() < 8 || !looks_like_base64(&compact) {
        return None;
    }

    let padded = apply_base64_padding(&compact);
    for engine in [STANDARD, URL_SAFE] {
        let Ok(bytes) = engine.decode(&padded) else {
            continue;
        };
        if let Some(decoded) = decode_text_bytes(&bytes) {
            return Some(decoded);
        }
    }
    None
}

fn sanitize_base64_candidate(candidate: &str) -> String {
    let mut trimmed = candidate.trim();
    while let Some(ch) = trimmed.chars().next() {
        if matches!(ch, '"' | '\'' | '(' | '[' | '{' | ',' | ';') {
            trimmed = &trimmed[ch.len_utf8()..];
            continue;
        }
        break;
    }
    while let Some(ch) = trimmed.chars().last() {
        if matches!(ch, '"' | '\'' | ')' | ']' | '}' | ',' | ';') {
            trimmed = &trimmed[..trimmed.len() - ch.len_utf8()];
            continue;
        }
        break;
    }
    trimmed.chars().filter(|ch| !ch.is_whitespace()).collect()
}

fn looks_like_base64(candidate: &str) -> bool {
    candidate
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=' | '-' | '_'))
}

fn apply_base64_padding(candidate: &str) -> String {
    let mut padded = candidate.to_string();
    while !padded.len().is_multiple_of(4) {
        padded.push('=');
    }
    padded
}

fn decode_text_bytes(bytes: &[u8]) -> Option<String> {
    if let Some(decoded) = decode_utf16le(bytes) {
        return Some(decoded);
    }
    if !bytes.len().is_multiple_of(2) {
        let mut padded = bytes.to_vec();
        padded.push(0);
        if let Some(decoded) = decode_utf16le(&padded) {
            return Some(decoded);
        }
    }

    let decoded = String::from_utf8(bytes.to_vec()).ok()?;
    let decoded = decoded.trim_matches('\0').trim().to_string();
    is_readable_text(&decoded).then_some(decoded)
}

fn decode_utf16le(bytes: &[u8]) -> Option<String> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }

    let units = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    let decoded = String::from_utf16(&units).ok()?;
    let decoded = decoded.trim_matches('\0').trim().to_string();
    is_readable_text(&decoded).then_some(decoded)
}

fn is_readable_text(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() < 3 {
        return false;
    }
    let total = trimmed.chars().count();
    let readable = trimmed
        .chars()
        .filter(|ch| !ch.is_control() || matches!(ch, '\n' | '\r' | '\t'))
        .count();
    readable.saturating_mul(100) / total >= 85
}

fn expand_environment_variables(value: &str) -> String {
    let percent_expanded = expand_percent_environment_variables(value);
    expand_powershell_environment_variables(&percent_expanded)
}

fn expand_percent_environment_variables(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = String::with_capacity(value.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' {
            let mut cursor = index + 1;
            while cursor < bytes.len() && bytes[cursor] != b'%' {
                cursor += 1;
            }
            if cursor < bytes.len() && cursor > index + 1 {
                let name = &value[index + 1..cursor];
                if let Some(expanded) = known_environment_value(name) {
                    output.push_str(expanded);
                    index = cursor + 1;
                    continue;
                }
            }
        }

        let ch = value[index..].chars().next().unwrap_or_default();
        output.push(ch);
        index += ch.len_utf8();
    }

    output
}

fn expand_powershell_environment_variables(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut index = 0;

    while index < value.len() {
        if starts_with_ignore_ascii_case(&value[index..], "$env:") {
            let start = index + "$env:".len();
            let mut cursor = start;
            while cursor < value.len() {
                let ch = value[cursor..].chars().next().unwrap_or_default();
                if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '(' | ')') {
                    cursor += ch.len_utf8();
                } else {
                    break;
                }
            }
            if cursor > start {
                let name = &value[start..cursor];
                if let Some(expanded) = known_environment_value(name) {
                    output.push_str(expanded);
                    index = cursor;
                    continue;
                }
            }
        }

        let ch = value[index..].chars().next().unwrap_or_default();
        output.push(ch);
        index += ch.len_utf8();
    }

    output
}

fn known_environment_value(name: &str) -> Option<&'static str> {
    match name.to_ascii_lowercase().as_str() {
        "comspec" => Some("cmd"),
        "windir" | "systemroot" => Some("windows"),
        "temp" | "tmp" => Some("temp"),
        "public" => Some("users/public"),
        "programdata" => Some("programdata"),
        "appdata" => Some("appdata"),
        "localappdata" => Some("localappdata"),
        "userprofile" => Some("users/current"),
        "username" => Some("user"),
        "computername" => Some("host"),
        "programfiles" => Some("program files"),
        "programfiles(x86)" => Some("program files (x86)"),
        _ => None,
    }
}

fn starts_with_ignore_ascii_case(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
}

fn normalize_unicode_homoglyphs(value: &str) -> String {
    value.chars().map(map_homoglyph).collect()
}

fn map_homoglyph(ch: char) -> char {
    if ('\u{FF01}'..='\u{FF5E}').contains(&ch) {
        return char::from_u32((ch as u32) - 0xFEE0).unwrap_or(ch);
    }

    match ch {
        '\u{3000}' => ' ',
        'А' | 'Α' => 'A',
        'В' | 'Β' => 'B',
        'С' | 'Ϲ' => 'C',
        'Е' | 'Ε' => 'E',
        'Н' | 'Η' => 'H',
        'І' | 'Ι' => 'I',
        'Ј' => 'J',
        'Κ' | 'К' => 'K',
        'М' | 'Μ' => 'M',
        'Ν' => 'N',
        'О' | 'Ο' => 'O',
        'Р' | 'Ρ' => 'P',
        'Ѕ' => 'S',
        'Т' | 'Τ' => 'T',
        'Υ' | 'Ү' => 'Y',
        'Χ' | 'Х' => 'X',
        'а' | 'α' => 'a',
        'е' | 'ε' => 'e',
        'і' | 'ι' => 'i',
        'ј' => 'j',
        'ο' | 'о' => 'o',
        'р' | 'ρ' => 'p',
        'с' | 'ϲ' => 'c',
        'у' | 'γ' => 'y',
        'х' | 'χ' => 'x',
        '’' | '‘' => '\'',
        '“' | '”' => '"',
        '−' | '‐' | '‑' | '‒' | '–' | '—' | '﹣' => '-',
        _ => ch,
    }
}

fn push_transform(transforms: &mut Vec<String>, transform: &'static str) {
    if !transforms.iter().any(|existing| existing == transform) {
        transforms.push(transform.to_string());
    }
}

fn default_enabled() -> bool {
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{CommandLineNormalizationProfile, analyze_command_line};

    #[test]
    fn strips_caret_and_expands_environment_variables() {
        let analysis = analyze_command_line(
            "cmd.exe /c po^wershell.exe %ComSpec% /c echo hi",
            &CommandLineNormalizationProfile::default(),
        );

        assert_eq!(
            analysis.normalized,
            "cmd.exe /c powershell.exe cmd /c echo hi"
        );
        assert!(
            analysis
                .transforms
                .contains(&"stripped_caret_escapes".to_string())
        );
        assert!(
            analysis
                .transforms
                .contains(&"expanded_environment_variables".to_string())
        );
    }

    #[test]
    fn folds_fullwidth_and_confusable_unicode() {
        let analysis = analyze_command_line(
            "powershell.exe －ＥＮＣＯＤＥＤＣＯＭＭＡＮＤ ΙΕΧ",
            &CommandLineNormalizationProfile::default(),
        );

        assert_eq!(analysis.normalized, "powershell.exe -ENCODEDCOMMAND IEX");
        assert!(
            analysis
                .transforms
                .contains(&"normalized_unicode_homoglyphs".to_string())
        );
    }

    #[test]
    fn decodes_powershell_encoded_command() {
        let analysis = analyze_command_line(
            "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQ==",
            &CommandLineNormalizationProfile::default(),
        );

        assert!(
            analysis
                .decoded_segments
                .iter()
                .any(|segment| segment.contains("IEX"))
        );
        assert!(
            analysis
                .transforms
                .contains(&"decoded_encoded_argument".to_string())
        );
    }

    #[test]
    fn decodes_from_base64_string_literals() {
        let analysis = analyze_command_line(
            "[Convert]::FromBase64String('SQBFAFgA')",
            &CommandLineNormalizationProfile::default(),
        );

        assert_eq!(analysis.decoded_segments, vec!["IEX".to_string()]);
        assert!(
            analysis
                .transforms
                .contains(&"decoded_frombase64string_literal".to_string())
        );
    }
}
