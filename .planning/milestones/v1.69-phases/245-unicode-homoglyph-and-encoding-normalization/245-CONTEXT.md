# Phase 245: Unicode Homoglyph And Encoding Normalization - Context

**Gathered:** 2026-04-13
**Status:** Ready for planning

<domain>
## Phase Boundary

This phase extends the shared command-line normalization seam with bounded
Unicode homoglyph folding and encoded-command decoding so command-line
detectors can match common obfuscation forms without introducing opaque free-
form rewriting.

</domain>

<decisions>
## Implementation Decisions

### Chosen Approach
- Use a bounded manual homoglyph map plus fullwidth ASCII folding instead of a
  broad free-form Unicode rewrite pass.
- Decode only common PowerShell-style encoded arguments and
  `FromBase64String(...)` literals, then append decoded text to detector
  `match_text` while keeping the raw command unchanged.

### Deferred To Later Phases
- Benchmark comparison and benign regression proof remain Phases 246-247.

</decisions>

<code_context>
## Existing Code Insights

- Phase 244 already introduced a shared normalizer and detector-profile seam,
  so Unicode and encoded-argument support can land in one place.
- `fileless_execution` and `suspicious_scripting` are the highest-value lanes
  because they rely on deobfuscation markers that encoded payloads can hide.

</code_context>
