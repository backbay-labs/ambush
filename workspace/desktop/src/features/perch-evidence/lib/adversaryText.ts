/**
 * The escaping behind `<AdversaryString>` (INV-14, 08 §7.7 control 1).
 *
 * A wire string built from telemetry can carry bidi overrides, zero-width
 * joiners and control characters that reorder, hide or split what an operator
 * sees. This module turns each such code point into a visible, named glyph
 * and leaves everything else as plain text runs. Pure, so it is testable
 * under `node:test` and so the component that renders it has nothing to
 * decide.
 */

/** Rendered graphemes before `<AdversaryString>` shows its expand control. */
export const ADVERSARY_CAP = 512;

/** One run of a value: readable text, or one escaped code point. */
export type AdversaryTextPart =
  | { kind: "text"; text: string }
  | { kind: "escaped"; codepoint: string; glyph: string };

/**
 * The Unicode names the `title` attribute carries. Everything an attacker
 * reaches for first is here; a code point outside the table renders its
 * `U+XXXX` alone, which is still enough to tell U+202E from U+200B.
 */
const CODEPOINT_NAMES: Readonly<Record<string, string>> = Object.freeze({
  "U+0000": "NULL",
  "U+0009": "CHARACTER TABULATION",
  "U+000A": "LINE FEED",
  "U+000D": "CARRIAGE RETURN",
  "U+001B": "ESCAPE",
  "U+007F": "DELETE",
  "U+200B": "ZERO WIDTH SPACE",
  "U+200C": "ZERO WIDTH NON-JOINER",
  "U+200D": "ZERO WIDTH JOINER",
  "U+200E": "LEFT-TO-RIGHT MARK",
  "U+200F": "RIGHT-TO-LEFT MARK",
  "U+202A": "LEFT-TO-RIGHT EMBEDDING",
  "U+202B": "RIGHT-TO-LEFT EMBEDDING",
  "U+202C": "POP DIRECTIONAL FORMATTING",
  "U+202D": "LEFT-TO-RIGHT OVERRIDE",
  "U+202E": "RIGHT-TO-LEFT OVERRIDE",
  "U+2066": "LEFT-TO-RIGHT ISOLATE",
  "U+2067": "RIGHT-TO-LEFT ISOLATE",
  "U+2068": "FIRST STRONG ISOLATE",
  "U+2069": "POP DIRECTIONAL ISOLATE",
  "U+FEFF": "ZERO WIDTH NO-BREAK SPACE",
});

type EscapeClass = "c0" | "c1" | "zero-width" | "bidi";

/** The classes that are escaped, and nothing else. */
function escapeClassOf(code: number): EscapeClass | null {
  if (code <= 0x1f) return "c0";
  if (code >= 0x7f && code <= 0x9f) return "c1";
  if ((code >= 0x200b && code <= 0x200f) || code === 0xfeff) {
    return "zero-width";
  }
  if (
    (code >= 0x202a && code <= 0x202e) ||
    (code >= 0x2066 && code <= 0x2069)
  ) {
    return "bidi";
  }
  return null;
}

/**
 * The visible stand-in for one escaped code point. C0 controls use the
 * Control Pictures block (U+240A renders a newline as a visible symbol);
 * the zero-width class a visible space; the bidi classes a reversal arrow;
 * everything else the generic NULL picture.
 */
function glyphFor(code: number, cls: EscapeClass): string {
  switch (cls) {
    case "c0":
      return String.fromCodePoint(0x2400 + code);
    case "zero-width":
      return "␣";
    case "bidi":
      return "⇄";
    default:
      return "␀";
  }
}

/** `U+202E`, four hex digits minimum, uppercase. */
function codepointLabel(code: number): string {
  return `U+${code.toString(16).toUpperCase().padStart(4, "0")}`;
}

/**
 * The `title` an escaped glyph carries: the codepoint plus its Unicode name
 * when the fixed table knows it, the bare codepoint otherwise.
 */
export function escapedCodepointTitle(codepoint: string): string {
  const name = CODEPOINT_NAMES[codepoint];
  return name ? `${codepoint} ${name}` : codepoint;
}

/**
 * Split `value` into text runs and escaped code points. Iterates by code
 * point (never by UTF-16 unit, so a surrogate pair is never split), merges
 * adjacent text, and returns a frozen array the component renders as plain
 * text nodes.
 */
export function escapeAdversaryText(
  value: string,
): ReadonlyArray<AdversaryTextPart> {
  const parts: AdversaryTextPart[] = [];
  let run = "";
  const flush = () => {
    if (run.length > 0) {
      parts.push({ kind: "text", text: run });
      run = "";
    }
  };
  for (const ch of value) {
    const code = ch.codePointAt(0) ?? 0;
    const cls = escapeClassOf(code);
    if (cls === null) {
      run += ch;
      continue;
    }
    flush();
    parts.push({
      kind: "escaped",
      codepoint: codepointLabel(code),
      glyph: glyphFor(code, cls),
    });
  }
  flush();
  return Object.freeze(parts);
}
