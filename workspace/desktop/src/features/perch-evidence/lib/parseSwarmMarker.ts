import {
  SWARM_MARKER_KINDS,
  SWARM_MARKER_VERSION,
  type SwarmMarkerKind,
  type SwarmMarkerParse,
} from "./markerTypes";

/**
 * The same interior whitespace Ground's `is_swarm_marker_line` accepts, and
 * a parsed (not pattern-pinned) version so a `v2` producer gets the honest
 * "this console is older than this card" state instead of silent prose.
 */
const MARKER_RE = /^<!--\s+swarm:([a-z][a-z-]*):v(\d{1,3})\s+-->$/;
const HEX64_RE = /^[0-9a-f]{64}$/;

/**
 * The chat app's own sniff is `content.trimStart().startsWith(WAVE_MESSAGE_MARKER)`
 * (`features/messages/lib/waveMessage.ts`) over arbitrary body text. That is
 * safe for a wave and unsafe here: `ProcessStartEvent.command_line` and
 * `DetectionFinding.evidence` reach this renderer. This sniff is
 * line-0-exact AND admitted-issuer-only (INV-15).
 */
export function parseSwarmMarker(args: {
  content: string;
  /** `event.pubkey` — the raw signer, NOT a delegated display author. */
  signerPubkey: string | undefined;
  /** `h` tag on the carrying event, or null. */
  channelTag: string | null;
  eventId: string;
  /** Resolves an admitted bridge identity. Reference-stable. */
  isAdmittedIssuer: (pubkey: string) => boolean;
}): SwarmMarkerParse {
  const { content, signerPubkey, channelTag, eventId, isAdmittedIssuer } = args;

  // 1. Line 0 only. No trimStart: a leading space is a producer bug we want
  //    to see.
  const newlineAt = content.indexOf("\n");
  const line0 = (
    newlineAt === -1 ? content : content.slice(0, newlineAt)
  ).trimEnd();
  const matched = MARKER_RE.exec(line0);
  if (!matched) return { status: "not-a-marker" };

  const slug = matched[1];
  const version = Number.parseInt(matched[2], 10);

  // 2. Admission. A well-formed marker from an unadmitted signer is counted
  //    and rendered as prose — APPENDIX-NORMATIVE.md §3's admitted-issuer rule.
  const issuer = signerPubkey?.toLowerCase();
  if (!issuer || !HEX64_RE.test(issuer) || !isAdmittedIssuer(issuer)) {
    return { status: "unadmitted-issuer", slug, issuerPubkey: issuer ?? null };
  }

  // 3. rawBody is byte-exact after the first newline. Never trimmed.
  const base = {
    rawBody: newlineAt === -1 ? "" : content.slice(newlineAt + 1),
    issuerPubkey: issuer,
    channelTag,
    eventId,
  };

  if (!(SWARM_MARKER_KINDS as readonly string[]).includes(slug)) {
    return { status: "unknown-kind", slug, version, card: base };
  }
  const kind = slug as SwarmMarkerKind;

  if (version !== SWARM_MARKER_VERSION) {
    return { status: "unsupported-version", kind, version, card: base };
  }

  return {
    status: "ok",
    card: { ...base, kind, version: SWARM_MARKER_VERSION },
  };
}
