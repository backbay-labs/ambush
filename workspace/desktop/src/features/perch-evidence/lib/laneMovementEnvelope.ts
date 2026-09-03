// TODO(First card Task 2): replace with @/features/perch/wire parseCardContent
//
// A temporary reader for the two envelope members the lane-movement sink
// needs, standing in until the TypeScript wire mirror
// (`features/perch/wire/marker.ts`) lands. It mirrors that module's
// `parseCardContent` discipline: line 0 is the whole marker, the envelope is
// the JSON inside the fenced block whose info string is the marker's own
// `swarm:<slug>:v<n>`, and nothing here ever throws. When the mirror lands,
// `readLaneMovementEnvelope` becomes `parseCardContent` plus one JSON parse
// and this file is deleted; `perchLaneMovement.ts` changes one import.

/** The two envelope members the lane-movement sink reads. */
export type LaneMovementEnvelope = {
  readonly issuer: string;
  readonly seq: number;
};

const MARKER_LINE = /^<!--\s+swarm:([a-z][a-z-]*):v(\d{1,3})\s+-->$/;

/**
 * Read `issuer` and `seq` out of a swarm card body. Returns null for prose,
 * for a marker that is not the whole of line 0, for a fence whose info
 * string is not the marker's own, and for a malformed or ill-typed envelope.
 */
export function readLaneMovementEnvelope(
  content: string,
): LaneMovementEnvelope | null {
  const firstBreak = content.indexOf("\n");
  if (firstBreak === -1) return null;
  const marker = MARKER_LINE.exec(
    content.slice(0, firstBreak).replace(/\r$/, ""),
  );
  if (!marker) return null;
  const fenceOpen = `\`\`\`swarm:${marker[1]}:v${marker[2]}\n`;
  const rest = content.slice(firstBreak + 1);
  const openAt = rest.indexOf(fenceOpen);
  if (openAt === -1) return null;
  const jsonStart = openAt + fenceOpen.length;
  const closeAt = rest.indexOf("\n```", jsonStart);
  if (closeAt === -1) return null;
  try {
    const envelope: unknown = JSON.parse(rest.slice(jsonStart, closeAt));
    if (typeof envelope !== "object" || envelope === null) return null;
    const { issuer, seq } = envelope as { issuer?: unknown; seq?: unknown };
    if (typeof issuer !== "string" || issuer.length === 0) return null;
    if (typeof seq !== "number" || !Number.isInteger(seq) || seq < 0) {
      return null;
    }
    return { issuer, seq };
  } catch {
    return null;
  }
}
