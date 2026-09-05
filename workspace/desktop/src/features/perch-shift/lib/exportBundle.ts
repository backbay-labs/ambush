/**
 * The export bundle: the record, as bytes, with a manifest that says exactly
 * what it does and does not answer.
 *
 * Every file is the daemon's or the relay's bytes VERBATIM. Re-serializing
 * would change the digest of a signed record and turn a verifiable artifact
 * into this console's paraphrase of one.
 */
export type ExportEntry = {
  kind: "receipt" | "rollback" | "hold" | "envelope" | "verdict";
  id: string;
  /** Verbatim. Never reserialized. */
  bytes: Uint8Array;
  tier: 0 | 1 | 2;
  /**
   * False for a relay row with no daemon record. Excluded from the bundle: an
   * unreconciled row is a claim the daemon does not corroborate, and shipping
   * it inside an evidence bundle would lend it the bundle's authority.
   */
  reconciled: boolean;
  verdictCardId?: string;
};

export type ExportFile = {
  path: string;
  bytes: Uint8Array;
  verification_tier: 0 | 1 | 2;
};

/**
 * Lay the bundle out.
 *
 * `envelopes/` is present and EMPTY rather than omitted when nothing is
 * signed: an absent directory reads as "we did not look", and an empty one
 * says "we looked and there was nothing signed to carry".
 */
export function planExportFiles(entries: readonly ExportEntry[]): ExportFile[] {
  const files: ExportFile[] = [];
  let envelopes = 0;
  for (const entry of entries) {
    if (!entry.reconciled) continue;
    const dir =
      entry.kind === "receipt" || entry.kind === "rollback"
        ? "receipts"
        : entry.kind === "hold" || entry.kind === "verdict"
          ? "holds"
          : "envelopes";
    if (dir === "envelopes") envelopes += 1;
    files.push({
      path: `${dir}/${entry.id}.json`,
      bytes: entry.bytes,
      verification_tier: entry.tier,
    });
  }
  if (envelopes === 0) {
    files.push({
      path: "envelopes/.keep",
      bytes: new Uint8Array(),
      verification_tier: 0,
    });
  }
  return files;
}

export type ExportManifest = {
  generated_at: string;
  exporting_operator: string;
  /**
   * Always false, and stated rather than omitted. The bundle answers "a human
   * was asked", not "who approved this": the operator identity here is
   * whoever EXPORTED, which is a different question and a tempting one to
   * confuse.
   */
  answers_who_approved: false;
  verification_tiers_present: (0 | 1 | 2)[];
  files: { path: string; sha256: string; verification_tier: 0 | 1 | 2 }[];
  /** Detached Ed25519 over the canonical body; filled by the Tauri command. */
  manifest_signature: string | null;
};

/**
 * SHA-256 through Web Crypto.
 *
 * This is renderer code: `node:crypto` is not available here, and reaching for
 * it would compile against types the bundle does not ship.
 */
async function sha256Hex(bytes: Uint8Array): Promise<string> {
  // A fresh, exactly-sized buffer: a Uint8Array can be a view into a larger
  // (or shared) buffer, and hashing the backing store would digest bytes the
  // caller never handed us.
  const exact = new Uint8Array(bytes.byteLength);
  exact.set(bytes);
  const digest = await crypto.subtle.digest("SHA-256", exact);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function buildExportManifest(
  files: readonly ExportFile[],
  opts: {
    exportingOperator: string;
    derived: readonly { fn: string; value: unknown }[];
  },
): Promise<ExportManifest> {
  const tiers = Array.from(
    new Set(files.map((file) => file.verification_tier)),
  ).sort() as (0 | 1 | 2)[];
  return {
    generated_at: new Date().toISOString(),
    exporting_operator: opts.exportingOperator,
    answers_who_approved: false,
    verification_tiers_present: tiers,
    files: await Promise.all(
      files.map(async (file) => ({
        path: file.path,
        sha256: await sha256Hex(file.bytes),
        verification_tier: file.verification_tier,
      })),
    ),
    manifest_signature: null,
  };
}

/**
 * `VERIFY.md`, per tier, as commands a reader can run with `swarmctl` and
 * nothing else.
 *
 * A bundle whose verification instructions require this console would be
 * verifiable only by the thing under examination.
 */
export function renderVerifyMd(manifest: ExportManifest): string {
  const lines = [
    "# VERIFY",
    "",
    "This bundle answers “a human was asked”, not “who approved this”",
    "(`answers_who_approved: false`). The operator named in the manifest is the",
    "one who EXPORTED it.",
    "",
  ];
  if (manifest.verification_tiers_present.includes(0)) {
    lines.push(
      "## Tier 0 files",
      "These files carry no Ed25519 signature. Re-fetch them from the daemon to verify:",
      "",
      "    swarmctl evidence fetch --id <id> | diff - receipts/<id>.json",
      "",
    );
  }
  if (manifest.verification_tiers_present.includes(1)) {
    lines.push(
      "## Tier 1 files",
      "These carry a detached signature over their own bytes:",
      "",
      "    swarmctl evidence verify --file receipts/<id>.json",
      "",
    );
  }
  if (manifest.verification_tiers_present.includes(2)) {
    lines.push(
      "## Tier 2 files",
      "These are spine envelopes: the signature covers the record AND its place in",
      "the issuer's chain, so a missing link is detectable rather than invisible.",
      "",
      "    swarmctl evidence verify-chain --dir envelopes/",
      "",
    );
  }
  return lines.join("\n");
}
