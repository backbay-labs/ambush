import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

/**
 * INV-30 -- the CSP is a pinned string, not a policy anyone edits in passing.
 *
 * Target path in BUZZ: desktop/scripts/check-csp-pin.mjs
 * Wire into desktop/package.json's `check` script beside check:px-text and
 * check:pubkey-truncation, so `just desktop-check`, `just ci` and pre-push all
 * run it. (BUZZ has no tools/ directory and no check-gates-wired.sh; the
 * package.json `check` script is where a Buzz gate becomes real.)
 *
 * WHY EQUALITY AND NOT A REGEX
 *   The shipped policy (desktop/src-tauri/tauri.conf.json:39, applied by Tauri
 *   to the webview at launch) ends connect-src with the bare schemes
 *   `https: http: wss: ws:` and carries a remote script-src host,
 *   https://cdn.jsdelivr.net/npm/@mediapipe/, for animated-avatar capture. Any
 *   code in a ~100k-LOC React tree can therefore POST the whole verdict queue
 *   anywhere on the internet, and a compromised renderer can pull a script from
 *   a third party.
 *
 *   A regex that merely forbids `https:` would pass a policy that added
 *   `connect-src ... https://evil.example`. String equality against a literal
 *   makes every widening a one-line diff in a file a reviewer is already
 *   looking at. That is the whole mechanism.
 *
 * ORDER OF OPERATIONS -- this matters
 *   Pinning FIRST would pin the hole. The animated-avatar feature
 *   (features/profile/lib/animatedAvatarCapture.ts, which also fetches a model
 *   from storage.googleapis.com) must be deleted BEFORE this pin lands, or the
 *   pinned literal has to keep the remote script host and INV-30 asserts
 *   nothing worth asserting. 09's Phase 0 owns that ordering.
 *
 * WHAT THIS CANNOT SEE
 *   1. A CSP overridden at runtime by a <meta http-equiv> tag injected into the
 *      document. Tauri's header wins for the schemes it names, but a meta tag
 *      can add to some directives. Nothing lexical here covers that; the DOM
 *      assertion in tests/e2e/perch-marker-admission.spec.ts checks the live
 *      document for exactly one CSP source.
 *   2. `dangerouslySetInnerHTML` and friends. CSP does not stop those and this
 *      script does not claim to. INV-14 covers them.
 */

const PINNED_CSP = [
  "default-src 'self'",
  "base-uri 'self'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "object-src 'none'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self' data:",
  "connect-src 'self' ipc: http://ipc.localhost buzz-media: http://buzz-media.localhost",
  "img-src 'self' buzz-media: http://buzz-media.localhost data: blob:",
  "media-src 'self' buzz-media: http://buzz-media.localhost data: blob:",
  "worker-src 'self' blob:",
].join("; ");

// The four bare schemes and the one remote host that must never come back.
const FORBIDDEN_CONNECT_SOURCES = ["https:", "http:", "wss:", "ws:"];
const REMOTE_HOST_RE = /(script|connect|img|media|font|style)-src[^;]*\bhttps?:\/\/(?!ipc\.localhost|buzz-media\.localhost)[^\s;]+/g;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// In BUZZ this file sits at desktop/scripts/, so `..` is desktop/. PERCH_TAURI_CONF
// overrides it, which is how this gate is runnable from the wave-2 skeleton and
// from a checkout laid out differently.
const confPath =
  process.env.PERCH_TAURI_CONF ??
  path.resolve(__dirname, "..", "src-tauri", "tauri.conf.json");

// REFUSE TO PASS SILENTLY, and refuse to crash with a stack trace either. An
// unreadable config is not a clean CSP; it is a gate that asserted nothing, and
// an ENOENT stack is the shape a reader dismisses as "the script is broken"
// rather than "the path is wrong".
let raw;
try {
  raw = await fs.readFile(confPath, "utf8");
} catch (error) {
  console.error(
    `check-csp-pin: cannot read ${confPath} (${error.code ?? error.message}).\n` +
      "Run it from BUZZ desktop/, or set PERCH_TAURI_CONF to the tauri.conf.json\n" +
      "to check. Refusing to report a pass over a file that was not read.",
  );
  process.exit(1);
}

let conf;
try {
  conf = JSON.parse(raw);
} catch (error) {
  console.error(`check-csp-pin: ${confPath} is not valid JSON (${error.message}).`);
  process.exit(1);
}
const actual = conf?.app?.security?.csp ?? conf?.tauri?.security?.csp;

const failures = [];

if (typeof actual !== "string" || actual.length === 0) {
  failures.push(
    "security.csp is absent or not a string. An absent CSP is the widest CSP.",
  );
} else {
  if (actual !== PINNED_CSP) {
    failures.push(
      [
        "security.csp does not equal the pinned literal.",
        "",
        "  pinned: " + PINNED_CSP,
        "  actual: " + actual,
        "",
        "If the change is intended, edit PINNED_CSP in this file in the SAME",
        "commit and say in the PR body which directive widened and why. That is",
        "the review this gate exists to force.",
      ].join("\n"),
    );
  }

  // These run even when equality already failed, so one run names every problem.
  const connectDirective =
    actual.split(";").map((d) => d.trim()).find((d) => d.startsWith("connect-src")) ?? "";
  for (const source of FORBIDDEN_CONNECT_SOURCES) {
    const pattern = new RegExp(`(^|\\s)${source.replace(":", "\\:")}(\\s|$)`);
    if (pattern.test(connectDirective)) {
      failures.push(
        `connect-src carries the bare scheme \`${source}\`. That permits a request ` +
          "to every host on the internet, which makes the verdict queue exfiltratable " +
          "by any code in the renderer.",
      );
    }
  }

  const remoteHosts = actual.match(REMOTE_HOST_RE) ?? [];
  for (const hit of remoteHosts) {
    failures.push(
      `a remote host appears in a fetch directive: \`${hit.trim()}\`. Perch loads ` +
        "nothing from a third party; inline it or ship it as an asset.",
    );
  }
}

if (failures.length > 0) {
  console.error("INV-30 -- the pinned Content-Security-Policy has moved.\n");
  console.error(`  ${path.relative(process.cwd(), confPath)}\n`);
  for (const failure of failures) {
    console.error(failure.split("\n").map((l) => (l ? `  ${l}` : l)).join("\n"));
    console.error("");
  }
  process.exit(1);
}

console.log("CSP pin intact");
