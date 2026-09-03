# Superseded

The six files that used to live here — `perch-tokens.css`, `perch-bridge.css`,
`perch-token-aliases.tsv`, `severity.ts`, `tailwind.perch.js`, `perch-tokens.test.mjs` — specified
a palette for a direction (one of six then still open) that was not the one chosen. See
[`../art/DECISION.md`](../art/DECISION.md): the studio recommended Quiet, with Night Bridge's
guarded throw for the grant control, and the client decided it. That rejected palette is gone
from this directory rather than kept alongside its replacement, because a proposed token file
sitting next to the shipped one is exactly the kind of two-places-decide-it-differently drift
`00-REGISTRY.md` exists to prevent.

What is here now — `quiet.ts`, `theme.css`, `tailwind.config.js` — is not a new proposal. It is
an unmodified copy of the tokens `block/buzz` (`rebrand/ambush`) already ships, read from
`desktop/src/shared/theme/quiet.ts`, `desktop/src/shared/styles/globals/theme.css`, and
`desktop/tailwind.config.js` respectively. They are the built system, not a plan for one; the
guarded-throw grant control they will carry is still to be built on top of them, per
`../17-COMPONENT-SPECS.md` and `../20-TASK-BREAKDOWN.md`.
