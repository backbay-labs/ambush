// Target path in BUZZ: desktop/src/app/routes.ts  (REPLACES the file at that path)
//
// Read at build/dev time by the tanstackRouter vite plugin
// (BUZZ desktop/vite.config.ts:11-23), which regenerates the COMMITTED
// desktop/src/app/routeTree.gen.ts (292 lines today) from this file plus the
// files under src/app/routes/. Nothing checks that the generated tree is in
// sync — see 14-CLIENT-ARCHITECTURE.md §3.5 for the proposed gate.
//
// Eleven Perch paths (APPENDIX-NORMATIVE.md §1) = an index() plus ten route()
// entries, PLUS three redirect stubs that keep hash-history bookmarks alive.
// Buzz declares an index() plus eleven route() entries today.

import { index, rootRoute, route } from "@tanstack/virtual-file-routes";

export const routes = rootRoute("root.tsx", [
  // --- the eleven Perch routes -------------------------------------------
  index("index.tsx"), //                                  /              watch
  route("/cases/$caseId", "cases.$caseId.tsx"), //                       case
  route("/lanes/$laneId", "lanes.$laneId.tsx"), //                       lane
  route("/leases", "leases.tsx"), //                     nav label: Containments
  route("/policy", "policy.tsx"),
  route("/watch-floor", "watch-floor.tsx"), //            A3: never "/watch"
  route("/ledger", "ledger.tsx"),
  route("/tuning", "tuning.tsx"),
  route("/handoff", "handoff.tsx"),
  route("/gaps", "gaps.tsx"),
  route("/settings", "settings.tsx"),

  // --- retired Buzz paths, kept as redirects ------------------------------
  // createHashHistory (BUZZ desktop/src/app/router.tsx:7) means every URL is
  // "#/…" and lives in the user's window state, so a deleted route must not
  // dead-end. Shape copied verbatim from BUZZ routes/reminders.tsx:7-11.
  // /channels/$channelId redirects to /cases/$channelId: a Perch case IS a
  // NIP-29 channel UUID, so an old channel bookmark is a valid case id.
  route("/channels/$channelId", "channels.$channelId.tsx"),
  route("/agents", "agents.tsx"), //                      -> /watch-floor
  route("/pulse", "pulse.tsx"), //                        -> /watch-floor
]);

// DELETED with no redirect stub, because no Perch route can host them and the
// concept is gone rather than moved (00-BRIEF.md §5.4):
//   /reminders                        (already a redirect stub in Buzz today)
//   /workflows, /workflows/$workflowId
//   /projects, /projects/$projectId
//   /messages/new
//   /channels/$channelId/posts/$postId   (forum)
// The router's own not-found path handles these. Adding a stub for each is
// three lines apiece if telemetry shows real traffic; the stubs above exist
// because those three paths are the ones a Buzz operator actually bookmarks.
