// PROPOSED — lands at BUZZ desktop/src/app/useAppShellBackgroundSync.ts
//
// Commit AS-1 of 15-FILE-SPLIT-PLAN.md. Pure extraction. Every statement below
// the signature is moved verbatim from AppShell.tsx at eed74bde2 — :144,
// :181, :191-221 and :223-227 — with their comments, in their original order.
// Nothing is rewritten and nothing is added.
//
// These fifteen hooks share one shape: they are mounted for their effects, they
// take at most the active pubkey / relay url / community list, and none of them
// returns a value the shell's JSX reads. The one exception is `deferredPubkey`,
// which AppShell still needs at three sites (presence session, self-status
// query, self-status mutation), so it is the hook's only return value.
//
// House pattern: this is the eleventh `use*` sibling extracted from AppShell —
// `useAppShellDesktopNotifications.ts` (a9ce477a0 "fix(desktop): split AppShell
// notification effects" #1248) is the precedent.

import { useMembershipNotifications } from "@/features/channels/useMembershipNotifications";
import { useAgentsDataRefresh } from "@/features/agents/lib/useAgentsDataRefresh";
import { useManagedAgentRuntimeReconciliation } from "@/features/agents/useManagedAgentRuntimeReconciliation";
import { useAutoRestartPolicy } from "@/features/agents/lib/useAutoRestartPolicy";
import { usePersonaSync } from "@/features/agents/lib/usePersonaSync";
import { useAgentObserverIngestion } from "@/features/agents/useAgentObserverIngestion";
import { usePresenceSubscription } from "@/features/presence/hooks";
import { useUserStatusSubscription } from "@/features/user-status/hooks";
import { useCommunityEmojiLiveUpdates } from "@/features/custom-emoji/hooks";
import { useArchiveSync } from "@/features/local-archive/useArchiveSync";
import { useArchiveAgentMetricsBridge } from "@/features/local-archive/useArchiveAgentMetricsBridge";
import { useObserverArchiveReconciliation } from "@/features/local-archive/useObserverArchiveSeed";
import { useAgentMetricArchiveSeed } from "@/features/local-archive/useAgentMetricArchiveSeed";
import { useRelayAutoHeal } from "@/shared/api/useRelayAutoHeal";
import { useDeferredStartup } from "@/shared/hooks/useDeferredStartup";
import type { Community } from "@/features/communities/types";

/**
 * Mounts every community-scoped background sync the shell owns and returns the
 * startup-deferred pubkey the shell's own presence and status hooks consume.
 *
 * Call order inside this hook is the order these hooks had in `AppShell` before
 * the extraction. `useProfileQuery` (AppShell.tsx:222) deliberately stayed in
 * `AppShell` and therefore now runs after this whole block rather than in the
 * middle of it — the single ordering change in commit AS-1, covered by
 * `tests/e2e/onboarding.spec.ts` and `tests/e2e/profile.spec.ts` in the smoke
 * project.
 */
export function useAppShellBackgroundSync({
  communities,
  pubkey,
  relayUrl,
}: {
  communities: ReadonlyArray<Community>;
  pubkey: string | undefined;
  relayUrl: string | undefined;
}): { deferredPubkey: string | undefined } {
  useManagedAgentRuntimeReconciliation(communities); // sync storage snapshot
  const startupReady = useDeferredStartup();
  usePersonaSync(
    pubkey,
    relayUrl,
  );
  useAgentsDataRefresh();
  // Chunk F: auto-restart drifted idle agents (per-agent opt-out, default ON).
  useAutoRestartPolicy();
  // Owner-global observer ingestion: receives + decrypts agent observer
  // frames and keeps derived active-turn liveness in sync app-wide, so no
  // individual screen/panel has to mount its own bridge for ingestion.
  // Intentionally mounted without a `startupReady`/identity guard: before
  // `currentPubkey` resolves the hook ingests managed agents only, and
  // relay-owned agents join automatically once identity arrives. Adding a
  // guard here would drop managed-agent coverage during startup.
  useAgentObserverIngestion();
  // Kind 24200 is relay-ephemeral, so reconciliation runs eagerly (not
  // deferred): seeds kind 24200 for fresh identities, no-ops for explicit
  // opt-outs. Frames before the listener opens are permanently lost.
  const observerReconciled = useObserverArchiveReconciliation(
    pubkey,
  );
  // useArchiveSync must wait for reconciliation, or listeners could open
  // before kind 24200 is guaranteed present in the subscription.
  useArchiveSync(observerReconciled);
  // The archive batch now persists in Rust, so the agent-metrics invalidation
  // signal arrives as a Tauri event rather than an in-process call.
  useArchiveAgentMetricsBridge();
  // Kind 44200 is relay-persisted (durable) and stays deferred: missed
  // startup frames can be replayed, so there's no ordering constraint.
  const deferredPubkey = startupReady ? pubkey : undefined;
  useAgentMetricArchiveSeed(deferredPubkey);
  useRelayAutoHeal();
  usePresenceSubscription();
  useUserStatusSubscription();
  useCommunityEmojiLiveUpdates();
  useMembershipNotifications(pubkey);

  return { deferredPubkey };
}
