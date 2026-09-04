import { useAgentsDataRefresh } from "@/features/agents/lib/useAgentsDataRefresh";
import { useAutoRestartPolicy } from "@/features/agents/lib/useAutoRestartPolicy";
import { usePersonaSync } from "@/features/agents/lib/usePersonaSync";
import { useAgentObserverIngestion } from "@/features/agents/useAgentObserverIngestion";
import { useManagedAgentRuntimeReconciliation } from "@/features/agents/useManagedAgentRuntimeReconciliation";
import { useMembershipNotifications } from "@/features/channels/useMembershipNotifications";
import type { Community } from "@/features/communities/types";
import { useCommunityEmojiLiveUpdates } from "@/features/custom-emoji/hooks";
import { useAgentMetricArchiveSeed } from "@/features/local-archive/useAgentMetricArchiveSeed";
import { useArchiveAgentMetricsBridge } from "@/features/local-archive/useArchiveAgentMetricsBridge";
import { useArchiveSync } from "@/features/local-archive/useArchiveSync";
import { useObserverArchiveReconciliation } from "@/features/local-archive/useObserverArchiveSeed";
import { usePresenceSubscription } from "@/features/presence/hooks";
import { useUserStatusSubscription } from "@/features/user-status/hooks";
import { useDeferredStartup } from "@/shared/hooks/useDeferredStartup";
import { useRelayAutoHeal } from "@/shared/api/useRelayAutoHeal";

/**
 * Mounts the community-scoped background synchronization owned by AppShell and
 * returns the startup-deferred pubkey consumed by its presence and status hooks.
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
  useManagedAgentRuntimeReconciliation(communities);
  const startupReady = useDeferredStartup();
  usePersonaSync(pubkey, relayUrl);
  useAgentsDataRefresh();
  // Auto-restart drifted idle agents (per-agent opt-out, default on).
  useAutoRestartPolicy();
  // Owner-global ingestion remains unguarded so managed-agent frames are not
  // dropped while the current identity is still resolving.
  useAgentObserverIngestion();
  // Ephemeral kind 24200 must be reconciled before archive listeners open.
  const observerReconciled = useObserverArchiveReconciliation(pubkey);
  useArchiveSync(observerReconciled);
  useArchiveAgentMetricsBridge();
  // Persisted kind 44200 can remain deferred because startup frames replay.
  const deferredPubkey = startupReady ? pubkey : undefined;
  useAgentMetricArchiveSeed(deferredPubkey);
  useRelayAutoHeal();
  usePresenceSubscription();
  useUserStatusSubscription();
  useCommunityEmojiLiveUpdates();
  useMembershipNotifications(pubkey);

  return { deferredPubkey };
}
