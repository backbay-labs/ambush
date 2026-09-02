/**
 * The relay this instance is configured to talk to (`AMBUSH_RELAY_URL`, read
 * back through `get_default_relay_url`). Dev instances always have one, so the
 * first-run screen can offer that community by name instead of asking for a
 * URL the app already knows.
 */

import { relayHttpFromWs } from "@/shared/api/inviteHelpers";
import { getJoinPolicy } from "@/shared/api/invites";

import { deriveCommunityName } from "./communityStorage";

export type ConfiguredCommunity = {
  /** The relay's own NIP-11 name, or a name derived from its host. */
  name: string;
  relayUrl: string;
};

/** Bounds the probe so an unreachable relay never delays the first-run screen. */
const RELAY_INFO_TIMEOUT_MS = 2_500;

/**
 * Whether this build may offer its configured relay as a community.
 *
 * Compiled into the dev server and explicit E2E builds only, mirroring the
 * mock-bridge gate in `main.tsx`: a shipped build falls back to
 * `ws://localhost:3000` when nothing is configured, and that fallback must
 * never be presented as a community to join.
 */
export function canOfferConfiguredCommunity(): boolean {
  return import.meta.env?.DEV === true || import.meta.env?.MODE === "e2e";
}

/** Name a relay by its NIP-11 `name`, falling back to its host-derived name. */
export function configuredCommunityName(
  relayInfoName: unknown,
  relayUrl: string,
): string {
  const advertised =
    typeof relayInfoName === "string" ? relayInfoName.trim() : "";
  return advertised || deriveCommunityName(relayUrl);
}

/**
 * Resolve the configured relay into an offer for the first-run screen, or
 * `null` when it should not be offered.
 *
 * The offer is a single click straight into onboarding, so it is withheld
 * unless that click can succeed: the relay has to answer its NIP-11 document,
 * and it must not carry a join policy — a policy needs the acknowledgment the
 * invite form collects before anyone connects.
 */
export async function resolveConfiguredCommunity(
  relayUrl: string,
): Promise<ConfiguredCommunity | null> {
  let httpUrl: string;
  try {
    httpUrl = relayHttpFromWs(relayUrl);
  } catch {
    return null;
  }

  try {
    const response = await fetch(httpUrl, {
      headers: { Accept: "application/nostr+json" },
      signal: AbortSignal.timeout(RELAY_INFO_TIMEOUT_MS),
    });
    if (!response.ok) return null;
    const document = (await response.json()) as { name?: unknown };
    if (await getJoinPolicy(relayUrl, "webview")) return null;
    return { name: configuredCommunityName(document.name, relayUrl), relayUrl };
  } catch {
    return null;
  }
}
