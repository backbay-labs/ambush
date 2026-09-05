import type { SourceAttribution } from "./types";

/**
 * The agent behind a source id.
 *
 * A source id is `{agent}:{strategy}` and an agent key itself contains colons
 * (`swarm:ed25519:…`), so the split is the LAST colon, not the first. Mirrors
 * `distinct_agents` in `crates/swarm-ingest-runtime/src/ingest/perch_ops/deposits.rs`.
 *
 * An id with no colon is its own agent. That is not a fallback: operator
 * feedback arrives as a bare id, and counting it as zero agents would make the
 * denominator smaller than the numerator.
 */
export function agentIdOfSource(sourceId: string): string {
  const cut = sourceId.lastIndexOf(":");
  return cut === -1 ? sourceId : sourceId.slice(0, cut);
}

/** Both numbers from one function, so a caller cannot render one without the other. */
export function sourceCounts(
  attribution: Extract<SourceAttribution, { kind: "ids" }>,
): { sources: number; agents: number } {
  return {
    sources: new Set(attribution.sourceIds).size,
    agents: new Set(attribution.sourceIds.map(agentIdOfSource)).size,
  };
}

/**
 * Render law 2: never a bare source count.
 *
 * Twelve sources from one agent and twelve sources from twelve agents are
 * different evidence, and the first is what a single misconfigured detector
 * looks like. A frame that carries only `distinct_sources` says the agent
 * count is not carried rather than reusing the source count for both.
 */
export function attributionText(attribution: SourceAttribution): string {
  if (attribution.kind === "ids") {
    const { sources, agents } = sourceCounts(attribution);
    return `${sources} source${sources === 1 ? "" : "s"} / ${agents} agent${agents === 1 ? "" : "s"}`;
  }
  const sources = attribution.distinctSources;
  return `${sources} source${sources === 1 ? "" : "s"} / agent count not carried`;
}
