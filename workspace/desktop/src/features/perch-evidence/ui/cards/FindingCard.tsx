import type * as React from "react";

import {
  type Card,
  type FindingFact,
  admitCard,
  envelopeTier,
  parseCardParts,
  threatClassSlug,
} from "@/features/perch/wire";
import { AdversaryString } from "@/shared/ui/perch/AdversaryString";

import { isAdmittedIssuer } from "../../lib/admittedIssuers";
import type { SwarmCardDecoder, SwarmCardProps } from "../../lib/markerTypes";
import { defineSwarmCard } from "../defineSwarmCard";
import { EvidenceCardFrame } from "../EvidenceCardFrame";
import { FindingCardActions } from "./FindingCardActions";

/**
 * `swarm:finding:v1`, with its verbs.
 *
 * `E` promotes the finding to a case the daemon mints; `C`, `D` and `I`
 * record a verdict in two legs. The action group is mounted only when the
 * card decoded, so a refusal state never carries something to press. The
 * facts it acts on come from the ADMITTED envelope below, never from the
 * timeline row's own copies of them.
 */

type FindingPayload = {
  envelope: Card;
  fact: FindingFact;
};

const decodeFinding: SwarmCardDecoder<FindingPayload> = (card) => {
  const parts = parseCardParts("finding", card.rawBody);
  if (!parts) {
    return {
      ok: false,
      reason: "the human line or the swarm:finding:v1 fence is missing",
    };
  }
  const admitted = admitCard(parts.json, card.issuerPubkey, isAdmittedIssuer);
  if (!admitted.ok) return { ok: false, reason: admitted.reason };
  const { fact } = admitted.card;
  if (fact.schema !== "swarm.perch.finding.v1") {
    return {
      ok: false,
      reason: `fact.schema is ${fact.schema}, expected swarm.perch.finding.v1`,
    };
  }
  return { ok: true, value: { envelope: admitted.card, fact } };
};

function Row({ term, children }: { term: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-baseline gap-x-2">
      <dt className="text-2xs uppercase tracking-wide text-[hsl(var(--perch-foreground-muted))]">
        {term}
      </dt>
      <dd className="m-0 text-sm">{children}</dd>
    </div>
  );
}

function threatClassLabel(threatClass: FindingFact["finding"]["threat_class"]) {
  return typeof threatClass === "string"
    ? threatClassSlug(threatClass)
    : `custom: ${threatClass.custom}`;
}

/** The read-only presenter. `data-testid="perch-evidence-finding"` on its root. */
export function FindingCardPresenter({
  card,
  payload,
}: SwarmCardProps<FindingPayload>) {
  const { envelope, fact } = payload;
  return (
    <div data-testid="perch-evidence-finding">
      <EvidenceCardFrame
        kind="finding"
        pillar="substrate"
        tier={envelopeTier(envelope)}
        gap={fact.gap}
        eventId={card.eventId}
        issuerPubkey={card.issuerPubkey}
      >
        <dl className="my-1 flex flex-col gap-0.5">
          <Row term="agent">{fact.issuer.swarm_agent_id}</Row>
          <Row term="threat class">
            {threatClassLabel(fact.finding.threat_class)}
          </Row>
          <Row term="severity">{fact.finding.severity}</Row>
          <Row term="confidence">
            confidence {fact.finding.confidence.toFixed(2)}
          </Row>
          <Row term="host">
            <AdversaryString
              field="host"
              value={fact.locator.host_id ?? "unknown"}
              layout="inline"
            />
          </Row>
          <Row term="finding id">{fact.locator.finding_id}</Row>
          <Row term="strategy">{fact.locator.strategy_id}</Row>
          <Row term="event id">{fact.locator.event_id}</Row>
          <Row term="evidence">
            {fact.evidence_truncated ? (
              <span>
                evidence omitted: {fact.evidence_truncated.bytes} bytes, sha256{" "}
                {fact.evidence_truncated.sha256}
              </span>
            ) : (
              <AdversaryString
                field="evidence"
                value={JSON.stringify(fact.finding.evidence ?? null)}
                layout="block"
              />
            )}
          </Row>
        </dl>
        <FindingCardActions card={{ cardEventId: card.eventId, fact }} />
      </EvidenceCardFrame>
    </div>
  );
}

export const findingCardEntry = defineSwarmCard<FindingPayload>({
  pillar: "substrate",
  homeSurface: ["case", "lane"],
  // A CEILING, not a reading. The pacer seals every evidence envelope and
  // `perch_verify_envelope` checks the hash, the signature and the chain link
  // — so this card MAY reach tier 2, and renders whatever the verifier
  // actually concluded, which is tier 1 for an unsigned or unchained envelope.
  maxTier: 2,
  decode: decodeFinding,
  Presenter: FindingCardPresenter,
});
