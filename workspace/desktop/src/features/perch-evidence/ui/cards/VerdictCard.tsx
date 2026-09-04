import type * as React from "react";

import {
  admitCard,
  envelopeTier,
  parseCardParts,
  type Card,
  type VerdictFact,
} from "@/features/perch/wire";
import { AdversaryString } from "@/shared/ui/perch/AdversaryString";

import { isAdmittedIssuer } from "../../lib/admittedIssuers";
import type { SwarmCardDecoder, SwarmCardProps } from "../../lib/markerTypes";
import { defineSwarmCard } from "../defineSwarmCard";
import { EvidenceCardFrame } from "../EvidenceCardFrame";

/**
 * `swarm:verdict:v1` — leg 1 of a decision, signed by a PERSON.
 *
 * Two chains meet on this card and the difference is the whole point. The
 * relay event is secp256k1 Schnorr, which proves only that this console's
 * Nostr key published it. The `signature` INSIDE the body is Ed25519 over the
 * decide route's own preimage, and it is what the daemon checks — but nothing
 * here checks it against the daemon, so this card never claims it did.
 *
 * A verdict card is an INTENT, not an outcome. Several can exist for one hold:
 * every Approve-scoped principal is `p`-tagged on the notice, the relay has no
 * compare-and-set, and a `kind:9` is immutable, so two consoles that both
 * decided leave two signed cards in the case channel forever. Which one ran is
 * a question only the daemon's `HoldDecisionRecord` answers; Task 27 wires
 * that predicate in and until then this card says `unresolved` rather than
 * picking one.
 */

type VerdictPayload = {
  envelope: Card;
  fact: VerdictFact;
};

const decodeVerdict: SwarmCardDecoder<VerdictPayload> = (card) => {
  const parts = parseCardParts("verdict", card.rawBody);
  if (!parts) {
    return {
      ok: false,
      reason: "the human line or the swarm:verdict:v1 fence is missing",
    };
  }
  const admitted = admitCard(parts.json, card.issuerPubkey, isAdmittedIssuer);
  if (!admitted.ok) return { ok: false, reason: admitted.reason };
  const fact = admitted.card.fact as VerdictFact;
  if (fact.schema !== "swarm.perch.verdict.v1") {
    return {
      ok: false,
      reason: `fact.schema is ${fact.schema}, expected swarm.perch.verdict.v1`,
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

/** The subject's id, whichever discriminator the card carries (D-FC-3). */
function subjectId(fact: VerdictFact): string {
  return fact.locator.subject === "hold"
    ? fact.locator.hold_id
    : fact.locator.finding_id;
}

/** The read-only presenter. `data-testid="perch-evidence-verdict"` on its root. */
export function VerdictCardPresenter({
  card,
  payload,
}: SwarmCardProps<VerdictPayload>) {
  const { envelope, fact } = payload;
  const leg2 = fact.leg2;
  return (
    <div
      data-testid="perch-evidence-verdict"
      data-perch-verdict-subject={fact.locator.subject}
      data-perch-leg2-state={leg2?.state ?? "unknown"}
    >
      <EvidenceCardFrame
        kind="verdict"
        pillar="authority"
        tier={envelopeTier(envelope)}
        eventId={card.eventId}
        issuerPubkey={card.issuerPubkey}
      >
        <dl className="my-1 flex flex-col gap-0.5">
          <Row term="decision">{fact.decision.decision}</Row>
          <Row term="subject">
            {fact.locator.subject} {subjectId(fact)}
          </Row>
          <Row term="operator">{fact.decision.operator_id}</Row>
          <Row term="decided at">
            {new Date(fact.decision.decided_at_ms).toLocaleString()}
          </Row>
          {fact.decision.rationale ? (
            <Row term="rationale">
              <AdversaryString
                field="rationale"
                value={fact.decision.rationale}
                layout="inline"
                cap={320}
              />
            </Row>
          ) : null}
          <Row term="leg 2">
            {leg2 === undefined
              ? "not yet reported by this console"
              : leg2.state === "superseded"
                ? "superseded — another operator's decision ran"
                : leg2.state}
          </Row>
          {/* The claim this card is entitled to make, and no more. */}
          <Row term="signature">
            Ed25519 · tier 1 (leg-1 signature; not verified against the daemon
            here)
          </Row>
        </dl>
      </EvidenceCardFrame>
    </div>
  );
}

export const verdictCardEntry = defineSwarmCard<VerdictPayload>({
  pillar: "authority",
  homeSurface: ["case"],
  decode: decodeVerdict,
  Presenter: VerdictCardPresenter,
});
