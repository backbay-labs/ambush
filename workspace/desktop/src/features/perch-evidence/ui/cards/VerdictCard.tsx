import { useQuery } from "@tanstack/react-query";
import type * as React from "react";

import { isTheDecision } from "@/features/perch-watch/lib/isTheDecision";
import {
  admitCard,
  envelopeTier,
  parseCardParts,
  type Card,
  type VerdictFact,
} from "@/features/perch/wire";
import { PERCH_NO_RETRY, perchKeys } from "@/shared/api/perchKeys";
import { perchGetHold } from "@/shared/api/tauriPerch";
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
 * a question only the daemon's `HoldDecisionRecord` answers, so this card asks
 * it — by hold id, joined on the SIGNATURE bytes and never on the event id.
 *
 * With no daemon answer the card reads `unresolved`, which is a different
 * claim from `not-the-decision`: one says this console cannot reach the
 * authority, the other says the authority named somebody else. A card that
 * collapsed them would let an unreachable daemon read as "your decision lost".
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
  const holdId = fact.locator.subject === "hold" ? fact.locator.hold_id : null;
  // Only a hold verdict has a compare-and-set to have lost. A finding verdict
  // is not in a race with anybody, so it asks no question.
  const record = useQuery({
    queryKey: perchKeys.hold(holdId ?? ""),
    queryFn: () => perchGetHold(holdId ?? ""),
    enabled: holdId !== null,
    ...PERCH_NO_RETRY,
  });
  const verdict =
    holdId === null
      ? null
      : isTheDecision(
          { holdId, signatureHex: fact.signature.signature_hex },
          record.data?.hold ?? null,
        );
  return (
    <div
      data-testid="perch-evidence-verdict"
      data-perch-verdict-subject={fact.locator.subject}
      data-perch-leg2-state={leg2?.state ?? "unknown"}
      data-perch-decision-verdict={verdict ?? undefined}
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
          {verdict === null ? null : (
            <Row term="did it run">
              {verdict === "decision"
                ? "the daemon's record names this signature: this is the decision that ran"
                : verdict === "not-the-decision"
                  ? "not the decision — the daemon's record names another operator's signature"
                  : "unresolved — the daemon is unreachable, so this console cannot say which verdict ran"}
            </Row>
          )}
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
