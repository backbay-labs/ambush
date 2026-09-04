import type * as React from "react";

import {
  admitCard,
  envelopeTier,
  parseCardParts,
  threatClassSlug,
  type Card,
  type HoldFact,
} from "@/features/perch/wire";
import { AdversaryString } from "@/shared/ui/perch/AdversaryString";

import { isAdmittedIssuer } from "../../lib/admittedIssuers";
import type { SwarmCardDecoder, SwarmCardProps } from "../../lib/markerTypes";
import { defineSwarmCard } from "../defineSwarmCard";
import { EvidenceCardFrame } from "../EvidenceCardFrame";

/**
 * `swarm:hold:v1` on a case timeline. Read-only, and deliberately so.
 *
 * The card is the bridge's account of a hold; the DAEMON is the record. So
 * this presenter carries no grant control and no refuse control — deciding
 * happens on the Verdict Row, against a hold re-read from
 * `GET /v1/response/holds/{id}`, never against a relay event that may be
 * minutes stale. A decision control here would be a control that can act on a
 * hold that has already expired.
 */

type HoldPayload = {
  envelope: Card;
  fact: HoldFact;
};

const decodeHold: SwarmCardDecoder<HoldPayload> = (card) => {
  const parts = parseCardParts("hold", card.rawBody);
  if (!parts) {
    return {
      ok: false,
      reason: "the human line or the swarm:hold:v1 fence is missing",
    };
  }
  const admitted = admitCard(parts.json, card.issuerPubkey, isAdmittedIssuer);
  if (!admitted.ok) return { ok: false, reason: admitted.reason };
  const fact = admitted.card.fact as HoldFact;
  if (fact.schema !== "swarm.perch.hold.v1") {
    return {
      ok: false,
      reason: `fact.schema is ${fact.schema}, expected swarm.perch.hold.v1`,
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

function threatClassLabel(
  threatClass: HoldFact["hold"]["rationale"]["threat_class"],
): string {
  return typeof threatClass === "string"
    ? threatClassSlug(threatClass)
    : `custom: ${threatClass.custom}`;
}

/** The read-only presenter. `data-testid="perch-evidence-hold"` on its root. */
export function HoldCardPresenter({
  card,
  payload,
}: SwarmCardProps<HoldPayload>) {
  const { envelope, fact } = payload;
  const { hold } = fact;
  const irreversible = hold.inverse_resolution.find(
    (step) => step.verdict !== "executable",
  );
  return (
    <div data-testid="perch-evidence-hold" data-perch-hold-state={hold.state}>
      <EvidenceCardFrame
        kind="hold"
        pillar="authority"
        tier={envelopeTier(envelope)}
        eventId={card.eventId}
        issuerPubkey={card.issuerPubkey}
      >
        <dl className="my-1 flex flex-col gap-0.5">
          <Row term="action">{hold.action_kind}</Row>
          <Row term="severity">{hold.severity}</Row>
          <Row term="threat class">
            {threatClassLabel(hold.rationale.threat_class)}
          </Row>
          <Row term="why we are asking">
            <AdversaryString
              field="reason"
              value={hold.rationale.reason}
              layout="inline"
              cap={240}
            />
          </Row>
          <Row term="blast radius">
            {hold.rehearsal
              ? "the runtime derived a rehearsal preview; read it on the Verdict Row"
              : "NO REHEARSAL — the runtime derived no blast radius for this request"}
          </Row>
          <Row term="if you undo">
            {hold.inverse_resolution.length === 0
              ? "no rollback plan was derived"
              : irreversible
                ? `${irreversible.step_kind} is ${irreversible.verdict}`
                : "every planned rollback step has an executable inverse"}
          </Row>
          <Row term="what granting opens">
            {hold.leases_a_containment
              ? "a capability lease at the decision instant, then a containment lease"
              : "a capability lease at the decision instant"}
          </Row>
          <Row term="hold id">{hold.hold_id}</Row>
          <Row term="expires">
            {new Date(hold.expires_at_ms).toLocaleString()}
          </Row>
        </dl>
      </EvidenceCardFrame>
    </div>
  );
}

export const holdCardEntry = defineSwarmCard<HoldPayload>({
  pillar: "authority",
  homeSurface: ["case"],
  decode: decodeHold,
  Presenter: HoldCardPresenter,
});
