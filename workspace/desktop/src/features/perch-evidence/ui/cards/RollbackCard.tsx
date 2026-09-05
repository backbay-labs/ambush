import type * as React from "react";

import {
  admitCard,
  envelopeTier,
  parseCardParts,
  type Card,
  type PartitionState,
  type RollbackFact,
} from "@/features/perch/wire";
import { AdversaryString } from "@/shared/ui/perch/AdversaryString";

import { isAdmittedIssuer } from "../../lib/admittedIssuers";
import type { SwarmCardDecoder, SwarmCardProps } from "../../lib/markerTypes";
import { defineSwarmCard } from "../defineSwarmCard";
import { EvidenceCardFrame } from "../EvidenceCardFrame";

type RollbackPayload = {
  envelope: Card;
  fact: RollbackFact;
};

const decodeRollback: SwarmCardDecoder<RollbackPayload> = (card) => {
  const parts = parseCardParts("rollback", card.rawBody);
  if (!parts) {
    return {
      ok: false,
      reason: "the human line or the swarm:rollback:v1 fence is missing",
    };
  }
  const admitted = admitCard(parts.json, card.issuerPubkey, isAdmittedIssuer);
  if (!admitted.ok) return { ok: false, reason: admitted.reason };
  const fact = admitted.card.fact as RollbackFact;
  if (fact.schema !== "swarm.perch.rollback.v1") {
    return {
      ok: false,
      reason: `fact.schema is ${fact.schema}, expected swarm.perch.rollback.v1`,
    };
  }
  return { ok: true, value: { envelope: admitted.card, fact } };
};

/**
 * What a rollback receipt with no governance attestation is, given where the
 * cluster stood when it executed (B2g-p). `null` is a third answer — the
 * console could not establish the state — and never a synonym for healthy.
 */
export function attestationBadge(state: PartitionState | null | undefined): {
  testid: string;
  text: string;
} {
  switch (state) {
    case "healthy":
    case "degraded":
      return {
        testid: `perch-attestation-badge-rollback-${state}`,
        text: "UNATTESTED",
      };
    case "partitioned":
    case "healing":
      return {
        testid: `perch-attestation-badge-rollback-${state}`,
        text: "UNATTESTED — BY DESIGN",
      };
    default:
      return {
        testid: "perch-attestation-badge-rollback-unknown",
        text: "UNATTESTED · the console could not establish the partition state",
      };
  }
}

function Row({ term, children }: { term: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-baseline gap-x-2">
      <dt className="text-2xs uppercase tracking-wide text-muted-foreground">
        {term}
      </dt>
      <dd className="text-sm">{children}</dd>
    </div>
  );
}

/** The read-only presenter. `data-testid="perch-evidence-rollback"` on its root. */
export function RollbackCardPresenter({
  card,
  payload,
}: SwarmCardProps<RollbackPayload>) {
  const { envelope, fact } = payload;
  const receipt = fact.rollback_receipt;
  const attested =
    receipt.governance_attestation !== undefined &&
    receipt.governance_attestation !== null;
  const badge = attestationBadge(fact.partition_state_at_execution);
  return (
    <div
      data-testid="perch-evidence-rollback"
      data-perch-rollback-status={receipt.status}
    >
      <EvidenceCardFrame
        kind="rollback"
        pillar="evidence"
        tier={envelopeTier(envelope)}
        eventId={card.eventId}
        issuerPubkey={card.issuerPubkey}
      >
        <dl className="space-y-1">
          <Row term="rollback">{receipt.rollback_id}</Row>
          <Row term="lease">{receipt.lease_id}</Row>
          <Row term="trigger">{`${receipt.trigger} · ${receipt.mode} · ${receipt.status}`}</Row>
          <Row term="summary">
            <AdversaryString value={receipt.summary} field="summary" />
          </Row>
          <Row term="attestation">
            {attested ? (
              <span data-testid="perch-attestation-badge-rollback-present">
                attestation carried · not checked by this console
              </span>
            ) : (
              <span data-testid={badge.testid}>{badge.text}</span>
            )}
          </Row>
          <Row term="steps">
            <ol className="list-decimal pl-5 text-xs">
              {receipt.steps.map((step) => (
                <li key={`${step.kind}:${step.detail}`}>
                  {`${step.kind} · ${step.status} · `}
                  <AdversaryString value={step.detail} field="step_detail" />
                </li>
              ))}
            </ol>
          </Row>
          <Row term="completed">
            {new Date(receipt.completed_at_ms).toLocaleString()}
          </Row>
        </dl>
      </EvidenceCardFrame>
    </div>
  );
}

export const rollbackCardEntry = defineSwarmCard<RollbackPayload>({
  pillar: "evidence",
  homeSurface: ["case"],
  maxTier: 1,
  decode: decodeRollback,
  Presenter: RollbackCardPresenter,
});
