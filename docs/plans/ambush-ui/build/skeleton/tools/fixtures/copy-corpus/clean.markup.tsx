// TODO: the old label said Approve; do not bring it back.
/* All clear was the phrase we removed. */
import { Trusted } from "./nope";
export function CorpusMarkupClean() {
  return (
    <div>
      <a href="/ledger?q=ambush:lease">open in Ledger</a>
      <button data-testid="perch-approve-legacy" aria-label="Record my decision and send it to the daemon">
        Record my decision
      </button>
      <span title="attestation matches this body">tier 1</span>
      <p>2 sources / 1 agent</p>
      <nav aria-label="Lanes">
        <span>Lanes</span>
      </nav>
      <p>authorized but held for human approval</p>
    </div>
  );
}
