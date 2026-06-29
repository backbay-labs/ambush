# Ambush — Founder Decisions

*Standalone decision set extracted from the Ambush Platform Brief (Capstone), 2026-06-28. These are the calls only the founder can make. Each lists the decision, the realistic options, the recommendation, and the reason. Treat this as a direct question set.*

---

1. **Wedge sequence — which arena do we enter first?**
   - *Options:* (a) land governed/validated code-review → prove on offense/CTF → expand to IR; (b) lead with autonomous offense/continuous-pentest; (c) lead with IR/DFIR; (d) lead with the governance kernel itself.
   - *Recommend:* (a) — code-review first, offense/CTF as proving ground, IR as later expansion.
   - *Why:* it develops the existential validated-fan-out capability in the lowest-liability, fastest-feedback arena while monetizing where "local" is non-negotiable, so the primitive compounds instead of forcing a pivot.

2. **Sales lead — painkiller vs attestation (vitamin)?**
   - *Options:* lead the sale with validated signal-to-noise (the slop-filter), or lead with cryptographic non-repudiation/attestation.
   - *Recommend:* lead with the signal-to-noise painkiller; build the signed attestation underneath as the moat.
   - *Why:* nobody pays a premium for "non-repudiation" by name, but the two are complementary halves gated by the same evidence layer, so leading with the painkiller sells while chain-of-custody compounds.

3. **The engine's near-term role — what do we do with the Rust engine now?**
   - *Options:* (a) extract `swarm-spine/-crypto/-policy` as a local governance/attestation daemon now, build the validator fresh, defer detection, cut/quarantine swarm-evolution; (b) keep the engine whole and wire detection early; (c) shelve it.
   - *Recommend:* (a) — extract the trust-kernel, build the validator as net-new code, defer detection. Do *not* repurpose `swarm-consensus` (BFT voting) as the finding-validator.
   - *Why:* it resolves the central marketing-vs-engineering inversion at minimal cost and defers the capital-intensive detection collision with funded EDR incumbents.

4. **Sandbox boundary — what isolation is mandatory for agents on untrusted code?**
   - *Options:* git worktrees as the boundary, vs mandatory container/microVM for any write or exploit lane.
   - *Recommend:* worktrees for read-only review now; container/microVM mandatory before any write or live-fire phase.
   - *Why:* worktrees are git isolation, not a security boundary, and the entire governance claim depends on the boundary being real.

5. **Air-gap / model-egress stance — what do we promise about where source code goes?**
   - *Options:* (a) DPA + frontier cloud inference only; (b) true air-gap with weaker local models only; (c) both, segmented by use case.
   - *Recommend:* (c), stated explicitly per segment — DPA cloud for code-review/offense; true air-gap (local models) as a named NDA/IR niche — and let first-partner discovery set the weighting.
   - *Why:* every frontier-model lane egresses the source, so we must say so plainly; if NDA buyers reject DPA cloud inference, local-model benchmarking is promoted to a gating eval arm and air-gap becomes load-bearing.

6. **Receipt-format standardization — bespoke or standards-aligned?**
   - *Options:* keep the engine's hand-rolled YAML/receipt format, vs adopt in-toto/Sigstore receipts + Cedar/OPA policy.
   - *Recommend:* standards-aligned (in-toto/Sigstore + Cedar/OPA).
   - *Why:* the receipt primitive is commoditizing toward an IETF draft and is the subject of a patent-pending twin, so alignment buys credibility, interop, and prior-art/FTO posture for free.

7. **OSS free-vs-paid boundary — what is given away vs charged for?**
   - *Options:* where to draw the line — how much of the filter, sandbox, and attestation is free.
   - *Recommend:* free = fan-out + worktree isolation + intel vault + the fail-closed governance floor + `ambush verify`; Pro = the validated cross-family slop-filter + container/microVM sandbox + synthesis Consolidate + signed attestation *export* + policy packs.
   - *Why:* a security tool that paywalls the safety floor never gets pointed at untrusted code, and an attestation you must pay to check is worthless — so give away the commodity and the verifier, charge for *produced* trust (the sign/verify split).

8. **First design-partner segment — who do we recruit first?**
   - *Options:* staff/principal AppSec engineers, boutique pentest/AppSec consultancies, or M&A technical-DD teams.
   - *Recommend:* a mix weighted to boutique consultancies plus 1-2 M&A-DD leads.
   - *Why:* consultancies give the fastest paid feedback and a natural home for a signed deliverable, while the DD lead validates both the local-vs-DPA thesis and the externally-verified-attestation conversion event.

9. **Brand & naming — kill ClawdStrike, and rename "Ambush"?**
   - *Options:* (a) kill "ClawdStrike" (and "Swarm Team Six") now and keep "Ambush" as the umbrella pending a formal USPTO/EUIPO clearance; (b) full rename to a coined/compound mark immediately.
   - *Recommend:* (a) immediately — kill the ClawdStrike codename this week regardless (it is a live, already-public legal blocker against a famous mark in the same EDR category); evaluate a full "Ambush" rename to a coined mark before any funding/clearance search.
   - *Why:* ClawdStrike is a willful-infringement landmine with no parody defense for a competing commercial source identifier, while "Ambush" is merely a weak common-word mark that a clearance search can re-decide without urgency.