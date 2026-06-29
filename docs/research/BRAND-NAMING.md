# AMBUSH ("Vector Swarm") — Brand / Naming / Trademark / Domain Risk Assessment

*Prepared 2026-06-28. Risk-screening opinion, not legal clearance.*

## Executive verdict
Overall naming risk: **HIGH**, driven by one term. Single most urgent action: **KILL "ClawdStrike" before any public launch, marketing, GitHub publishing, crate publishing, or fundraising.** It is a phonetic/visual parody of **CrowdStrike** (~$174B public cybersecurity co.) used for a *directly competing* category (EDR / detection & response). CrowdStrike is an aggressive enforcer: **sued rival "AiStrike" for trademark infringement, N.D. Cal. 5:2026-cv-01984 (filed 2026-03-06)** and **DMCA'd the "ClownStrike" parody (2024)**. "ClawdStrike" is *closer* to CrowdStrike than AiStrike. Cheapest to fix now (only an internal engine codename) — but already public under **`backbay-labs/clawdstrike`** (GitHub + `clawdstrike.ai` + `docs.rs/clawdstrike` crate), which *raises* exposure.

Secondary: **"Vector Swarm" + chain-of-custody/non-repudiation positioning is already occupied by competitor 7AI** ("swarming AI agents," "evidence collection & chain of custody"); "swarm" is now a generic category descriptor. Defensible to keep but not differentiating and weak as a trademark.

## Per-term findings
| Term | Issue | Severity | Recommendation |
|---|---|---|---|
| **ClawdStrike** (engine) | Parody of CrowdStrike, same EDR category; infringement+dilution+confusion; domains taken; already public via backbay-labs | **BLOCKER** | **Kill.** Rename engine; drop crate/repo/"SDR" copy. |
| **Swarm Team Six** (engine) | Echoes "SEAL Team Six"; USPTO §2(a) false-association refusals for SEAL marks; tonal/PR risk | **HIGH** | Kill/retire as any public name. |
| **Ambush** (product) | No security collision, BUT AMBUSH fashion house (Yoon Ahn, cls 9/42 muddy), common English word (weak mark + poor SEO), "attack" connotation for a defensive tool, all premium domains gone | **MEDIUM** | Reconsider; if kept, accept compromised domain + weak protection + coexistence check. |
| **Vector Swarm** (positioning) | "Vector" near Vectra AI / Vector Security; "Swarm" generic (7AI, Swimlane); vectorswarm.com taken | **MEDIUM** | Keep as tagline only, not a protectable brand. |
| **7AI** (competitor) | Positioning collision: markets "swarming AI agents" + "chain of custody" = Ambush's exact wedge; $130M Series A, ex-Cybereason | **HIGH (competitive)** | Differentiate the *message*: lead with governance/policy-receipts/provenance, not "swarm". |
| **Chio** (governance) | Chio snack brand (Intersnack, food classes) + anime; low security collision; SEO-buried | **LOW** | Keep internal; re-check if standalone. |
| **Whisker** (detector) | **Calico Whisker** (Tigera K8s network-security — same sector!) + "Whisker" red-team tool (Shadow Credentials) + libwhisker scanner + Whisker pet-tech | **MEDIUM** | Internal only; do not market standalone. |
| **OpenKnowledge** (embedded dep) | inkeep's product, GPL-3.0-or-later (strong copyleft); embedding may trigger copyleft on distributed combo | **MEDIUM (license)** | Don't rebrand as yours; **get GPL-3.0 linking/distribution legal review**. |
| **Orca** (upstream) | Hard collision with **Orca Security** (major CNAPP vendor) if surfaced in security branding | **HIGH if surfaced** | Internal/upstream reference only; never user-facing. |

**Domains:** every premium exact-match is gone — ambush.com/.ai/.io, getambush.com, ambushsecurity.com, vectorswarm.com, clawdstrike.com/.ai all unavailable. Social handles unverified.

## The CrowdStrike collision — KILL
"CrowdStrike" = coined, arbitrary, federally registered, internationally famous mark in *exactly this field* (broad protection + dilution under TDRA). "ClawdStrike" vs "CrowdStrike": same syllables/cadence, identical "-Strike" suffix, single-consonant swap — *more* similar than AiStrike (already being sued). Identical goods (EDR/D&R) = max confusion. Deliberate pun = evidence of bad-faith intent (cuts against you). Parody/fair-use is weakest when used as a commercial source identifier for *competing* goods. Demonstrated enforcement appetite (AiStrike suit + ClownStrike takedowns via CSC Digital Brand Services). **No safe version exists.**

## Alternative name candidates (screening-only, not cleared)
*Product:* Provenant (provenant.ai taken), Custody Ledger (custodyledger.ai available), Swarm Custody (swarmcustody.com available), Proven Swarm (provenswarm.ai available), Swarm Notary (swarmnotary.ai available), Vouchsafe (taken), Reckoner (taken).
*Engine (replace ClawdStrike/Swarm Team Six):* Chainwarden (chainwarden.ai available), Vowguard (vowguard.ai available), Warden/Marshal (warden.security available).
Guidance: prefer **coined/compound** marks (stronger legally, cleaner SEO, exact-match domains) over common words; de-emphasize "swarm" in the hero name.

## Confidence
MEDIUM-HIGH on headlines (ClawdStrike kill, Orca/7AI collisions, domains unavailable — verified). MEDIUM-LOW on fine print (no USPTO/EUIPO register search run; handles/WHOIS unverified; GPL analysis is a flag not an opinion). Formal clearance still needs: USPTO/EUIPO/WIPO searches by Nice class 9/42 incl. "-Strike" family; pull the AiStrike docket; WHOIS+handle audit; GPL-3.0 + Orca-derivation license review.
