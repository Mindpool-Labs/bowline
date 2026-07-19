# Bowline Neutrality Charter

**Charter version:** 1.0.0
**Status:** In force
**Anchoring:** every version of this charter is recorded in a public transparency log before it
takes effect; entries and verification steps are listed in [`docs/anchors.md`](anchors.md).

## Why this charter exists

Bowline decides where enterprise AI work should run. Mindpool Labs maintains Bowline, curates and
signs the registry, pricing, and TCO data feed that Bowline consumes, and may offer commercial
services that supply or operate model-serving capacity ("affiliated supply"). A judge whose
maintainer also sells supply has a conflict of interest. This charter does not deny that conflict;
it binds it with published, verifiable rules, so any operator can check — from disclosed inputs
alone — that Bowline's decisions do not favor its maintainer.

## Commitments

1. **Identical methodology.** Mindpool-affiliated supply appears in data-feed releases and in
   Bowline evidence only under the same published methodology
   ([`docs/methodology.md`](methodology.md)) applied to any other supply. No affiliated entry uses
   private formulas, private ratings, or private confidence rules.
2. **Affiliation is always disclosed.** Every feed entry and every evidence record that references
   Mindpool-affiliated supply flags it as affiliated.
3. **Affiliation is never an advantage.** Bowline never defaults to affiliated supply, and
   affiliation is never a tiebreaker. Placement decisions derive only from operator-owned inputs
   and published formulas.
4. **Signed, anchored feed releases.** Every data-feed release is signed, and the signature is
   anchored in the public transparency log. Methodology changes are logged before they take
   effect.
5. **Reproducible decisions.** Bowline's decisions remain deterministic and reproducible from
   disclosed inputs: published formulas, operator-owned costs and floors, and the versioned feed.
   No commitment in this charter depends on trusting Mindpool Labs' intentions — each one is
   checkable.

## Amendments

This charter is versioned. An amendment takes effect only after the new version, with a written
rationale, is anchored in the transparency log. The current and all previous versions remain
verifiable against their log entries.

## What this charter is not

It is not a third-party audit, and it does not claim Bowline's defaults fit every deployment.
Operators own their inputs and should verify decisions against the published methodology.
