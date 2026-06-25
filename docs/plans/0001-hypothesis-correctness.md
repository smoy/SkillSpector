# 0001 — Hypothesis & Correctness: a neurosymbolic verification architecture

## Abstract

SkillSpector is a security **gate** — its score decides whether a skill is "safe to
install" — but it grew as an imperative tool, so its correctness invariants were never
stated, only embedded. This proposal asks how to put that gate on a verified footing.
The core idea is neurosymbolic: we can't formally verify the LLM at the center, but we
*can* verify the deterministic **safety envelope** around it (the rules that keep a real
CRITICAL finding from being dropped) by treating the LLM as an arbitrary adversarial
oracle. We adapt AWS's Cedar methodology — an authoritative executable model bridged to
production code by differential testing in CI — to a code-first, partly-neural Python
codebase. The first deliverable is not code but a **ratified specification**: an
archaeology pass that recovers each behavior and has a maintainer rule it intended,
incidental, or bug. The full architecture is below; this top section is for a
go/no-go decision.

## Pitch for maintainers

**The problem, concretely.** The risk score, the severity bands, and the LLM
finding-filter are the load-bearing safety logic, and they're guarded today by
example-based tests. Nothing *establishes* that a real CRITICAL survives the LLM filter
for every possible (including prompt-injected) model response, or that the score behaves
sanely across all inputs. For a tool whose whole job is to be trusted, that gap is the
product.

**This isn't theoretical — the archaeology already surfaced two issues.** While reading
the scoring code we found (1) **score depends on the input order** of equal-severity
findings, so adding a low-confidence finding can *lower* the score (`report.py:111-135`),
and (2) the 0-100→[0,1] confidence rule is **inconsistent across call sites**
(`>1.0` vs a historical `>2.0`). Both are exactly the kind of latent defect that a
stated, checked specification would have caught — and that example tests didn't.

**Why the approach is credible, not academic.** It copies a methodology AWS already
ships in production (Cedar): a small executable model as the source of truth, kept
honest against the real code by differential random testing in CI. We adapt it to
reality here — Python reference model first (no new toolchain, survives the OSS-sync
merges), heavyweight proofs (Lean/Dafny) held in reserve for the *one* deep theorem
that actually needs them (the adversarial-oracle envelope). We also draw an honest line:
the LLM itself is out of formal scope; we verify the symbolic guardrails, not the model.

**Why it's good open-source work.** It's self-contained (lives in `tests/` + a spec
module, touches no production behavior), naturally tiered for contributors of different
levels (property tests → reference model + DRT → optional theorem proving), and produces
durable artifacts — a readable spec and a CI gate — that outlast any one contributor.
It's also a strong showcase: "continuous formal verification of an AI-security tool" is
a recruiting and credibility win for the project.

**The decision we're asking for.** Is this worth pursuing, and at what ceiling? Three
forks gate everything (see §7): (1) **fidelity** — universal proof of the envelope, or
exhaustive-where-finite + adversarial sampling elsewhere? (2) **substrate** — start with
a Python reference model (recommended), or evaluate Lean/Dafny up front? (3) **home** —
downstream verification overlay, or upstream contribution with a real release gate? A
"yes, at fidelity X" unblocks the no-tooling archaeology pass as step one.

---

> **Status:** Architecture / design proposal. No source or test changes are made by
> this document. It (a) frames how verified development applies to a code-first,
> partly-neural tool, (b) records the raw archaeology material, and (c) surfaces the
> architectural decisions that must be made *before* any verification code is written.
>
> **Origin:** `docs/tasks/0001-hypothesis-correctness.md`. Prompted by commit
> `47c75223511f8ead154954c03293cc981ad4e569` (PR #32, *"isolate Stage 2 batch failures
> and keep unanalysed findings"*).
>
> **Architectural inspiration:** AWS, *["Lean into verified software
> development"](https://aws.amazon.com/blogs/opensource/lean-into-verified-software-development/)*
> (the Cedar methodology) — see §4.

---

## 1. Problem & framing

SkillSpector is a security **gate**: its output decides whether a skill is "safe to
install." Correctness failures are asymmetric — a dropped/under-scored CRITICAL is
dangerous (false negative); noise is merely annoying (false positive). The system is
tuned to fail toward false positives (fail-closed). The question this document
addresses is whether we can *establish* that those safety properties hold, continuously,
rather than hoping the example-based tests happen to cover them.

### 1.1 SkillSpector is already neurosymbolic

The pipeline mixes two kinds of computation, and they have different verifiability:

| | Components | Determinism | Verifiability |
|---|---|---|---|
| **Symbolic** | static pattern / YARA / AST / taint / MCP analyzers; **risk scoring**, banding, dedup, suppression | deterministic, pure | directly verifiable |
| **Neural** | LLM semantic analyzers (`semantic_*`), the **LLM meta-filter** (`nodes/meta_analyzer.py`) | non-deterministic, reads attacker-controlled content | not verifiable in isolation |

The neural layer reads attacker-controlled skill text, so the LLM is not merely
non-deterministic — it is potentially **adversarial**. You cannot verify the LLM. You
*can* verify the deterministic **safety envelope** that wraps it, by modeling the LLM
as an arbitrary oracle and proving the envelope holds for *all* of its outputs. That
is the neurosymbolic answer, and it determines the whole architecture below.

---

## 2. The inversion: this is code → spec, not spec → code

The single most important fact about applying verified development here:

> **AWS does verification-guided development: write the model, prove theorems, then
> write the code. SkillSpector is the reverse — the code already exists, grew
> imperatively, and the invariants were never stated up front.** Some are recorded in
> `DEVELOPMENT.md` as an afterthought; most are emergent.

This inversion changes what the first deliverable is. When the model comes first
(AWS), every line is intended by construction. When you reconstruct a model from
organically-grown code, the code conflates three things that look identical:

1. **Load-bearing invariants** someone meant (the severity floor; fail-closed — these
   even carry comments).
2. **Incidental-but-fine** behavior (the exact `1.3×` executable multiplier — a tuning
   knob, not a law).
3. **Incidental-and-wrong** behavior nobody decided (see SC-2 in §6 — score depends on
   the *input order* of equal-severity findings; it just fell out of a sort key).

### 2.1 Archaeology is *adjudication*, not extraction

You cannot mechanically "extract the invariants" from imperative code, because the
code is equally happy to exhibit (1), (2), and (3). The recovered behaviors are only
*candidates*. Turning a candidate into a spec line requires a **human ruling**:
intended / incidental / suspected-bug. That ratification step has no shortcut, and it
*is* the archaeology.

**Worked example (why this can't be automated).** The scoring sort key
(`report.py:111-114`) is `(rule_id, severity_rank)` with no confidence tie-break.
Python's stable sort then orders equal-severity findings by input position, and the
diminishing weights `(1.0, 0.5, 0.25)` are handed out by position. So a low-confidence
CRITICAL that appears *before* a high-confidence one steals the full-weight slot:

- input `[conf 0.01, conf 1.0]` → `50·1.0·0.01 + 50·0.5·1.0 = 25.5`
- input `[conf 1.0, conf 0.01]` → `50·1.0·1.0 + 50·0.5·0.01 = 50.25`

Same findings, different score. The code has no opinion on whether this is correct.
*Only a human* can rule "score must be permutation-invariant → add confidence to the
sort key" vs. "input order is meaningful → document it." A hand-written formal model
would almost certainly model the sort as severity-descending and **prove the bug
away** — which is exactly why the ratification must precede, and drive, the model.

> *(SC-2 is asserted from reading `report.py:111-135`; confirm empirically before
> filing. It is used here as a methodology example, not yet a ruled defect.)*

---

## 3. The verification boundary map

Cedar is small and pure, so AWS models *all* of it. SkillSpector is not uniform —
naming the boundary is half the architectural work. Three strata, three obligations:

| Stratum | Code | Verification obligation | Right mechanism |
|---|---|---|---|
| **S1 — pure deterministic cores** | scoring, banding, dedup, suppression, confidence normalization | output matches an authoritative spec for all inputs | executable reference model + **differential testing**; finite props (bounds, band partition) by **exhaustive enumeration** |
| **S2 — neural↔symbolic envelope** | `apply_filter`, fail-closed, batch isolation | safety property holds for **all possible (adversarial) LLM outputs** | model LLM as an **uninterpreted/arbitrary oracle**; prove (theorem prover) or heavily sample (adversarial property testing) the wrapper preserves the floor |
| **S3 — neural components** | LLM semantic analyzers | *unverifiable* | eval datasets, statistical bounds — **out of formal scope** |

Key consequences:

- **S1 is shallow.** `score ∈ [0,100]` is trivially true by the final
  `min(100, max(0, …))` clamp; band-partition is a complete proof by enumerating
  `range(0, 101)`. No solver required. Differential testing against a reference model
  + enumeration covers S1.
- **S2 is the only genuinely deep, universally-quantified theorem in the system**
  ("for all oracle outputs, every CRITICAL/HIGH input survives"). This is what
  Hypothesis can only *sample* and a prover can actually *close*. If anything here
  justifies a Lean-grade tool, it is S2 and only S2.
- **S3 must be drawn explicitly** so a green CI is never mistaken for "the LLM is
  correct." The boundary map itself is an archaeology deliverable.

---

## 4. Target architecture (AWS-shaped, substrate-light)

The transferable skeleton from the Cedar methodology — independent of language:

> **authoritative executable model  ⇄ (differential testing)  ⇄ production code,
> gated at release.**

AWS specifics, for reference: an executable **Lean model** doubles as spec and
documentation ("10X smaller than its corresponding Rust implementation"); **differential
random testing** runs "millions of random inputs … both model and code produce the same
output," nightly; and "a new version … isn't released unless its model, proofs, and
differential tests are up to date."

### 4.1 What we adopt, and what we change

- **Adopt the shape**: a separate, authoritative model; DRT as the bridge; a
  release/merge gate.
- **Change the substrate — do not lead with Lean.** Start with an **executable Python
  reference model** of the S1 cores: a deliberately simple, obviously-correct
  reimplementation, separate from the evolved production functions, that serves as
  spec-as-documentation and as the DRT oracle. It needs no second toolchain, no
  learning curve (AWS's own advice: "start simple"), survives OSS syncs in-language,
  and gives the shallow S1 strata everything they need.
- **Reserve Lean/Dafny for the S2 envelope theorem only.** That universal
  "for-all-oracles" guarantee is the one place a prover earns a second language. Treat
  it as a separately-justified phase, not the price of entry.

### 4.2 Continuous verification (the "CI" part)

| Cadence | Job | Covers |
|---|---|---|
| **Per-PR (fast)** | property tests + reference-model DRT on a few thousand inputs (seconds) | S1 regressions, envelope sampling |
| **Nightly (deep)** | DRT on millions of inputs; adversarial-oracle fuzzing of `apply_filter` | S1 drift, S2 envelope under adversarial responses |
| **Merge/release gate** | spec + DRT (+ S2 proof, if adopted) green; no *un-ratified* recovered behavior outstanding | the AWS gate, mapped to our flow |

`make verify` runs the fast tier; the deep tier runs in scheduled CI. The reference
model is the living, readable spec referenced from `DEVELOPMENT.md`.

---

## 5. The OSS-sync constraint (a force AWS doesn't have)

The git history shows periodic `Sync OSS release snapshot` merges. AWS's release gate
only bites when verification ships *with* the artifact. So there is a prior decision:

- **(a) Downstream research overlay** — verification lives strictly in `tests/` + a
  standalone spec module, never touching production files, engineered to survive
  upstream merges. The "gate" is advisory on this fork.
- **(b) Upstream contribution** — spec + DRT become part of the project and the release
  gate can actually block. Requires upstream buy-in.

This choice constrains where every artifact below lives, so it is settled first.

---

## 6. Raw archaeology material (candidate behaviors — NOT yet ratified)

Recovered from reading the code. Each row is a **candidate** awaiting the §2.1
adjudication (intended / incidental / suspected-bug). `S#` = stratum. This is input to
archaeology, not the spec.

### Scoring & banding — `nodes/report.py:89-148` (S1)

| ID | Recovered behavior | Source | Adjudication needed |
|----|--------------------|--------|---------------------|
| SC-1 | `risk_score ∈ [0,100]` always | `report.py:140` | intended (trivial by clamp) |
| SC-2 | Score depends on input order of equal-`(rule_id,severity)` findings; adding a finding can *lower* score | `report.py:111-135` | **suspected-bug** — see §2.1 |
| SC-3 | Contribution linear in confidence | `report.py:135` | likely intended |
| SC-4 | Base points CRITICAL 50 ≥ HIGH 25 ≥ MEDIUM 10 ≥ LOW 5; unknown ⇒ 5 | `report.py:78-83,125` | intended |
| SC-5 | Per-rule weights `(1.0,0.5,0.25)`, ≥4th occurrence ⇒ 0 | `report.py:85-86,131-134` | intended |
| SC-6 | `confidence ≤ 0` ⇒ 0 points, finding still reported | `report.py:120-122` | intended |
| SC-8 | Executable multiplier `1.3×`, once, before clamp | `report.py:137-140` | incidental (tuning knob) |
| BD-1 | Bands partition `[0,100]`: LOW`[0,20]`/MED`[21,50]`/HIGH`[51,80]`/CRIT`[81,100]` | `report.py:59,143-146` | intended (finite-checkable) |
| BD-3 | CRITICAL/HIGH ⇒ `DO_NOT_INSTALL`; MEDIUM ⇒ `CAUTION`; LOW ⇒ `SAFE` | `report.py:60-65,147` | intended |

### LLM-filter envelope — `nodes/meta_analyzer.py` (S2)

| ID | Recovered behavior | Source | Adjudication needed |
|----|--------------------|--------|---------------------|
| LF-1 | CRITICAL/HIGH survive `apply_filter` even if LLM denies them; tagged `llm-unconfirmed` | `meta_analyzer.py:362,441-444` | intended (the central safety invariant) |
| LF-2 | A finding whose batch never returned is kept (`_fallback_filtered`), not treated as rejected | `meta_analyzer.py:514,548-557` | intended (PR #32) |
| LF-3 | LLM exception ⇒ all findings pass through (fail-closed) | `meta_analyzer.py:279-307,568` | intended |
| LF-4 | `apply_filter` output ⊆ input (never invents findings) | `meta_analyzer.py:422-489` | intended (implicit) |
| LF-5 | `--no-llm`: conf `<0.4` drops unless severity∈{CRIT,HIGH}; code-example ⇒ `×0.5`, never hard-drop | `meta_analyzer.py:221-247` | intended |

### Confidence / batch isolation / dedup / suppression (S1, + S2 for BI-3)

| ID | Recovered behavior | Source | Adjudication needed |
|----|--------------------|--------|---------------------|
| CN-1 | Every confidence lands in `[0,1]` on all paths | `report.py:120`, `llm_analyzer_base.py:87-94`, `meta_analyzer.py:71-78` | intended |
| CN-2 | `>1` treated as 0-100 scale ÷100; **threshold differs across sites** (`>1.0` vs historical `>2.0`) | `llm_analyzer_base.py:90-93`, `meta_analyzer.py:75-77` | **suspected-inconsistency** |
| BI-1 | `ValueError`/`NotImplementedError`/`CancelledError` propagate | `llm_analyzer_base.py:438-441` | intended |
| BI-2 | Other `BaseException` swallowed; one bad batch never cancels fan-out | `llm_analyzer_base.py:442-445` | intended |
| DS-1 | Dedup never increases count | `deduplicate.py` | intended |
| DS-4 | Suppressed findings never affect `risk_score` | `report.py` partition→score | intended |
| DS-5 | Empty suppression rule matches nothing | `suppression.py:117-118` | intended |
| DS-6 | Fingerprint deterministic/stable | `suppression.py:85-103` | intended |

---

## 7. Open architectural decisions (settle before writing verification code)

1. **Fidelity ceiling.** Are we aiming for the universal guarantee on the S2 envelope
   (the theorem that pulls in a prover), or is "exhaustive-where-finite + DRT /
   adversarial-sampling everywhere else" the honest target for a tool with an
   unverifiable LLM at its core?
2. **Substrate.** Accept "Python reference model now, Lean reserved for the S2
   theorem," or evaluate Lean/Dafny up front as the modeling language?
3. **Home (per §5).** Downstream overlay or upstream contribution? Determines whether a
   real release gate is on the table.

---

## 8. Recommended sequencing

1. **Archaeology pass (no tooling).** Walk §6 with a maintainer; produce the *ratified
   spec*: each behavior tagged intended / incidental / bug, plus the §3 boundary map
   finalized. File SC-2 and CN-2 as defects-or-decisions. **This is the deliverable
   that must exist before anything else.**
2. **Decide the three forks in §7.**
3. **Stand up the S1 reference model + DRT** as the CI spine (`make verify` + nightly),
   plus exhaustive enumeration for the finite properties (BD-1, SC-1).
4. **Adversarial-oracle property testing of the S2 envelope** (LF-1..LF-4 over all
   oracle outputs).
5. **(Conditional on §7.1/7.2)** Lean/Dafny proof of the S2 envelope theorem, with the
   reference model as its executable counterpart and DRT as the bridge to production.

My current lean: do step 1 first with no machinery, adopt the AWS *shape* with a Python
reference-model substrate as the spine (steps 3–4), and treat the Lean envelope theorem
(step 5) as a separately-justified bet rather than the foundation — but decisions §7
genuinely move this, so they come before commitment.

---

## Appendix — verified scoring formula (read from `report.py:89-148`)

```
sort findings by (rule_id, severity_rank asc: CRITICAL<HIGH<MEDIUM<LOW)   # no confidence tie-break → SC-2
score = 0.0
for f in sorted:
    confidence = clamp(f.confidence, 0.0, 1.0)
    if confidence <= 0.0: continue            # SC-6
    base = SEVERITY_POINTS.get(f.severity.upper(), 5)   # 50/25/10/5  (SC-4)
    count = occurrences[rule_id]; occurrences[rule_id] += 1
    if count >= 3: continue                    # SC-5
    weight = (1.0, 0.5, 0.25)[count]           # SC-5  (allocated by position → SC-2)
    score += base * weight * confidence        # SC-3
if has_executable_scripts: score *= 1.3        # SC-8
final = min(100, max(0, int(score)))           # SC-1
band  = first b in [(81,CRIT),(51,HIGH),(21,MED),(0,LOW)] with final >= threshold   # BD-1
rec   = {LOW:SAFE, MEDIUM:CAUTION, HIGH:DO_NOT_INSTALL, CRITICAL:DO_NOT_INSTALL}[band]   # BD-3
```
