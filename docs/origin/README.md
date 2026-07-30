# Origin corpus — Assembly

Preserved operator source material behind the Assembly line of work: the
original post on execution-correctness invariants, the transcribed
operator↔assistant dialogue, the author's dated clarifications, and two working
attribution maps derived from them.

This directory is **provenance, not contract**. Nothing here is a ratified
architecture for this repository. Ratified design lives under
[`../reference/`](../reference/README.md) and [`../explanation/`](../explanation/README.md).

## Contents

| File | Kind | What it is |
|---|---|---|
| [`Инварианты корректности распределённого исполнения.md`](Инварианты%20корректности%20распределённого%20исполнения.md) | Source — do not edit | The operator's post, the full dialogue transcript, and three dated author clarifications (2026-07-30) at the end. Embeds the five screenshots below. |
| [`Смысловая карта диалога — Assembly.md`](Смысловая%20карта%20диалога%20—%20Assembly.md) | Working map | Attribution slice of the dialogue: decided by operator / proposed by assistant / undetermined / needs research. |
| [`Распределение смыслов Assembly по проектам Арканады.md`](Распределение%20смыслов%20Assembly%20по%20проектам%20Арканады.md) | Working map | Ownership slice: which meaning maps onto which Arcanada project, plus undetermined seams and the consilium queue. |
| `image_001.jpg` … `image_005.jpg` | Source — do not edit | Screenshots of the third-party post on abstract algebra for inter-agent communication that the operator's post responds to. Referenced inline from the source document; the originals were named `1000042548.jpg`–`1000042552.jpg` and were renamed on import, with the original names preserved as image alt text. |

Reading order: the source document first for what was actually said, then the
two working maps for what it was taken to mean.

## Language

The corpus is Russian because the source dialogue is Russian, and it is kept in
the original language so that operator wording is not lost in translation. The
rest of `docs/` is English.

## What the author settled, and what is still open

The three clarifications dated **2026-07-30** at the end of the source document
are the most recent authority in this corpus and override earlier passages:

- The categorical-algebraic approach of other authors is a **source of ideas and
  a language for checking properties, not a mandatory architectural
  dependency**. The practical design is a typed protocol, a Task Card, and a
  state machine, with a six-step canonical execution path.
- **Agent Arcana is a process supervisor** on a single execution boundary.
  In-process model API, a local vendor-CLI child process, and remote
  `tmux + vendor CLI` are three execution adapters of one Task Card protocol —
  they neither produce different result formats nor bypass execution invariants.
- A **new separate project, Agent Fleet Supervisor**, owns the fleet control
  plane across hosts. Fleet management does not belong to Muneral and must not
  grow inside it.

Both working maps have been brought up to date with these clarifications; see
§ «Уточнения автора 2026-07-30» in the semantic map and § 1.1 in the
distribution map. Everything still marked `НЕОПРЕДЕЛЕНО` in those files remains
genuinely open — notably the event-bus technology, the owner of the actual LLM
invocation, the artefact store, and the product/repository boundary of Prompt
Assembly. The claimed 80–90 % token reduction is an unmeasured hypothesis and is
recorded as such.

## Relationship to this repository

`Agent Arcana` in this corpus is the project built here. The clarification that
it is a per-host process supervisor is consistent with the shipped
[`crates/supervisor`](../reference/supervisor.md), which supervises OS child
processes on one host with process-group ownership, watchdogs, and budgets. The
fleet control plane is explicitly **out of scope for this repository** and
belongs to the new Agent Fleet Supervisor project.

## Integrity

The corpus was imported as a sealed 8-file package. Per-file SHA-256 at import:

```text
960e092f5740393c185dead72ae4a21405d0abb691ca6e09570ce0b3fc828294  Инварианты корректности распределённого исполнения.md
9204e0b28e19c01978546a4a6491b68180fd162be07fa17eca715f92fa5a4bf7  Распределение смыслов Assembly по проектам Арканады.md
523053b0a6273ae7b9245227669c80467e1f4f5cf0cb047086e2f59b84076f50  Смысловая карта диалога — Assembly.md
cc465026041e941637e12e2d83c7f83da4bede10a1610f52de81ffdb904e5be4  image_001.jpg
6d188f39e690b3d87dc66a8fa9e2a62883a0d91b7dcba8ed81ae09b200c514ed  image_002.jpg
3fb1b97be9ad91a66052864a603e2a46548b6573c94a39b0f03b5d1fafb098d8  image_003.jpg
f3cdb782a102ee4ac6d6a0873b00cc00fbfb7107a703b0ad3bc4438a24eccfe1  image_004.jpg
43cb3bcb3163fdd3019dde06f63f1918fb74717dcda35e8165949ad2068fd8cb  image_005.jpg
```

Aggregate manifest hash — `sha256sum * | sort | sha256sum`:

```text
5f045f9d08a4004cfedbc516616eb8572935aaf50b75c3e1bf503d6e102e0e4f
```

The source document and the five images are byte-identical to that manifest and
must stay so. The two working maps are living documents: they have been revised
since import to absorb the 2026-07-30 clarifications, so they no longer match
their import hashes by design. The hashes above remain the audit baseline —
re-derive divergence with `git log --follow` on the file in question.
