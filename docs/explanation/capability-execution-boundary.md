# Why capability execution is one fused, fail-closed boundary

Understanding-oriented: the reasoning behind `CapabilityExecutor`, the
`ToolInvocation` token, and the sole-transform-authority rule.

## Context

A tool call is the only place the agent may touch the outside world, so the
seam between *authorising* a call and *executing* it is the trust boundary of
the whole system. Two properties must hold for every executed call:

1. **Provenance** — the value a tool runs on is exactly the value the
   permission cascade authorised (including any sandboxing/rewrite a rule
   applied). A caller must not be able to execute a tool with a raw,
   un-governed payload.
2. **Attribution** — every executed call produces exactly one correlated
   audit record pair (one decision, one result). No silent execution (zero
   records), no double-count (audit noise), and the audited value equals the
   executed value.

## The decision

An earlier design split the boundary in two: the cascade minted a proof token
("authorise here") and a separate dispatcher method consumed it to run the
tool ("dispatch there"), while the audit record was produced by an audit
*hook* living in a composable hook chain. That shape is sound only if every
composition wires it correctly — the token has to be threaded to the one
sealed method, and the audit hook has to be present exactly once. Both are
*composition contracts*: properties a reviewer must re-verify at every call
site.

We replaced it with a single owned transaction. **`CapabilityExecutor` is the
sole execution authority.** It consumes the `ToolDispatcher` at construction
(freezing the registry), and owns the permission cascade, the non-audit hook
chain, and a mandatory synchronous audit sink. One method — `execute` —
authorises, validates, audits, and runs the call as one indivisible unit.
There is no public dispatcher lookup and no raw-value execution function.

### Token: from a mint-here/dispatch-there proof to a move-only invocation

The execution input is carried by `ToolInvocation`: a private-field,
crate-constructable, move-only value. `Tool::execute(ToolInvocation)` is the
only way to run a tool, and only the executor can construct the invocation —
after the cascade, final schema validation, and the durable decision audit.
A forged invocation built from an arbitrary value is a **compile error**
(the field is private; external crates cannot name it). This gives the same
compile-time bypass guarantee the proof-token design aimed for, but folds it
into the one component that already owns execution, instead of a token handed
across a module boundary. The move-only nature also means an invocation is
consumed exactly once, directly into the registered implementation.

### Fail-open → fail-closed default

The permission cascade walks its layers and short-circuits on the first
concrete answer. The prior pipeline ended an all-layers-defer walk by
*allowing* the call — a fail-**open** default: if no authority objected, the
call ran. The fused boundary inverts this. When every layer defers, the
cascade denies with `layer: "cascade"` — no authority *approved*, so the call
is refused. Fail-closed is the only safe default for an execution boundary,
and it is now the structural default, pinned by a regression test
(all-defer cascade → denied, zero tools executed).

### Sole transform authority, type-enforced

A permission layer may rewrite the payload (for example, a rule that sandboxes
a path). That rewrite is *governed*: it happens inside the cascade, and the
downstream layers (rule matching, interactive human-approval) re-evaluate the
rewritten value before it is authorised. Hooks that need to transform input
therefore register as a cascade layer (the hook bridge), where the transform
is re-governed.

The executor also runs a post-cascade hook stage, but that stage is a
**veto / side-effect gate only** — it must never transform the executed input,
or it would smuggle a value past the rule-deny and human-approval gates the
cascade already applied. This is enforced *by type*, not by convention: the
post-cascade gate returns an outcome (`PreToolGate`) that has **no input
field**. `Proceed` carries nothing; the executed value is always the
cascade-authorised input. A post-cascade "replace the input" outcome is
unrepresentable — writing one is a compile error, pinned by a `compile_fail`
doctest. A hook that nonetheless emits a replace-input result at this stage is
rejected fail-closed at runtime as a misconfiguration, but the executor has no
channel that could route such a value into execution in the first place.

This is the key improvement over a runtime guard ("hooks must never replace
input here"): a convention can be violated by the next contributor; a type
that cannot express the unsafe operation cannot.

### Single audit by construction

The audit sink is a plain field the executor owns and calls directly — it is
**not** a `ToolHook`. Because it is not composable, it cannot be omitted from
a call (the executor always calls it) and it cannot be bridged twice into the
same execution path (there is no second place to register it). The
"exactly one audit pair per execution" property is therefore true *by
construction*, not by a composition contract a reviewer must re-check. A
concurrency test drives sixteen executions and asserts exactly sixteen
correlated decision/result pairs with unique invocation ids; records carry
hashes only, never raw input, output, or error text.

This structurally closes what would otherwise have been a separate follow-up
task — guarding against a double-bridged audit hook. There is nothing to
double-bridge: the audit is a field, not a hook. That follow-up is resolved by
construction and needs only a regression test to pin it, not new code.

### Durability and latching

Both audit writes are synchronous and flushed. A decision-write failure
executes zero tools (fail-closed before the side effect). A result-write
failure — after the tool already ran — is fatal and **latches the executor
closed** for all later attempts: once the system can no longer prove what it
did, it stops doing new things.

## Consequences

- Execution provenance and single-audit are structural properties of one owned
  transaction, not contracts spread across a token hand-off and a hook chain.
- The unsafe operations (raw-value execution, post-cascade input transform,
  forged invocation) are *unrepresentable*, verified by `compile_fail`
  doctests, not merely discouraged.
- The default authorisation posture is fail-closed.
- Filesystem tools still apply their own path-traversal guard internally; that
  is a tool-level defence and is unchanged by this boundary.
