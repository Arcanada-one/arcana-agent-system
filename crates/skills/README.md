# arcana-skills

The **skills-engine**: a skill is *declarative data*, not code. A `SkillPlan`
names the stages a skill runs, the model each stage uses, its agent-count,
per-stage limits, tool allowlist, and metrics, plus a `template ↔ instance`
distinction and a `draft → validated → production` maturity ladder. The
`SkillInterpreter` loads a plan from a data file **on every invocation** and
executes its stages in declared order — each stage routed through the existing
`arcana_core::execution::CapabilityExecutor` (the single Blake3 audit log +
permission cascade). Because the plan is re-read from disk each run, a bumped
on-disk version is picked up on the *next run* of the same binary: a data
reload, never a recompile.

The engine opens **no** audit sink and **no** dispatch path of its own. Model
calls flow through the `model_call` capability (from `arcana-tools`); per-stage
model selection is either a literal id or a `TaskType` resolved through the
reused `arcana_core::dispatch::ModelPolicy`.

## Example plan (JSON)

```json
{
  "schema_version": 1,
  "name": "summarize-then-code",
  "version": 1,
  "kind": "instance",
  "maturity": "production",
  "stages": [
    {
      "id": "draft",
      "model": { "by_task_type": "code" },
      "agent_count": 1,
      "limits": { "max_turns": 2, "max_cost_usd": 0.25, "context_budget_chars": 8192 },
      "tools": [],
      "metrics": [{ "name": "coverage", "goal": 0.9 }],
      "action": { "capability": "model_call", "input": { "prompt": "draft the change" } }
    }
  ],
  "defaults": { "model": { "by_task_type": "default" } }
}
```

## Running

```rust
let interpreter = SkillInterpreter::new(executor, ModelPolicy::new());
let out = interpreter.run(&plan_path, &ctx).await?;
```

A `PlanKind::Template` or a below-`Production` maturity is refused on the run
path with a typed `SkillError`; instantiate + promote first
(`plan.instantiate().promote(Maturity::Production)`).

## Scope

In scope: the plan schema, the read-on-invoke interpreter, single-`execute`
stages over the `CapabilityExecutor`, per-stage multi-model dispatch, and a
minimal `SkillBuilder::draft_stub`. Deferred to **ARAS-0046**: the LLM-drafted
builder and the background-improvement loop (re-run + re-score against
`metrics` + auto-promote). No broker/queue — tokio in-process only;
`unsafe_code = "forbid"`.
