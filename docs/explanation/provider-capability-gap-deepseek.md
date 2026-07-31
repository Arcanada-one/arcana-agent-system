# Provider capability gap — DeepSeek and the least-privilege requirement

Date: 2026-07-31
Status: ratified
Decision owner: SEC-0030
Blast radius: 3 (cross-system — provider authority, credential broker, every consumer)
Panel: architect, security, SRE, devops, strategist

## Question

The credential-recovery requirement calls for a *least-privilege replacement*
with provider/model/operation scope, rate and spend caps, and a bounded
lifetime. Can DeepSeek satisfy that at the provider, and if not, what is the
correct outcome?

## Verified provider facts

Empirical, status-only probes against the live account (no credential value was
read, printed or transcribed):

| Probe | Result | Meaning |
|---|---|---|
| `GET /models` | `200` | The exposed key **still authenticates** |
| `GET /models` with invalid key | `401` | The probe distinguishes valid from invalid |
| `POST /chat/completions` | `402` | Account balance exhausted |

Documented capability, from vendor and secondary sources:

| Requirement | DeepSeek support |
|---|---|
| Per-key model/operation scope | Not offered |
| Per-key spend cap | Not offered |
| Per-key expiry / bounded lifetime | Not offered |
| Per-key IP allowlist | Not offered |
| Per-key RPM/TPM rate limit | Enforced by the provider, **not operator-configurable** |
| Programmatic key create/revoke | Not offered — web console only |

DeepSeek keys are account-scoped bearer credentials. A key either has full
account authority or does not exist.

### The 402 is not a revocation

This is the finding that most changes the risk picture. Authentication still
succeeds; only billing fails. The credential remains a valid bearer token whose
authority returns in full the moment anyone funds the account — including an
attacker holding a copy, since topping up an account does not require holding
the key. **Balance exhaustion must not be recorded as invalidation.**

## Panel

### Architect — conditional support for a compensating control

The requirement was written assuming a provider that issues capability-scoped
credentials. That assumption is simply false for this vendor, and no amount of
provider-side configuration will make it true. The scope boundary therefore has
to move to the only place we control: the broker. This is not a workaround —
terminating authority in a local broker was already the ratified architecture,
and an account-scoped upstream key is precisely the case that architecture was
designed to contain.

**Condition:** the broker must be the *sole* holder of the upstream key. A
compensating control that sits beside an environment-distributed key compensates
for nothing.

### Security — oppose retention as a primary provider; support the compensating control

Two distinct issues are being conflated and must not be.

First: the old key must still be formally revoked through the console. A `402`
is a billing state, not a security state. Treating it as invalidation would
leave a live bearer credential in 53 known local copies with a documented path
back to full authority.

Second: an account-scoped key means the blast radius of any future exposure is
the entire account — every model, unlimited spend, no expiry. Broker-enforced
scope genuinely reduces *agent-side* blast radius, because the agent can no
longer request arbitrary operations. It does **not** reduce *credential-side*
blast radius: anyone who obtains the upstream key still has full account
authority. That residual risk is irreducible at this provider and must be
recorded as accepted, not papered over.

**Condition:** the residual risk is documented explicitly, and the key lives in
the canonical secret channel with an owning accessor.

### SRE — support, with a reliability caveat

The compensating control adds the broker to the critical path of every
credentialed operation. That is the correct trade — fail-closed is the whole
point — but it means broker availability becomes provider availability. Since
the ratified design already forbids any fallback to secret-bearing execution,
a broker outage is a full stop for credentialed work. We should be honest that
this is a deliberate availability reduction bought with a security gain.

The exhausted balance is separately disqualifying for reliability: a provider
that silently returns `402` mid-pipeline killed three other lanes already. A
primary provider needs funded-balance monitoring regardless of this decision.

### DevOps — support; note the operational asymmetry

Every other provider in the canonical store has an accessor, a lease and a
revocation path. DeepSeek would be the sole exception managed by console
clicks. That asymmetry is an operational hazard: the runbook step "revoke the
key" means something different for this provider than for all 25 others, and
that difference will be forgotten under incident pressure.

**Condition:** the runbook states the console-only step explicitly rather than
implying parity with the rest of the store.

### Strategist — oppose retention as primary

Weigh what retention actually buys. DeepSeek's value was cost. Against that:
no scoping, no caps, no expiry, no programmatic revocation, an exhausted
balance, and an incident whose containment cost has already exceeded any
plausible savings. The provider fails the requirement on six of six axes. The
question is not whether to build the compensating control — we need it for any
account-scoped provider — but whether this provider earns a place behind it.

**Position:** build the compensating control, but demote DeepSeek from primary.

## Conflicts

| Between | Conflict | Resolution |
|---|---|---|
| Architect / Strategist | Architect treats the provider as a given and moves the boundary; Strategist questions keeping the provider at all | Both hold: the compensating control is required regardless (it generalises to any account-scoped provider), and the demotion is a separate, additive decision |
| Security / SRE | Security wants hard fail-closed; SRE notes this makes broker availability a hard dependency | Priority ladder: Security (3) outranks Reliability (4). Fail-closed stands; the availability cost is documented, not mitigated by a fallback |
| Security / "402 is good enough" | Whether balance exhaustion can stand in for revocation | Correctness (2) — a `402` with a `200` on `/models` is empirically not invalidation. Console revocation remains mandatory |

## Verdict

**DeepSeek cannot satisfy the least-privilege requirement at the provider.**
This is a provider-capability gap, not an implementation shortfall, and not an
operator task that can be completed by trying harder.

Three consequences follow:

1. **Record the gap.** The requirement's provider/model/operation scope, spend
   caps and bounded lifetime are unsatisfiable upstream. Recording this is the
   honest closure of that requirement — not marking it done.

2. **Compensate at our boundary.** The broker enforces provider, model and
   operation allowlists, quota and expiry on top of an account-scoped upstream
   key. The agent gains no ability to request an unscoped operation even though
   the underlying key is unscoped. This is the design already ratified; the gap
   makes it load-bearing rather than merely defensive.

3. **Demote DeepSeek from primary.** Retain it, if at all, behind the broker as
   a cost-tier option only, with the residual risk accepted in writing.

### Residual risk — accepted

Anyone who obtains the upstream key holds full account authority: every model,
unlimited spend, no expiry, revocable only through a web console. Broker
enforcement constrains what the *agent* can ask for; it cannot constrain what a
*key holder* can do. Accepting this is only tolerable while the broker is the
sole holder of the key.

## Failure modes

| Failure | Probability | Impact | Detection | Mitigation |
|---|---|---|---|---|
| `402` recorded as revocation, old key left live | **High** if unstated | High — live credential in 53 copies | `/models` returns `200` while `/chat/completions` returns `402` | Console revocation is a mandatory, separately evidenced step |
| Replacement re-issued into `.bashrc` / env files | Medium | High — reproduces the incident exactly | No accessor exists for the key | Replacement lands in the canonical store first; broker is sole reader |
| Broker becomes a single point of failure | Medium | Medium — credentialed work stops | Broker health check | Accepted by design; no secret-bearing fallback permitted |
| Console-only revocation forgotten under pressure | Medium | High | Runbook review | Runbook states the asymmetry explicitly |
| Account refunded, exposed key silently re-armed | Medium | High | Provider request audit | Revoke before any top-up |

## Conditions and assumptions

This decision holds while all of the following remain true:

- the broker is the sole holder of the upstream key, and no consumer reads it
  from environment, argv, readable config or an inherited descriptor;
- the replacement is stored in the canonical secret channel with an owning
  accessor, never in shell rc or host env files;
- console revocation of the old key is performed and evidenced independently of
  the balance state;
- the residual full-account-authority risk stays recorded and accepted.

If DeepSeek later ships scoped keys, spend caps or a key-management API, this
artifact should be revisited — the compensating control remains correct, but the
provider-side gap would close.
