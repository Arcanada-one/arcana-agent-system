# Content integrity and effect authority

Contract verification hashes the producer-declared preimage verbatim. It does not
reconstruct KC2 canonical JSON or treat the outer response as authenticated.
The outer `tools` field and its omission are outside that hash. They therefore
cannot grant tool calls, even when the content digest matches the work item.
Bindings currently carry an empty allowlist with `authority-not-bound`; the
contract permission layer denies effects, and the prompt offers no tools.
Legacy allowlist diagnostic values remain decodable API vocabulary only.

This is an unfinished integration hold, not an authenticated authority mechanism.
It intentionally disables formerly accepted contract-bound positive tool effects.
Interactive unbound runs keep their existing behavior; they are not KC-admitted.
An independently reviewed producer/consumer successor is required to enable a
positive contract-bound effect. It must establish authentic issuer and current
native authority, bind tool permissions to the requested contract, immutable
source and store generation, and check revocation at the actual effect boundary
including retry/resume. A new outer field or a guessed canonical body schema is
insufficient. This correction defines no producer schema and grants no authority.

Local controls retain content-positive verification, digest mismatch refusal,
explicit-empty refusal, identical-preimage outer-tool substitution, and actual
executor controls with the contract layer absent. The absent-layer control is a
local harness check, not a production bypass or a live authority canary. Exact
source review, current graph admission, CI, resulting main, installation provenance
and an authenticated paired live canary remain separate gates.
