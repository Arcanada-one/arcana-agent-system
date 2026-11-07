# Vendored talomnia-knowledge KC2 schemas (pin for the strict reader)

Byte-exact copies of `ontology/schemas/*.schema.json` from
`Arcanada-one/talomnia-knowledge` at commit `b3fe119921357964d68d77980b10b9f80135d831`
(head of the OPEN, UNMERGED draft PR546). They are the normative shape of
`arcanada-kc2-tools/v1`; ARAS writes no second schema. Do not edit them: the reader checks the
git blob SHA-1 of each file against `TALOMNIA_SCHEMA_PIN` (`../pin.rs`) and refuses with
`CONTRACT_READER_UNSUPPORTED` on any difference.

Re-pin procedure (required if PR546 is squash-merged or amended, because the commit then no
longer exists on a stable ref): copy the new bytes, update the commit and every blob in
`pin.rs`, and re-run `contract_strict_parity` and `contract_strict_pin`.

`kc2-v2-contract.schema.json` (the `talomnia-ontology/v2` legacy shape) is vendored and pinned for
completeness only; the profile schema does not reference it.
