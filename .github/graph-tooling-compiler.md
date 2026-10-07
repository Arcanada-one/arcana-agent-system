# Graph tooling compiler project

The tracked `.github/tsconfig.json` checks the actual shipped CommonJS observer
with `allowJs`, `checkJs` and `noEmit`. Its `files` list names the shipped CJS
source; it does not create a Nest application or execute the observer. No type
stubs, source overlays, exclusions or diagnostic suppressions are supplied.

`graph-tooling-compiler-sdk.json` declares the real TypeScript, Node typings and
transitive declaration bytes used for this project. Before checking, verify every
`sdk_files` path and SHA256 against an existing SDK root. The root is supplied by
the caller and is never a host path committed into this project.

```sh
node "$GRAPH_COMPILER_SDK_ROOT/typescript/bin/tsc" \
  --project .github/tsconfig.json \
  --typeRoots "$GRAPH_COMPILER_SDK_ROOT/@types" \
  --listFiles --pretty false
```

The explicit `typeRoots` binds dependency discovery to that verified root.
A compiler installed on PATH alone does not bind project dependency resolution.
The canonical graph verifier must preserve the same dependency binding when it
checks its exported source tree. Compiler diagnostics are failures to repair;
this project declaration does not assert a successful check or change admission.

The metadata observer's domain-specific Nest contract scope, reusable workflow
callee closure, exact-head graph admission and runtime authority remain separate.
