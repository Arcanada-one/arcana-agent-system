#!/usr/bin/env python3
"""check-env-declared.py — every environment variable the code reads is named in `.env.example`.

Graph admission's `v-config-schema` verifier asks the same question, but its Rust reader only
sees `env::var("LITERAL")`. Most reads in this repository go through a `const` (`env::var(ENV_API_KEY)`),
so a new variable added that way would pass the verifier undeclared. This check resolves the
`const NAME: &str = "..."` a read names, and also fails on a declared name nothing reads any more,
so the declaration cannot drift into a list of history.

Scanned: `crates/**/*.rs` (`env::var(…)` / `env::var_os(…)`) and `dev-tools/**/*.py`
(`os.environ.get(…)` / `os.environ[…]` / `os.getenv(…)`). Not scanned: shell scripts, and the
vendored `.github/graph-admission/` bundle, which is the program's code, not this repository's.

Usage: dev-tools/check-env-declared.py [REPO_ROOT]
Exit:  0 every read is declared and every declaration is read; 1 otherwise.
"""
import os
import re
import sys

OS_OWNED = {"HOME", "PATH", "TMPDIR"}
DECL_RE = re.compile(r"^\s*(?:export\s+)?#?\s*([A-Z_][A-Z0-9_]*)\s*=", re.M)
RUST_READ_RE = re.compile(r"\benv::var(?:_os)?\(\s*(?:\"([A-Za-z_][A-Za-z0-9_]*)\"|((?:\w+::)*)([A-Za-z_]\w*))\s*\)")
RUST_CONST_RE = re.compile(r"\bconst\s+([A-Z_][A-Z0-9_]*)\s*:\s*&(?:'static\s+)?str\s*=\s*\"([A-Za-z_][A-Za-z0-9_]*)\"")
PY_READ_RE = re.compile(r"""os\.(?:environ\.get\(|environ\[|getenv\()\s*["']([A-Za-z_][A-Za-z0-9_]*)["']""")


def files(root, top, ext):
    for base, dirs, names in os.walk(os.path.join(root, top)):
        dirs[:] = [d for d in dirs if d not in ("target", "__pycache__", ".out")]
        for name in sorted(names):
            if name.endswith(ext):
                path = os.path.join(base, name)
                yield os.path.relpath(path, root), open(path, encoding="utf-8", errors="replace").read()


def strip_line_comments(text):
    return "\n".join("" if line.lstrip().startswith("//") else line for line in text.splitlines())


def main(root):
    decl_path = os.path.join(root, ".env.example")
    if not os.path.exists(decl_path):
        print(f"FAIL .env.example missing under {root}")
        return 1
    declared = set(DECL_RE.findall(open(decl_path, encoding="utf-8").read()))

    rust = [(p, strip_line_comments(t)) for p, t in files(root, "crates", ".rs")]
    # Two modules may share a const name for different variables (`ENV_BASE_URL` is three keys),
    # so a bare name resolves in its own file first; a path (`a::b::NAME`) resolves crate-wide.
    local = {p: dict(RUST_CONST_RE.findall(t)) for p, t in rust}
    everywhere = {}
    for defs in local.values():
        for name, value in defs.items():
            everywhere.setdefault(name, set()).add(value)

    reads, unresolved = {}, []

    def read(key, path, text, pos):
        reads.setdefault(key, []).append(f"{path}:{text.count(chr(10), 0, pos) + 1}")

    for path, text in rust:
        for m in RUST_READ_RE.finditer(text):
            literal, qual, ident = m.group(1), m.group(2), m.group(3)
            if literal:
                read(literal, path, text, m.start())
                continue
            if not qual and ident in local[path]:
                read(local[path][ident], path, text, m.start())
                continue
            if len(everywhere.get(ident, ())) == 1:
                read(next(iter(everywhere[ident])), path, text, m.start())
                continue
            # A helper that reads its own parameter (`fn env_or(key: &str, …) { env::var(key) }`):
            # the names are the literals its callers in the same file pass.
            helper = re.search(r"\bfn\s+(\w+)\s*\(\s*" + re.escape(ident) + r"\s*:\s*&str", text[:m.start()])
            calls = list(re.finditer(r"\b" + re.escape(helper.group(1)) + r"\(\s*\"([A-Za-z_][A-Za-z0-9_]*)\"", text)) if helper else []
            for c in calls:
                read(c.group(1), path, text, c.start())
            if not calls:
                unresolved.append(f"{path}:{text.count(chr(10), 0, m.start()) + 1} env::var({qual or ''}{ident})")
    for path, text in files(root, "dev-tools", ".py"):
        for m in PY_READ_RE.finditer(text):
            read(m.group(1), path, text, m.start())

    failed = 0
    for key in sorted(reads):
        if key not in declared and key not in OS_OWNED:
            failed += 1
            print(f"FAIL UNDECLARED {key}: read at {', '.join(reads[key])}, not named in .env.example")
    for key in sorted(declared - set(reads)):
        failed += 1
        print(f"FAIL STALE {key}: named in .env.example, read nowhere in the scanned code")
    for site in unresolved:
        print(f"note unresolved read (not checked): {site}")
    print(f"{len(reads)} key(s) read, {len(declared)} declared, {failed} failure(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "."))
