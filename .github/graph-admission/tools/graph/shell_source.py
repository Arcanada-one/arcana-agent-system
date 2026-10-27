"""Bounded, non-executing Bash/Bats source analysis; dynamic closure is unknown.

Syntax runs bash -n on captured bytes only. Bats test declarations are translated
to functions for that syntax check; this never sources a test, hook, helper or CI job.
Behavior remains a separate mandatory, source-bound fixture evidence obligation.
"""
import os
import re
import hashlib
import shutil
import shlex
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

import shell_workflow

KINDS = {"bash_source", "bats_test"}


def kind(path, raw, mode=None):
    if path.endswith(".bats"):
        return "bats_test"
    if path.endswith((".sh", ".bash")):
        return "bash_source"
    if mode != "100755":
        return None
    first = raw.splitlines()[0].decode("utf-8", errors="replace") if raw else ""
    if mode == "100755" and re.fullmatch(r"#!\s*(?:/bin/bash|/usr/bin/bash|/usr/bin/env\s+bash)\s*", first):
        return "bash_source"
    return None


def analyse(path, raw, paths, *, root_cwd=False, cwd=None):
    text = raw.decode("utf-8", errors="replace")
    unknown, references, inventory = [], [], []
    functions, commands = [], []
    cwd = "." if root_cwd else cwd
    # Resolve only the common, source-anchored directory idiom.  Arbitrary
    # command substitutions remain dynamic and are never evaluated here.
    source_dirs = {}
    for match in re.finditer(
            r'''(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=.*\$\(\s*cd\b.*\bdirname\s+['"]?\$\{?BASH_SOURCE(?:\[[^]]+\])?''', text):
        source_dirs[match.group(1)] = os.path.dirname(path) or "."
    # Also accept `HERE=$(dirname "${BASH_SOURCE[0]}")`, whose relative
    # directory is anchored to the repository-root invocation of shell jobs.
    for match in re.finditer(
            r'''(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['"]?\$\(\s*dirname\s+['"]?\$\{?BASH_SOURCE(?:\[[^]]+\])?\}?['"]?\s*\)['"]?\s*$''', text):
        source_dirs[match.group(1)] = os.path.dirname(path) or "."
    for match in re.finditer(
            r'''(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['"]?\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/([^$`*?\s'";|&]+)['"]?\s*$''', text):
        if match[2] in source_dirs:
            source_dirs[match[1]] = os.path.join(source_dirs[match[2]], match[3])
    # A literal, standalone `cd` in a workflow run body is a bounded source
    # fact. Dynamic and compound transitions remain unknown; this does not
    # evaluate command substitutions or infer a shell script's runtime cwd.
    workflow_file = path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml"))
    if text.encode("utf-8") != raw:
        unknown.append("non-UTF-8 source is not parsed losslessly")
    first = text.splitlines()[0] if text else ""
    if first.startswith("#!") and not re.search(r"\bbash\b|\bbats\b", first):
        unknown.append("declared non-Bash interpreter dialect is not measured by bash syntax")
    translated = []
    heredoc, quoted = None, None
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if heredoc:
            translated.append(line)
            if stripped == heredoc:
                heredoc = None
            continue  # heredoc contents are data, never extracted as shell callers
        if quoted:
            translated.append(line)
            if re.search(r"(?<!\\)" + re.escape(quoted), line):
                quoted = None
            continue
        if re.search(r"\b(?:cd|pushd|popd)\b", line):
            literal_cd = re.fullmatch(
                r'''\s*cd\s+(?:--\s+)?(?:'([^']+)'|"([^"]+)"|([A-Za-z0-9._/-]+))\s*(?:#.*)?''',
                line)
            target = next((value for value in literal_cd.groups() if value is not None), None) if literal_cd else None
            controls = re.search(r"\b(?:if|then|elif|else|fi|for|while|until|case|esac|function|eval)\b|[;&|()]", text)
            candidate = os.path.normpath(os.path.join(cwd or ".", target or "")) if target else None
            safe_candidate = (workflow_file and literal_cd is not None and cwd is not None and not controls
                              and target is not None and not target.startswith("/") and "\\" not in target
                              and "$" not in target and "`" not in target
                              and ".." not in PurePosixPath(candidate or "").parts
                              and candidate == ".")
            translated.append(line)
            if safe_candidate:
                cwd = candidate
                continue
            cwd = None
            root_cwd = False
            unknown.append(f"line {lineno}: directory transition has unresolved execution cwd")
            continue
        if stripped.startswith("@test"):
            m = re.fullmatch(r'''\s*@test\s+(["'])(.+)\1\s*\{\s*(?:#.*)?''', line)
            if not m or any(x in (m[2] if m else "") for x in ("$", "`")):
                unknown.append(f"line {lineno}: unsupported/dynamic Bats registration")
                translated.append(line)
            else:
                inventory.append(m[2])
                translated.append(f"__graph_bats_test_{len(inventory)}() {{")
            continue
        translated.append(line)
        if not stripped or stripped.startswith("#"):
            if re.search(r"bats.*\bfocus\b", stripped):
                unknown.append(f"line {lineno}: focused Bats selection")
            continue
        for m in re.finditer(r'''['"]?\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?(?:/([^$`*?{}\s'";|&]+))?['"]?''', line):
            if m[1] not in source_dirs or (m[2] and os.path.isabs(m[2])):
                continue
            data_path = os.path.normpath(os.path.join(source_dirs[m[1]], m[2] or ""))
            if data_path in paths and ".." not in PurePosixPath(data_path).parts:
                references.append({"path": data_path, "type": "imports", "line": lineno,
                                   "cwd": source_dirs[m[1]], "loader": "data-read",
                                   "function_namespace": True, "provenance": "deterministic",
                                   "via": "literal-shell-data-read"})
        if root_cwd and re.match(r"^(?:-\s*)?run:", stripped):
            line = re.sub(r"^(?:-\s*)?run:", "", stripped).strip()
            if len(line) >= 2 and line[0] == line[-1] and line[0] in "\"'":
                line = line[1:-1]
        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|(){}")
            lexer.whitespace_split = True
            lexer.commenters = "#"
            tokens = list(lexer)
        except ValueError:
            # Multiline quotes/heredocs are not safely resolved by this bounded scanner.
            unknown.append(f"line {lineno}: multiline/opaque shell statement")
            quoted = lexer.state if lexer.state in ("'", '"') else None
            continue
        here = re.search(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1", line)
        if here:
            heredoc = here[2]
            unknown.append(f"line {lineno}: heredoc data/generation closure not measured")
        statements, current = [], []
        for token in tokens + [";"]:
            if token and all(c in ";&|{}" for c in token):
                if current:
                    statements.append(current)
                current = []
            else:
                current.append(token)
        for words in statements:
            bypass_function = False
            while words and (words[0] in ("then", "do", "else", "if", "elif", "!", "exec", "run", "env")
                             or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", words[0])):
                bypass_function = bypass_function or words[0] in {"exec", "env"}
                words = words[1:]
            if len(words) > 1 and words[0] == "command" and not words[1].startswith("-"):
                bypass_function = True
                words = words[1:]
            if words and words[0] in ("timeout", "nice", "sudo"):
                unknown.append(f"line {lineno}: wrapper execution scope/options unresolved")
                continue
            if words and words[0] == "function" and len(words) > 1:
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", words[1]):
                    functions.append({"name": words[1], "line": lineno})
                else:
                    unknown.append("unsupported function declaration identity")
                continue
            if not words or words[0] in ("fi", "done", "esac", "}"):
                continue
            if words[0].startswith("-"):
                unknown.append(f"line {lineno}: wrapper options/child command unresolved")
                continue
            if len(words) > 1 and (words[1] == "()" or words[1:3] == ["(", ")"]):
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", words[0]):
                    functions.append({"name": words[0], "line": lineno})
                else:
                    unknown.append("unsupported function declaration identity")
                continue
            command = words[0]
            if not bypass_function and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", command):
                commands.append({"name": command, "line": lineno})
            if command in ("eval", "alias", "unalias") or "$" in command or "`" in command:
                unknown.append(f"line {lineno}: dynamic command/alias/eval")
                continue
            if command == "skip":
                unknown.append(f"line {lineno}: Bats skip may omit a required test")
            loader = command in ("source", ".", "load", "bash", "/bin/bash", "bats")
            target = words[1] if loader and len(words) > 1 else command
            if loader and (len(words) < 2 or target.startswith("-")):
                unknown.append(f"line {lineno}: unsupported loader/interpreter options")
                continue
            bats_dir = target.startswith(("$BATS_TEST_DIRNAME/", "${BATS_TEST_DIRNAME}/"))
            if bats_dir:
                target = target.split("/", 1)[1]
            if "$" in target or "`" in target or "$(" in line or "<(" in line:
                if loader or "$(" in line or "<(" in line:
                    unknown.append(f"line {lineno}: dynamic load/substitution")
                continue
            if not loader and "/" not in target and target not in paths:
                continue  # a literal external utility/function, not a guessed repository call
            if target.startswith("/"):
                if loader:
                    unknown.append(f"line {lineno}: external absolute source/command")
                continue
            candidates = [os.path.normpath(os.path.join(cwd, target))] if cwd is not None else [
                os.path.normpath(os.path.join(os.path.dirname(path), target)), os.path.normpath(target)]
            if bats_dir or command == "load":
                candidates = candidates[:1]
            if command == "load":
                candidates = [c for p in candidates for c in (p + ".bash", p)]
            resolved = sorted({p for p in candidates if p in paths and ".." not in PurePosixPath(p).parts})
            if len(resolved) != 1:
                if loader or target.startswith("."):
                    unknown.append(f"line {lineno}: missing/ambiguous literal helper {target}")
                continue
            certain_cwd = cwd is not None or bats_dir or command == "load"
            references.append({"path": resolved[0], "type": "imports" if command in ("source", ".", "load") else "calls",
                               "line": lineno, "cwd": cwd, "loader": command, "function_namespace": not bypass_function, "provenance": "deterministic" if certain_cwd else "inferred"})
            if not certain_cwd:
                unknown.append(f"line {lineno}: relative execution cwd is not declared")
    if path.endswith(".bats") and not inventory:
        unknown.append("Bats inventory is empty or unmeasured")
    if len(inventory) != len(set(inventory)):
        unknown.append("Bats inventory has ambiguous duplicate names")
    if path.endswith(".bats"):
        for body in re.split(r"(?m)^\s*@test\s+", text)[1:]:
            body = re.split(r"(?m)^\s*}\s*$", body, maxsplit=1)[0]
            statements = [s.strip() for s in body.splitlines()[1:] if s.strip() and not s.lstrip().startswith("#")]
            assertion = r'''(?:\[|\[\[|test)\s+["']?\$(?:status|\{status\})["']?\s+(?:-eq|==|=|!=|-ne)\s+\d+\s*(?:\]|\]\])?\s*(?:#.*)?'''
            for i, statement in enumerate(statements):
                if statement.startswith("run ") and (i + 1 == len(statements)
                                                       or not re.fullmatch(assertion, statements[i+1])):
                    unknown.append("Bats run lacks an immediate unconditional child status assertion")
            if any(re.match(r"(?:if|for|while|until|case)\b", s) for s in statements):
                unknown.append("Bats conditional execution membership is not statically resolved")
    return {"references": references, "unknown": sorted(set(unknown)), "tests": inventory,
            "functions": functions, "commands": commands,
            "syntax_source": "\n".join(translated) + "\n"}


def workflow(path, raw, paths):
    """Only literal Bash step contexts yield deterministic repository calls.

    PyYAML is optional: absence/opaque representation retains unknown closure,
    rather than falling back to treating arbitrary YAML lines as root commands.
    Unknown closure selects conservative inferred shell callers in the builder.
    """
    refs, unknown, unbound_callers = [], [], []
    try:
        import yaml
        text = raw.decode("utf-8")
        if any(type(t).__name__ in ("AliasToken", "AnchorToken", "TagToken", "DirectiveToken")
               for t in yaml.scan(text)):
            raise ValueError("aliased/tagged workflow context")
        node = yaml.compose(text, Loader=yaml.BaseLoader)
        def unique(n):
            if isinstance(n, yaml.MappingNode):
                keys = [k.value for k, _ in n.value]
                if len(keys) != len(set(keys)):
                    raise ValueError("duplicate workflow context keys")
                for _, v in n.value:
                    unique(v)
            elif isinstance(n, yaml.SequenceNode):
                for v in n.value:
                    unique(v)
        unique(node)
        data = yaml.load(text, Loader=yaml.BaseLoader)
        if not isinstance(data, dict) or not isinstance(data.get("jobs"), dict):
            raise ValueError("workflow jobs context is not a mapping")
        def defaults(scope):
            d = scope.get("defaults", {})
            if not isinstance(d, dict) or not isinstance(d.get("run", {}), dict):
                raise ValueError("opaque workflow run defaults")
            return d.get("run", {})
        def environment(scope):
            env = scope.get("env", {})
            if not isinstance(env, dict):
                return False
            return not any(key in shell_workflow.SOURCE_ENVIRONMENT for key in env)
        root = defaults(data)
        for name, job in data["jobs"].items():
            if not isinstance(job, dict) or "uses" in job or not isinstance(job.get("steps"), list):
                unknown.append(f"job {name}: reusable/opaque shell context")
                unbound_callers.append(f"job {name}: reusable/opaque caller has no target script reference")
                continue
            inherited = {**root, **defaults(job)}
            checkout_unknown = any(
                isinstance(step, dict) and str(step.get("uses", "")).startswith("actions/checkout@")
                and (not isinstance(step.get("with", {}), dict)
                     or (step.get("with") or {}).get("path")
                     or (step.get("with") or {}).get("repository"))
                for step in job["steps"])
            inherited_env_safe = environment(data) and environment(job)
            prior_env_write = False
            for index, step in enumerate(job["steps"]):
                if not isinstance(step, dict):
                    unknown.append(f"job {name} step {index}: opaque step")
                    unbound_callers.append(f"job {name} step {index}: opaque caller has no target script reference")
                    continue
                if "run" not in step:
                    local_action = str(step.get("uses", "")).startswith("./")
                    checkout_path = (step.get("with") or {}).get("path")
                    if local_action or checkout_path:
                        unknown.append(f"job {name} step {index}: local action/checkout path scope unresolved")
                    if local_action:
                        unbound_callers.append(
                            f"job {name} step {index}: local action caller has no target script reference")
                    elif checkout_path:
                        unbound_callers.append(
                            f"job {name} step {index}: checkout path leaves later script callers unbound")
                    continue
                shell = step.get("shell", inherited.get("shell", "bash"))
                wd = step.get("working-directory", inherited.get("working-directory", "."))
                context = f"job {name} step {index}"
                valid = (isinstance(wd, str) and bool(wd) and not wd.startswith("/")
                         and not any(c in wd for c in "$`~\\")
                         and ".." not in PurePosixPath(wd).parts)
                if not valid or shell != "bash" or "windows" in str(job.get("runs-on", "")).lower() or "container" in job:
                    unknown.append(context + ": dynamic/unsupported shell or working-directory")
                    cwd = None
                else:
                    cwd = os.path.normpath(wd)
                if checkout_unknown or not inherited_env_safe or not environment(step) or prior_env_write:
                    unknown.append(context + ": checkout root or source-affecting workflow environment unresolved")
                    cwd = None
                run = step["run"]
                if not isinstance(run, str):
                    unknown.append(context + ": opaque run body")
                    unbound_callers.append(context + ": opaque run body has no target script reference")
                    continue
                # These files can change a later step's PATH/environment. A
                # source-only projection cannot establish their resulting value.
                if "GITHUB_ENV" in run or "GITHUB_PATH" in run:
                    prior_env_write = True
                analysis = shell_workflow.analyse(path, run.encode("utf-8"), paths, cwd=cwd)
                if cwd is None or analysis["unknown"]:
                    for ref in analysis["references"]:
                        ref["provenance"] = "inferred"
                step_references = list(analysis["references"])
                reference_keys = {
                    (ref["path"], ref["type"], ref["line"])
                    for ref in step_references
                }
                # The workflow parser remains primary. Its opaque/unknown result
                # is preserved, while the existing shell source parser may add
                # only inventory-bound, target-local inferred call candidates.
                # This secondary pass has no cwd and never supplies YAML context.
                if cwd is None or analysis["unknown"]:
                    secondary = analyse(path, run.encode("utf-8"), paths,
                                        cwd=None, root_cwd=False)
                    for ref in secondary["references"]:
                        if (ref["type"] != "calls"
                                or ref["provenance"] != "inferred"
                                or ref["cwd"] is not None
                                or ref["path"] not in paths):
                            continue
                        # A known workflow cwd with a primary line-specific
                        # refusal (for example a missing helper under sub/)
                        # cannot be replaced by a root-relative fallback.
                        if (cwd is not None and any(
                                reason.startswith(f"line {ref['line']}:")
                                for reason in analysis["unknown"])):
                            continue
                        key = (ref["path"], ref["type"], ref["line"])
                        if key not in reference_keys:
                            step_references.append(ref)
                            reference_keys.add(key)
                refs.extend(step_references)
                unknown.extend(context + ": " + s for s in analysis["unknown"])
                # An unknown on a source line with a parsed target reference is
                # scoped to that target (whose provenance was downgraded above).
                # Unknowns on other lines, or without a line binding, may be an
                # additional caller that emits no target reference at all.
                referenced_lines = {ref["line"] for ref in step_references}
                run_lines = run.splitlines()
                def has_multiple_statements(line_number):
                    if line_number < 1 or line_number > len(run_lines):
                        return True
                    try:
                        lexer = shlex.shlex(run_lines[line_number - 1], posix=False,
                                            punctuation_chars=";&|")
                        lexer.whitespace_split = True
                        lexer.commenters = "#"
                        return any(token and all(char in ";&|" for char in token)
                                   for token in lexer)
                    except ValueError:
                        return True
                unbound_unknown = any(
                    (match := re.match(r"line (\d+):", reason)) is None
                    or int(match.group(1)) not in referenced_lines
                    or has_multiple_statements(int(match.group(1)))
                    for reason in analysis["unknown"]
                )
                if unbound_unknown:
                    unbound_callers.append(context + ": unresolved shell caller has no target script reference")
    except (ImportError, ValueError, UnicodeError, TypeError, AttributeError, RecursionError) as ex:
        unknown.append("workflow shell context not measured: " + str(ex))
        unbound_callers.append("workflow shell context not measured; caller targets are unavailable")
    except Exception as ex:
        # YAML parser failures remain a scoped unknown; never invoke a shell.
        unknown.append("workflow shell context not measured: " + type(ex).__name__)
        unbound_callers.append("workflow shell context not measured; caller targets are unavailable")
    return {"references": refs, "unknown": sorted(set(unknown)),
            "unbound_callers": sorted(set(unbound_callers))}


def tap_membership(raw, inventory):
    """An exit-zero/filtered/skipped TAP stream never replaces actual complete membership."""
    text = raw.decode("utf-8", errors="strict")
    plans = re.findall(r"(?m)^1\.\.(\d+)\s*$", text)
    rows = re.findall(r"(?m)^(ok|not ok) (\d+) (.+)$", text)
    if (not inventory or plans != [str(len(inventory))] or len(rows) != len(inventory)
            or [int(r[1]) for r in rows] != list(range(1, len(inventory)+1))
            or [r[2] for r in rows] != inventory or any(r[0] != "ok" for r in rows)
            or re.search(r"(?i)#\s*(?:skip|todo)|bail out!", text)):
        return False
    return True


def syntax(path, raw, paths):
    try:
        analysis = analyse(path, raw, paths)
        if any("Bats registration" in s for s in analysis["unknown"]):
            return "not_measured", {**analysis, "exit_code": 125}
        with tempfile.TemporaryDirectory(prefix="graph-shell-syntax-") as td:
            p = Path(td) / "source.bash"
            p.write_text(analysis["syntax_source"])
            run = subprocess.run(["bash", "--noprofile", "--norc", "-n", str(p)],
                                 capture_output=True, timeout=15)
            shellcheck = shutil.which("shellcheck")
            shellcheck_sha256 = "4da528ddb3a4d1b7b24a59d4e16eb2f5fd960f4bd9a3708a15baddbdf1d5a55b"
            lint = {"verdict": "not_measured", "reason": "pinned ShellCheck 0.11.0 unavailable"}
            if shellcheck:
                shellcheck = str(Path(shellcheck).resolve())
                digest = hashlib.sha256(Path(shellcheck).read_bytes()).hexdigest()
                version_run = subprocess.run([shellcheck, "--version"], capture_output=True, timeout=5)
                version_text = (version_run.stdout + version_run.stderr).decode("utf-8", "replace")
                if (digest == shellcheck_sha256 and version_run.returncode == 0 and
                        re.search(r"(?m)^version: 0\.11\.0$", version_text)):
                    lint_args = [shellcheck, "--shell=bash", "--severity=warning", "--format=json"]
                    # Bats' `run` command creates `status`; ShellCheck cannot see
                    # that framework-provided dynamic variable in a syntax projection.
                    if path.endswith(".bats"):
                        lint_args += ["--exclude=SC2154"]
                    lint_run = subprocess.run([*lint_args, str(p)],
                                              capture_output=True, timeout=15)
                    lint_out = (lint_run.stdout + lint_run.stderr).decode("utf-8", "replace")
                    lint = {"verdict": "failed" if lint_run.returncode else "verified",
                            "path": shellcheck, "sha256": digest, "version": "0.11.0",
                            "exit_code": lint_run.returncode, "output": lint_out[:4000]}
                else:
                    lint = {"verdict": "not_measured", "reason": "ShellCheck binary identity is not the pinned release",
                            "path": shellcheck, "sha256": digest, "version_output": version_text[:1000]}
        if run.returncode or lint["verdict"] == "failed":
            verdict = "failed"
        elif analysis["unknown"] or lint["verdict"] == "not_measured":
            verdict = "not_measured"
        else:
            verdict = "verified"
        return verdict, {**analysis, "source_sha256": hashlib.sha256(raw).hexdigest(),
                         "exit_code": run.returncode,
                         "stderr": run.stderr.decode("utf-8", errors="replace"), "shellcheck": lint}
    except (ValueError, OSError, subprocess.SubprocessError) as ex:
        return "not_measured", {"unknown": [str(ex)], "exit_code": 127}


def function_scope_unknown(analysis, *, allowed_calls=(), shadowed=()):
    """Check declaration/include scope at token positions, never in string data."""
    conditional = {'if', 'elif', 'else', 'then', 'case', 'for', 'while', 'until', 'select'}
    mutable = {'unset', 'eval', 'alias', 'unalias', 'declare', 'typeset', 'enable',
               'return', 'exit', 'exec', 'trap', 'set', 'shopt'}
    # Export qualification is a closed grammar, not a catalogue of every shell
    # builtin that might change state. Provider bodies/callbacks outside it owe
    # a separate proof; only the consumer may call its captured sourced names.
    allowed = ({'true', ':', 'echo'} - set(shadowed)) | set(allowed_calls)
    allowed |= {'source', '.', 'load', 'function', 'command', 'builtin', '!'}
    captured_names = {fn['name'] for fn in analysis.get('functions', [])}
    # These bodies come only from the existing validated Bats projection;
    # they are scope containers, never exported declarations/binding candidates.
    captured_names |= {'__graph_bats_test_' + str(i)
                       for i in range(1, len(analysis.get('tests', [])) + 1)}
    unknown, depth = [], 0
    for line in analysis['syntax_source'].splitlines():
        try:
            lexer = shlex.shlex(line, posix=False, punctuation_chars='{}();&|')
            lexer.whitespace_split = True
            lexer.commenters = '#'
            raw_tokens = list(lexer)
            if any(token and all(c in '{}();&|' for c in token) and any(c in '&|' for c in token)
                   for token in raw_tokens):
                unknown.append('conditional/mutable function source scope')
            tokens = [part for token in raw_tokens for part in
                      (list(token) if token and all(c in '{}();&|' for c in token) else [token])]
        except ValueError:
            unknown.append('nested/unbalanced function declaration scope')
            continue
        command_start, source_offset = True, 0
        for i, token in enumerate(tokens):
            token_start = line.find(token, source_offset)
            token_end = token_start + len(token)
            if token_start < 0:
                unknown.append('opaque command word source position')
            else:
                source_offset = token_end
            try:
                normalized = shlex.split(token) if command_start else []
            except ValueError:
                normalized = []
            word = normalized[0] if len(normalized) == 1 else token
            declaration = (re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', token) and (tokens[i+1:i+3] == ['(', ')']
                           or (i > 0 and tokens[i-1] == 'function')))
            header = tokens[i+1:i+3] == ['(', ')'] or (i > 0 and tokens[i-1] == 'function')
            if header and (not declaration or token not in captured_names):
                unknown.append('function declaration outside captured name grammar')
            if depth and (declaration or (command_start and word in {'source', '.', 'load'})):
                unknown.append('nested/unbalanced function declaration scope')
            if command_start:
                if (not declaration
                        and token not in {'{', '}', '(', ')', ';', '&', '|'}
                        and word not in allowed):
                    unknown.append('command outside closed function export grammar')
                # posix=False retains quoted reserved-word spelling, but can
                # split a command such as 'un'set into two tokens. Refuse that
                # adjacent word grammar instead of qualifying its first piece.
                joined_quote = (token.startswith(('"', "'")) and token_start >= 0
                                and token_end < len(line)
                                and not line[token_end].isspace()
                                and line[token_end] not in '{}();&|<>')
                if (joined_quote or token == 'time'
                        or re.match(r'^[0-9]*[<>]', token)):
                    unknown.append('unsupported command word/prefix source scope')
                # Reserved words require unquoted spelling; quoted arguments
                # and comments never introduce a conditional source scope.
                if token in conditional or word in mutable or token.startswith('-'):
                    unknown.append('conditional/mutable function source scope')
            if token in {'{', '('}:
                depth += 1
                command_start = True
            elif token in {'}', ')'}:
                depth -= 1
                if depth < 0:
                    unknown.append('nested/unbalanced function declaration scope')
                command_start = False
            elif token in {';', '&', '|'}:
                command_start = True
            elif command_start and (token == 'function' or word in {'command', 'builtin', 'exec', '!'}
                                    or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*=.*', token)):
                continue
            else:
                command_start = False
    if depth:
        unknown.append('nested/unbalanced function declaration scope')
    return unknown


def function_bindings(path, files, *, cwd=None, expected_calls=()):
    """Source-reference contracts only; no execution/reachability claim.

    Resolve declarations through literal source/dot/load includes. Do not treat
    bash child scripts as imports into the caller's function namespace. Ambiguous
    declarations and uncertain include cwd cannot establish a binding.
    """
    seen, declarations, unknown = set(), {}, []
    analyses = {}
    def visit(current, context):
        key = (current, context)
        if key in seen:
            unknown.append("recursive source closure")
            return
        if len(seen) >= 64 or current not in files:
            unknown.append("missing/oversized source closure")
            return
        seen.add(key)
        a = analyse(current, files[current], files, cwd=context)
        analyses[current] = a
        unknown.extend(a["unknown"])
        for fn in a["functions"]:
            declarations.setdefault(fn["name"], []).append((current, fn["line"]))
        for ref in a["references"]:
            if ref["type"] != "imports":
                continue
            if ref.get("loader") == "load" and not path.endswith(".bats"):
                unknown.append("Bats load namespace unavailable")
                continue
            if ref["provenance"] != "deterministic" or not ref.get("function_namespace", True):
                unknown.append("source include cwd/namespace not bound")
                continue
            visit(ref["path"], ref.get("cwd"))
    visit(path, cwd)
    a = analyses.get(path, {"commands": []})
    sourced_names = {name for name, providers in declarations.items()
                     if any(provider != path for provider, _ in providers)}
    for current, analysis in analyses.items():
        unknown.extend(function_scope_unknown(analysis,
            allowed_calls=sourced_names | set(expected_calls) if current == path else (),
            shadowed=declarations))
    if set(declarations) & {"source", "load"}:
        unknown.append("source/load loader is shadowed by a function declaration")
    bindings = []
    for call in a["commands"]:
        providers = declarations.get(call["name"], [])
        imports = [ref for ref in analyses.get(path, {}).get("references", [])
                   if ref["type"] == "imports" and ref["provenance"] == "deterministic"]
        if (len(providers) == 1 and providers[0][0] != path
                and imports and call["line"] > max(ref["line"] for ref in imports)):
            bindings.append({"name": call["name"], "line": call["line"],
                             "provider": providers[0][0], "definition_line": providers[0][1]})
        elif len(providers) > 1:
            unknown.append("ambiguous function declaration: " + call["name"])
    if bindings:
        # A lexical declaration in invalid source is not an exported function.
        # Parse captured bytes only; -n never sources a helper or runs its body.
        for analysis in analyses.values():
            try:
                checked = subprocess.run(["bash", "--noprofile", "--norc", "-n"],
                    input=analysis["syntax_source"].encode("utf-8"),
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                if checked.returncode:
                    unknown.append("function source syntax not qualified")
            except (OSError, subprocess.SubprocessError):
                unknown.append("function source syntax qualification unavailable")
    return {"bindings": [] if unknown else bindings, "commands": a["commands"],
            "candidate_names": sorted({c["name"] for c in a["commands"]} & sourced_names),
            "unknown": sorted(set(unknown))}


def removed_function_references(path, base_files, head_files, *, cwd=None):
    """Prove a removed source function contract with a retained direct reference.

    No success result here can discharge shell behavior. Only loss of an exact
    previously bound provider definition is a failure. Unknown selection stays NM.
    """
    if path not in base_files or path not in head_files:
        return []
    before = function_bindings(path, base_files, cwd=cwd)
    # A retained call to an already qualified baseline name is the obligation
    # being checked, not an invented head export or an opaque new command.
    after = function_bindings(path, head_files, cwd=cwd,
                              expected_calls={x['name'] for x in before['bindings']})
    # Unknown source selection must never be promoted into a proven binding.
    if before["unknown"] or after["unknown"]:
        return []
    calls = {x["name"] for x in after["commands"]}
    retained = {x["name"] for x in after["bindings"]}
    return [x for x in before["bindings"] if x["name"] in calls
            and x["name"] not in retained
            and not any(f["name"] == x["name"] for f in analyse(
                path, head_files[path], head_files, cwd=cwd)["functions"])]


def workflow_script_contexts(files):
    """Native Git workflow run-step cwd facts, using the existing parser.

    Conflicting and inferred caller contexts are retained per target script. A
    caller with no target reference poisons every known target's unique-cwd proof;
    a resolved target's uncertainty stays local to that target. Child bash inherits
    a literal caller cwd; dynamic workflows establish no qualified context.
    """
    contexts = {}
    has_unbound_caller = False
    for path, raw in files.items():
        if not path.startswith(".github/workflows/") or not path.endswith((".yml", ".yaml")):
            continue
        # Shape validation is an independent prerequisite; a malformed author
        # workflow cannot invent a native caller cwd for function qualification.
        import workflow_config
        if workflow_config.validate(raw)[0] != "verified":
            continue
        facts = workflow(path, raw, files)
        has_unbound_caller = has_unbound_caller or bool(facts.get("unbound_callers"))
        for ref in facts["references"]:
            if ref["type"] != "calls":
                continue
            context = (ref.get("cwd") if ref["provenance"] == "deterministic"
                       and ref.get("cwd") is not None else None)
            contexts.setdefault(ref["path"], set()).add(context)
    if has_unbound_caller:
        for target_contexts in contexts.values():
            target_contexts.add(None)
    return contexts


def paired_function_regressions(path, base_files, head_files):
    before = workflow_script_contexts(base_files).get(path, set())
    after = workflow_script_contexts(head_files).get(path, set())
    # Only the same unique native caller context proves script cwd in both trees.
    context = next(iter(before)) if len(before) == 1 and before == after else None
    return removed_function_references(path, base_files, head_files, cwd=context)


def changed_function_uncertainty(path, base_files, head_files):
    """A changed potentially bound function is not compatible by absence of proof."""
    if path not in base_files or path not in head_files:
        return []
    before_contexts = workflow_script_contexts(base_files).get(path, set())
    after_contexts = workflow_script_contexts(head_files).get(path, set())
    cwd = next(iter(before_contexts)) if len(before_contexts) == 1 and before_contexts == after_contexts else None
    before = function_bindings(path, base_files, cwd=cwd)
    after = function_bindings(path, head_files, cwd=cwd)
    if not before["unknown"] and not after["unknown"]:
        return []
    calls = {c["name"] for c in after["commands"]}
    return [c for c in before["bindings"] if c["name"] in calls
            and base_files.get(c["provider"]) != head_files.get(c["provider"])]
