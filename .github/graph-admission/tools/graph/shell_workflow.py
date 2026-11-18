"""Non-executing, restricted workflow Bash caller extraction.

Logical statements preserve multiline quotes and backslash continuations. This
is a source-reference projection, not an execution engine or a general Bash AST.
Unsupported executable syntax remains an explicit unknown, retaining the
builder's conservative inferred caller set.
"""
import os
import re
import shlex
from pathlib import PurePosixPath

_LITERAL_DOLLAR = "\x00"  # Actual NUL input is rejected before tokenization.
_QUOTED_WORD = "\x01"  # Distinguish quoted assignment names / reserved words.
_NAME = r"[A-Za-z_][A-Za-z0-9_]*"
_ASSIGN = re.compile(r"(" + _NAME + r")=(.*)\Z", re.S)
_VARIABLE = re.compile(r"\$(?:\{(" + _NAME + r")\}|(" + _NAME + r"))")
_PATH = re.compile(r"[A-Za-z0-9_./-]+\Z")
_FLOW = {"if", "elif", "else", "then", "fi", "for", "while", "until", "do", "done", "select", "case", "esac"}
SOURCE_ENVIRONMENT = {"BASH_ENV", "ENV", "PATH", "CDPATH", "IFS", "SHELLOPTS", "BASHOPTS", "GLOBIGNORE"}
_LOADERS = {"source", ".", "bash", "/bin/bash", "/usr/bin/bash", "bats"}


def _statements(text):
    """Return losslessly delimited simple statements; refuse executable nesting."""
    if "\x00" in text or "\x01" in text or "\r" in text or "${{" in text or len(text) > 1024 * 1024:
        raise ValueError("opaque input/interpolated workflow source")
    result, buf = [], []
    quote, line, start, i, word_start = None, 1, 1, 0, True
    def emit(separator):
        nonlocal buf, start
        body = "".join(buf).strip()
        if body:
            lex = shlex.shlex(body, posix=True, punctuation_chars="<>")
            lex.whitespace_split, lex.commenters = True, ""
            result.append((list(lex), separator, start))
        buf, start = [], line
    while i < len(text):
        c = text[i]
        if quote == "'":
            buf.append(_LITERAL_DOLLAR if c == "$" else c)
            if c == "'":
                quote = None
            line += c == "\n"
            i += 1
            continue
        if c == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt == "\n":
                line += 1
            elif nxt == "$":
                buf.append(_LITERAL_DOLLAR)
            elif quote == '"' and nxt == "`":
                # shlex removes outside escapes but retains this double-quote
                # backslash. The character is data, never a substitution.
                buf.append("`")
            else:
                buf.extend((c, nxt))
            i += 2
            word_start = False
            continue
        if c == "`" or text.startswith("$(", i) or text.startswith("<(", i) or text.startswith(">(", i):
            raise ValueError("command/process substitution closure is unresolved")
        if quote == '"':
            buf.append(c)
            if c == '"':
                quote = None
            line += c == "\n"
            i += 1
            continue
        if c == "#" and word_start:
            end = text.find("\n", i)
            i = len(text) if end == -1 else end
            continue
        if c in "'\"":
            quote = c
            buf.extend((_QUOTED_WORD, c))
            word_start = False
            i += 1
            continue
        if text.startswith("${", i):
            end = text.find("}", i + 2)
            if end == -1 or any(v in text[i + 2:end] for v in ("$(", "`", "${")):
                raise ValueError("opaque parameter expansion")
            buf.append(text[i:end + 1])
            i = end + 1
            word_start = False
            continue
        if text.startswith("<<", i) or c in "(){}":
            raise ValueError("heredoc/group/function/brace expansion closure is unresolved")
        # A fd duplication is a redirection, not a background/list separator.
        fd = re.match(r"[<>]&[0-9-]+", text[i:])
        if fd:
            buf.append(fd[0]); i += len(fd[0]); word_start = False
            continue
        if c in ";&|\n":
            sep = c
            if c in "&|" and i + 1 < len(text) and text[i + 1] == c:
                sep += c; i += 1
            emit(sep)
            line += c == "\n"
            start, word_start = line, True
            i += 1
            continue
        if not buf and not c.isspace():
            start = line
        buf.append(c)
        word_start = c.isspace()
        i += 1
    if quote:
        raise ValueError("unclosed multiline/opaque shell quote")
    emit("\n")
    if len(result) > 10000:
        raise ValueError("shell statement bound exceeded")
    return result


def _literal(word, bindings):
    """Resolve only literal, confined path-like bindings; never evaluate output."""
    missing = False
    def replace(m):
        nonlocal missing
        value = bindings.get(m[1] or m[2])
        if value is None:
            missing = True
            return "$UNRESOLVED"
        return value
    value = _VARIABLE.sub(replace, word.replace(_QUOTED_WORD, ""))
    if missing or "$" in value or _LITERAL_DOLLAR in value or not _PATH.fullmatch(value):
        return None
    return value


def _brace_group(text):
    """Expose one bounded, simple outer brace group without implying execution."""
    start = len(text) - len(text.lstrip())
    if start == len(text) or text[start] != "{":
        return None
    end = len(text.rstrip()) - 1
    if (end <= start or text[end] != "}" or start + 1 >= len(text)
            or not text[start + 1].isspace() or not (text[end - 1].isspace() or text[end - 1] == ";")):
        raise ValueError("ambiguous brace-group boundaries")
    if len(text[:end + 1].encode("utf-8")) > 64 * 1024:
        raise ValueError("brace-group source bound exceeded")
    body = text[:start] + " " + text[start + 1:end] + " " + text[end + 1:]
    statements = _statements(body)
    if len(statements) > 256:
        raise ValueError("brace-group statement bound exceeded")
    for words, separator, _ in statements:
        if separator in ("&&", "||", "|", "&"):
            raise ValueError("unsupported compound command inside brace group")
        if any(word in ("<", ">", "<<", ">>", "<<<") for word in words):
            raise ValueError("redirection inside brace group is unresolved")
        if words and (words[0] in _FLOW or words[0] == "!"):
            raise ValueError("control flow inside brace group is unresolved")
    return body


def _command(words, bindings):
    """Strip metadata/prefix assignments, not arbitrary utility arguments."""
    words = list(words)
    while words and words[0] in ("if", "elif", "then", "else", "while", "until", "do", "!"):
        words.pop(0)
    while words and _ASSIGN.fullmatch(words[0]):
        words.pop(0)
    while words and _literal(words[0], bindings) in ("command", "builtin", "exec"):
        wrapper = _literal(words.pop(0), bindings)
        if wrapper == "command" and words and words[0] in ("-v", "-V"):
            return []  # command introspection does not execute its operands.
        if wrapper == "command" and words[:1] == ["-p"]:
            words.pop(0)
        if not words or words[0].startswith("-"):
            return ["$UNRESOLVED_WRAPPER"]
        if wrapper == "exec" and _literal(words[0], bindings) in ("cd", "source", "."):
            return ["$UNRESOLVED_EXEC_BUILTIN"]
    return words


# `python -m <tool>` is treated like the bare external utility `<tool>` only for these package tools,
# whose bare commands the analyser already accepts as external utilities (pip, build, twine). Modules that
# discover or execute repository-selected code by argument (unittest, pytest, http.server, ...) stay held.
_PYTHON_TOOL_MODULES = frozenset({"pip", "build", "twine"})
_PYTHON_ENV = re.compile(r"\bPYTHON[A-Z0-9_]*\b")


def _external_python_tool(words, original, bindings, cwd, paths, env_safe):
    """True only when `python -m <tool>` provably resolves to an installed package, not a repository module.

    `-m` puts the working directory first on sys.path, so a repository `<tool>.py`, `<tool>/` or `<tool>.*`
    at that directory would shadow the installed tool. Any Python search-path/environment control in the
    statement, the run body, or the workflow env keeps the dispatch unknown.
    """
    if not env_safe or cwd is None or len(words) < 3 or words[1] != "-m":
        return False
    module = _literal(words[2], bindings)
    if module not in _PYTHON_TOOL_MODULES:
        return False
    if any(_PYTHON_ENV.search(w) for w in original) or any(str(k).startswith("PYTHON") for k in bindings):
        return False
    prefix = "" if cwd == "." else cwd.rstrip("/") + "/"
    for candidate in paths:
        if candidate.startswith(prefix) and candidate[len(prefix):].split("/", 1)[0].split(".", 1)[0] == module:
            return False
    return True


def analyse(path, raw, paths, *, cwd=None, python_env_safe=False):
    refs, unknown, bindings = [], [], {}
    text = raw.decode("utf-8", errors="replace")
    if text.encode("utf-8") != raw:
        return {"references": [], "unknown": ["non-UTF-8 shell source is not parsed losslessly"]}
    grouped = False
    group_candidate = text.lstrip().startswith("{")
    try:
        group_text = _brace_group(text)
        grouped = group_text is not None
        statements = _statements(group_text if grouped else text)
    except ValueError as ex:
        unknown = [str(ex)]
        if group_candidate:
            unknown.append("brace-group execution scope is unresolved")
        return {"references": [], "unknown": sorted(set(unknown))}
    paths = set(paths)
    control = any(w and (w[0] in _FLOW or w[0] == "!") for w, _, _ in statements)
    conditional = control or any(sep in ("&&", "||", "|", "&") for _, sep, _ in statements)
    chain_cwd, after_load, environment_changed = False, False, False
    for index, (original, separator, line) in enumerate(statements):
        if chain_cwd and index and statements[index - 1][1] != "&&":
            cwd, chain_cwd = None, False
        prefix = f"line {line}: "
        if not original:
            continue
        # Unsupported parameter operators can modify variables (:=, array
        # subscripts). Never retain an earlier literal binding across them.
        if any(not re.fullmatch(_NAME, p) for w in original for p in re.findall(r"\$\{([^}]*)\}", w)):
            bindings.clear()
        assignments = [_ASSIGN.fullmatch(w) for w in original]
        if any(m and m[1] in SOURCE_ENVIRONMENT for m in assignments):
            unknown.append(prefix + "source-affecting shell environment binding")
            bindings.clear()
            cwd = None
        if all(assignments):
            environment_changed = True
            for m in assignments:
                bindings[m[1]] = None if conditional else _literal(m[2], bindings)
            continue
        if original[0] in ("for", "select", "case", "fi", "done", "esac", "in"):
            continue  # loop/pattern operands are data, not command positions
        words = _command(original, bindings)
        if not words:
            continue
        if words[0] in ("[", "[["):
            continue  # substitutions were already refused by tokenization.
        command = _literal(words[0], bindings)
        if command is None or command in ("eval", "alias", "unalias", "trap", "shopt", "function", "enable", "hash", "let"):
            unknown.append(prefix + "dynamic command/alias/eval/function scope")
            continue
        if command in ("export", "declare", "typeset", "local", "readonly", "unset", "read") or (command == "printf" and "-v" in words):
            environment_changed = True
            bindings.clear()
            if any(w.replace(_QUOTED_WORD, "").split("=", 1)[0] in SOURCE_ENVIRONMENT for w in words[1:]):
                unknown.append(prefix + "source-affecting environment builtin mutation")
                cwd = None
        if command in ("sh", "/bin/sh", "dash", "zsh", "ksh", "fish", "csh", "tcsh"):
            unknown.append(prefix + "alternate shell interpreter closure is unresolved")
            continue
        if after_load:
            unknown.append(prefix + "command scope after sourced helper is unresolved")
        if command in ("pushd", "popd"):
            unknown.append(prefix + "directory stack scope is unresolved")
            cwd = None
            continue
        if command == "cd":
            # `cd -- .` names the current directory, so it cannot change the
            # caller cwd. Accept only this exact standalone statement when the
            # starting cwd is already known; do not broaden transition parsing.
            if (original == ["cd", "--", "."] and words == ["cd", "--", "."]
                    and separator == "\n" and cwd is not None and not control):
                continue
            target = _literal(words[1], bindings) if len(words) == 2 else None
            resolved = os.path.normpath(os.path.join(cwd, target)) if cwd is not None and target else None
            if (control or separator != "&&" or resolved is None or target.startswith("/")
                    or ".." in PurePosixPath(resolved).parts
                    or not any(p.startswith(resolved.rstrip("/") + "/") for p in paths)):
                unknown.append(prefix + "directory transition has unresolved execution cwd")
                cwd = None
            else:
                cwd, chain_cwd = resolved, True
            continue
        if command == "timeout":
            node_dispatch = len(words) >= 3 and words[2] in ("node", "nodejs")
            if node_dispatch:
                unknown.append(prefix + "unsupported interpreter script/module/stdin dispatch closure")
            if (node_dispatch and original == words and not control and not conditional
                    and not environment_changed and not after_load
                    and (separator == "\n" or (grouped and separator == ";"))
                    and len(words) == 4 and cwd is not None):
                duration = re.fullmatch(r"([0-9]{1,5})s", words[1])
                if duration and 0 < int(duration[1]) <= 86400:
                    target_word = words[3].replace(_QUOTED_WORD, "")
                    target = _literal(words[3], bindings) if "$" not in target_word else None
                    if target and not target.startswith("/") and target.endswith((".js", ".mjs", ".cjs")):
                        candidate = os.path.normpath(os.path.join(cwd, target))
                        if ".." not in PurePosixPath(candidate).parts and candidate in paths:
                            refs.append({"path": candidate, "type": "calls", "line": line,
                                         "provenance": "deterministic", "cwd": cwd})
            unknown.append(prefix + "wrapper execution scope/options unresolved")
            continue
        if command in ("sudo", "nice", "env", "time", "nohup", "setsid", "chroot", "nsenter", "runuser", "su", "stdbuf", "xargs", "parallel", "watch", "flock", "ionice", "numactl", "unshare", "bwrap"):
            unknown.append(prefix + "wrapper execution scope/options unresolved")
            continue
        if command == "find" and any(w in ("-exec", "-execdir", "-ok", "-okdir") for w in words):
            unknown.append(prefix + "find command dispatch closure is unresolved")
            continue
        if re.fullmatch(r"python(?:[0-9]+(?:\.[0-9]+)*)?|node(?:js)?|ruby|perl", command):
            if len(words) == 2 and _literal(words[1], bindings) in ("--version", "--help"):
                continue  # Informational options do not dispatch a script.
            if (command.startswith("python") and not _PYTHON_ENV.search(text)
                    and _external_python_tool(words, original, bindings, cwd, paths, python_env_safe)):
                continue  # installed package tool, not a repository caller
            unknown.append(prefix + "unsupported interpreter script/module/stdin dispatch closure")
            if command.startswith("python") and original == words and not control and not conditional and not environment_changed and not after_load and not _PYTHON_ENV.search(text) and not any(str(name).startswith("PYTHON") for name in bindings):
                target_index, seen_options, unsupported = 1, set(), False
                while target_index < len(words):
                    raw_arg = words[target_index]
                    option = _literal(raw_arg, bindings)
                    if _VARIABLE.search(raw_arg):
                        unsupported = True
                        break
                    if option is None or not option.startswith("-"):
                        break
                    if option not in ("-I", "-B") or option in seen_options:
                        unsupported = True
                        break
                    seen_options.add(option)
                    target_index += 1
                if not unsupported and target_index < len(words):
                    raw_target = words[target_index]
                    target = _literal(raw_target, bindings)
                    if (not _VARIABLE.search(raw_target) and target is not None and target.endswith(".py")
                            and not target.startswith("/") and target_index + 1 == len(words) and cwd is not None):
                        candidate = os.path.normpath(os.path.join(cwd, target))
                        if ".." not in PurePosixPath(candidate).parts and candidate in paths:
                            refs.append({"path": candidate, "type": "calls", "line": line,
                                         "provenance": "deterministic", "cwd": cwd})
                        elif ".." not in PurePosixPath(candidate).parts:
                            unknown.append(prefix + "missing literal Python script " + target)
            elif command in ("node", "nodejs") and not control and not conditional and not environment_changed and not after_load and (separator == "\n" or (grouped and separator == ";")) and original == words and len(words) == 2 and cwd is not None:
                target_word = words[1].replace(_QUOTED_WORD, "")
                target = _literal(words[1], bindings) if "$" not in target_word else None
                if target and not target.startswith("/") and target.endswith((".js", ".mjs", ".cjs")):
                    candidate = os.path.normpath(os.path.join(cwd, target))
                    if ".." not in PurePosixPath(candidate).parts and candidate in paths:
                        refs.append({"path": candidate, "type": "calls", "line": line,
                                     "provenance": "deterministic", "cwd": cwd})
                    elif ".." not in PurePosixPath(candidate).parts:
                        unknown.append(prefix + "missing literal Node script " + target)
            continue
        loader = command in _LOADERS
        importing = command in ("source", ".")
        loader_bindings = dict(bindings) if importing else bindings
        loader_cwd = cwd
        if importing:
            # Even a dynamic, bare, or malformed source request can change the
            # later command scope. Keep a snapshot only to resolve this load;
            # never use its pre-load cwd/bindings for subsequent statements.
            after_load, cwd = True, None
            bindings.clear()
        target_index = 1
        startup_options = set()
        if loader and command in ("bash", "/bin/bash", "/usr/bin/bash"):
            while target_index < len(words):
                option = _literal(words[target_index], loader_bindings)
                if option is None or not option.startswith("-"):
                    break
                if option not in ("--noprofile", "--norc") or option in startup_options:
                    unknown.append(prefix + "unsupported loader/interpreter options")
                    target_index = len(words)
                    break
                startup_options.add(option)
                target_index += 1
            if startup_options:
                unknown.append(prefix + "Bash startup-option execution scope is unresolved")
        target = words[target_index] if loader and target_index < len(words) else words[0]
        target_value = _literal(target, loader_bindings) if loader else None
        if loader and (target_index >= len(words) or (target_value is not None and target_value.startswith("-"))):
            unknown.append(prefix + "unsupported loader/interpreter options")
            continue
        if startup_options and (control or conditional or environment_changed or after_load):
            unknown.append(prefix + "unsupported loader/interpreter options")
            continue
        target = _literal(target, loader_bindings)
        if target is None:
            unknown.append(prefix + "dynamic load/command target")
            continue
        if importing and "/" not in target:
            unknown.append(prefix + "source PATH search is unresolved; explicit relative path required")
            continue
        if target.startswith("/"):
            unknown.append(prefix + "external absolute execution/source target")
            continue
        if not loader and "/" not in target and target not in paths:
            continue  # literal external utility, not a guessed repository call
        if not loader and "/" not in target:
            unknown.append(prefix + "bare executable PATH search is unresolved")
            continue
        candidate_cwd = loader_cwd if importing else cwd
        candidate = os.path.normpath(os.path.join(candidate_cwd, target)) if candidate_cwd is not None else None
        if candidate is None or ".." in PurePosixPath(candidate).parts:
            unknown.append(prefix + "relative execution cwd is not declared")
        elif candidate not in paths:
            unknown.append(prefix + "missing literal helper " + target)
        else:
            refs.append({"path": candidate, "type": "imports" if importing else "calls",
                         "line": line, "provenance": "deterministic", "cwd": candidate_cwd})
        if importing:
            after_load, cwd = True, None
            bindings.clear()
        if chain_cwd and separator != "&&":
            # A later independent statement may execute after a failed cd.
            # A guarded child's own caller identity remains certain.
            cwd, chain_cwd = None, False
    if grouped:
        unknown.append("brace-group execution scope is unresolved")
    return {"references": refs, "unknown": sorted(set(unknown))}
