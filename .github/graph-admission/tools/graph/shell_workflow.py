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


def analyse(path, raw, paths, *, cwd=None):
    refs, unknown, bindings = [], [], {}
    text = raw.decode("utf-8", errors="replace")
    if text.encode("utf-8") != raw:
        return {"references": [], "unknown": ["non-UTF-8 shell source is not parsed losslessly"]}
    try:
        statements = _statements(text)
    except ValueError as ex:
        return {"references": [], "unknown": [str(ex)]}
    paths = set(paths)
    control = any(w and (w[0] in _FLOW or w[0] == "!") for w, _, _ in statements)
    conditional = control or any(sep in ("&&", "||", "|", "&") for _, sep, _ in statements)
    chain_cwd, after_load = False, False
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
        if command in ("sudo", "timeout", "nice", "env", "time", "nohup", "setsid", "chroot", "nsenter", "runuser", "su", "stdbuf", "xargs", "parallel", "watch", "flock", "ionice", "numactl", "unshare", "bwrap"):
            unknown.append(prefix + "wrapper execution scope/options unresolved")
            continue
        if command == "find" and any(w in ("-exec", "-execdir", "-ok", "-okdir") for w in words):
            unknown.append(prefix + "find command dispatch closure is unresolved")
            continue
        if re.fullmatch(r"python(?:[0-9]+(?:\.[0-9]+)*)?|node(?:js)?|ruby|perl", command):
            if len(words) == 2 and _literal(words[1], bindings) in ("--version", "--help"):
                continue  # Informational options do not dispatch a script.
            unknown.append(prefix + "unsupported interpreter script/module/stdin dispatch closure")
            continue
        loader = command in _LOADERS
        importing = command in ("source", ".")
        target = words[1] if loader and len(words) > 1 else words[0]
        if loader and (len(words) < 2 or target.startswith("-")):
            unknown.append(prefix + "unsupported loader/interpreter options")
            continue
        target = _literal(target, bindings)
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
        candidate = os.path.normpath(os.path.join(cwd, target)) if cwd is not None else None
        if candidate is None or ".." in PurePosixPath(candidate).parts:
            unknown.append(prefix + "relative execution cwd is not declared")
        elif candidate not in paths:
            unknown.append(prefix + "missing literal helper " + target)
        else:
            refs.append({"path": candidate, "type": "imports" if importing else "calls",
                         "line": line, "provenance": "deterministic", "cwd": cwd})
        if importing:
            after_load, cwd = True, None
            bindings.clear()
        if chain_cwd and separator != "&&":
            # A later independent statement may execute after a failed cd.
            # A guarded child's own caller identity remains certain.
            cwd, chain_cwd = None, False
    return {"references": refs, "unknown": sorted(set(unknown))}
