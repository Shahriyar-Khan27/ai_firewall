"""Semantic shell-command parsing.

Wraps `bashlex` to give the firewall a real AST instead of regex/shlex
tokenization. The output is a flat list of `EffectiveCommand`s — what the
shell would *actually* execute after expanding variables, command/process
substitutions, and decoding common obfuscations (base64, hex/octal escapes).

The intent classifier and risk analyzer then run against the worst-of-the-bunch,
so `echo "cm0gLXJmIC8=" | base64 -d | sh` is classified as `rm -rf /`, not
as a benign `echo`.

Falls back to `shlex.split` when bashlex can't parse the input — we never want
the firewall to raise on a syntactically weird command. Treat that as an
opaque single-verb command so policy still fires.
"""
from __future__ import annotations

import base64
import binascii
import re
import shlex
from dataclasses import dataclass, field
from typing import Iterable

try:
    import bashlex  # type: ignore
    import bashlex.errors  # type: ignore
    _BASHLEX_AVAILABLE = True
except Exception:  # pragma: no cover - bashlex is a hard dep, but be defensive
    _BASHLEX_AVAILABLE = False


@dataclass(frozen=True)
class EffectiveCommand:
    """A single command the shell would execute after expansion."""

    verb: str                                  # e.g. "rm", "sh", "curl"
    args: tuple[str, ...] = ()                 # raw tokens after the verb
    full_text: str = ""                        # reconstructed `verb arg arg…`
    obfuscated: bool = False                   # came from a decoded payload?
    obfuscation_kind: str = ""                 # "base64" / "hex" / "eval" / ""
    source_text: str = ""                      # the original outer command


@dataclass(frozen=True)
class ParseResult:
    commands: tuple[EffectiveCommand, ...]
    parse_ok: bool                             # bashlex succeeded?
    obfuscation_detected: bool                 # any decoded payload found?

    def all_text(self) -> str:
        """Joined text of every effective command — used for regex matching."""
        return "\n".join(c.full_text for c in self.commands)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def parse(cmd: str) -> ParseResult:
    """Parse a shell command into one or more effective commands.

    Always returns at least one EffectiveCommand. Never raises.
    """
    if not cmd or not cmd.strip():
        return ParseResult(commands=(), parse_ok=False, obfuscation_detected=False)

    if not _BASHLEX_AVAILABLE:
        return _fallback(cmd)

    try:
        trees = bashlex.parse(cmd)
    except (bashlex.errors.ParsingError, Exception):  # type: ignore[attr-defined]
        return _fallback(cmd)

    out: list[EffectiveCommand] = []
    obfuscation_detected = False
    # Variable bindings from earlier `VAR=value` standalone statements within
    # the same input. Mutated as we walk; applied to later commands in the same
    # input. (Real shell behaviour treats these as session-scoped.)
    assignments: dict[str, str] = {}

    for tree in trees:
        for ec, was_obfuscated in _walk(tree, source_text=cmd, assignments=assignments):
            out.append(ec)
            if was_obfuscated:
                obfuscation_detected = True

    if not out:
        return _fallback(cmd)

    return ParseResult(
        commands=tuple(out),
        parse_ok=True,
        obfuscation_detected=obfuscation_detected,
    )


# ---------------------------------------------------------------------------
# AST walking
# ---------------------------------------------------------------------------

def _walk(
    node, *, source_text: str, assignments: dict[str, str]
) -> Iterable[tuple[EffectiveCommand, bool]]:
    """Yield (EffectiveCommand, was_decoded_from_obfuscation) for the AST.

    Handles common shapes:
      - command:  rm -rf /
      - pipeline: echo … | base64 -d | sh   (we look at every part + decode)
      - list:     a; b && c
      - compound: for/while/if blocks (recurse into bodies)
      - commandsubstitution / processsubstitution: $(cmd), <(cmd)
      - assignments without commands: VAR=value (treated as setting state for
        subsequent statements in the same list)
    """
    kind = getattr(node, "kind", "")

    if kind == "command":
        # If the command is purely assignments (no verb), record them and emit
        # nothing — they apply to subsequent commands in the same list.
        if _is_assignment_only(node):
            for k, v in _extract_leading_assignments(node).items():
                assignments[k] = v
            return
        yield from _command_to_effective(
            node, source_text=source_text, obfuscated=False, assignments=assignments
        )
        return

    if kind == "pipeline":
        # Each command in the pipeline is its own effective command.
        # Also: detect base64/hex/printf decoders and resolve their inner commands.
        parts = list(getattr(node, "parts", []))
        for p in parts:
            if getattr(p, "kind", "") == "command":
                yield from _command_to_effective(
                    p, source_text=source_text, obfuscated=False, assignments=assignments
                )
        decoded = _resolve_pipeline_decoder(parts, source_text)
        for ec in decoded:
            yield ec, True
        return

    if kind in {"list", "compound"}:
        for child in getattr(node, "parts", []):
            yield from _walk(child, source_text=source_text, assignments=assignments)
        return

    if kind in {"commandsubstitution", "processsubstitution"}:
        inner = getattr(node, "command", None)
        if inner is not None:
            yield from _walk(inner, source_text=source_text, assignments=assignments)
        return

    if kind in {"if", "while", "for", "function", "until", "case", "select"}:
        # Walk every child node recursively — bodies often contain real commands
        for child in getattr(node, "parts", []):
            yield from _walk(child, source_text=source_text, assignments=assignments)
        # Some bashlex nodes carry the body as `body` instead of in parts
        body = getattr(node, "body", None)
        if body is not None:
            yield from _walk(body, source_text=source_text, assignments=assignments)
        return

    if kind == "reservedword":
        return  # `do`, `done`, `then`, `fi`, …

    # Anything else: recurse into children if they exist
    for child in getattr(node, "parts", []) or []:
        yield from _walk(child, source_text=source_text, assignments=assignments)


def _is_assignment_only(node) -> bool:
    """A command is assignment-only if every part is an assignment."""
    parts = getattr(node, "parts", []) or []
    if not parts:
        return False
    return all(getattr(p, "kind", "") == "assignment" for p in parts)


def _extract_leading_assignments(node) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in getattr(node, "parts", []) or []:
        if getattr(p, "kind", "") != "assignment":
            break
        word = getattr(p, "word", "") or ""
        if "=" in word:
            k, _, v = word.partition("=")
            # Strip quotes from a quoted RHS
            v = v.strip().strip("'\"")
            out[k] = v
    return out


def _command_to_effective(
    node,
    *,
    source_text: str,
    obfuscated: bool,
    obfuscation_kind: str = "",
    assignments: dict[str, str] | None = None,
) -> Iterable[tuple[EffectiveCommand, bool]]:
    """Convert a bashlex `command` node into one or more EffectiveCommands.

    A command can have variable assignments before the verb: `RM=rm $RM -rf /`.
    We resolve those assignments inline. The caller may also pass session-level
    `assignments` from earlier statements in the same list.
    """
    parts = list(getattr(node, "parts", []))

    # Inline assignments override session-level ones for this command.
    inline: dict[str, str] = dict(assignments or {})
    while parts and getattr(parts[0], "kind", "") == "assignment":
        word = getattr(parts[0], "word", "") or ""
        if "=" in word:
            k, _, v = word.partition("=")
            v = v.strip().strip("'\"")
            inline[k] = v
        parts = parts[1:]
    assignments = inline

    # Walk substitutions inside args first (so $(…) shows up too)
    sub_commands: list[tuple[EffectiveCommand, bool]] = []
    word_tokens: list[str] = []
    for p in parts:
        p_kind = getattr(p, "kind", "")
        if p_kind == "word":
            word = getattr(p, "word", "") or ""
            # Resolve $VAR if we just saw an assignment for it
            word_tokens.append(_resolve_assignments(word, assignments))
            # Recurse into any embedded substitution
            for sub in getattr(p, "parts", []) or []:
                sub_kind = getattr(sub, "kind", "")
                if sub_kind in {"commandsubstitution", "processsubstitution"}:
                    inner = getattr(sub, "command", None)
                    if inner is not None:
                        for nested in _walk(inner, source_text=source_text, assignments=assignments):
                            sub_commands.append(nested)
        elif p_kind == "redirect":
            # Surface the redirect operator (>, >>, <, etc.) so downstream
            # token-based classifiers still see "write to file" intent.
            op = getattr(p, "type", "") or ""
            if op:
                word_tokens.append(op)
            # Append the redirect target (the file being written/read)
            output = getattr(p, "output", None)
            if output is not None:
                target = getattr(output, "word", "") or ""
                if target:
                    word_tokens.append(target)

    if word_tokens:
        verb = word_tokens[0]
        args = tuple(word_tokens[1:])
        full = " ".join(word_tokens)
        yield EffectiveCommand(
            verb=verb,
            args=args,
            full_text=full,
            obfuscated=obfuscated,
            obfuscation_kind=obfuscation_kind,
            source_text=source_text,
        ), obfuscated

    yield from sub_commands


# ---------------------------------------------------------------------------
# Assignment + obfuscation helpers
# ---------------------------------------------------------------------------

_VAR_REF = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")


def _resolve_assignments(word: str, assignments: dict[str, str]) -> str:
    """Replace $VAR / ${VAR} when VAR was set by a leading assignment."""
    if not assignments:
        return word

    def sub(m: re.Match[str]) -> str:
        name = m.group(1) or m.group(2)
        return assignments.get(name, m.group(0))

    return _VAR_REF.sub(sub, word)


_BASE64_LIKE = re.compile(r"^[A-Za-z0-9+/=]+$")


def _looks_base64(text: str) -> bool:
    if len(text) < 8 or len(text) % 4 != 0:
        return False
    return bool(_BASE64_LIKE.match(text))


def _try_decode_base64(text: str) -> str | None:
    if not _looks_base64(text):
        return None
    try:
        decoded = base64.b64decode(text, validate=True)
        try:
            return decoded.decode("utf-8")
        except UnicodeDecodeError:
            return None
    except (binascii.Error, ValueError):
        return None


def _try_decode_hex(text: str) -> str | None:
    """Decode `\\x41\\x42…` style hex escape sequences embedded in a string."""
    if "\\x" not in text:
        return None
    try:
        decoded = bytes(text, "utf-8").decode("unicode_escape")
        if decoded != text:
            return decoded
    except (UnicodeDecodeError, ValueError):
        pass
    return None


def _resolve_pipeline_decoder(parts, source_text: str) -> list[EffectiveCommand]:
    """If the pipeline ends in `… | sh` or `… | bash`, try to materialise the
    inner command from base64/printf/echo upstream stages.

    Yields the decoded inner command(s) so they get policy-checked.
    """
    if not parts:
        return []

    last = parts[-1]
    if getattr(last, "kind", "") != "command":
        return []
    last_words = _command_words(last)
    if not last_words:
        return []
    if last_words[0] not in {"sh", "bash", "zsh", "ash"}:
        return []

    # Look upstream for an `echo "<base64>" | base64 -d` or `printf "%b" "\\x..."`
    for up in parts[:-1]:
        if getattr(up, "kind", "") != "command":
            continue
        words = _command_words(up)
        if not words:
            continue
        head = words[0]
        if head == "echo":
            for w in words[1:]:
                payload = w.strip("\"'")
                decoded = _try_decode_base64(payload)
                if decoded:
                    return _parse_decoded(decoded, source_text, "base64")
                hex_decoded = _try_decode_hex(payload)
                if hex_decoded:
                    return _parse_decoded(hex_decoded, source_text, "hex")
        elif head == "printf":
            joined = " ".join(words[1:])
            hex_decoded = _try_decode_hex(joined)
            if hex_decoded:
                return _parse_decoded(hex_decoded, source_text, "hex")
        elif head in {"base64", "openssl"}:
            # Already a decoder; the upstream `echo` will have provided the payload above.
            continue
    return []


def _command_words(node) -> list[str]:
    out: list[str] = []
    for p in getattr(node, "parts", []):
        if getattr(p, "kind", "") == "word":
            out.append(getattr(p, "word", "") or "")
    return out


def _parse_decoded(decoded: str, source_text: str, kind: str) -> list[EffectiveCommand]:
    """Re-parse a decoded payload and tag every command as obfuscation-derived."""
    if not decoded.strip():
        return []
    sub_result = parse(decoded)
    return [
        EffectiveCommand(
            verb=ec.verb,
            args=ec.args,
            full_text=ec.full_text,
            obfuscated=True,
            obfuscation_kind=kind,
            source_text=source_text,
        )
        for ec in sub_result.commands
    ]


# ---------------------------------------------------------------------------
# Fallback (bashlex parse failed)
# ---------------------------------------------------------------------------

def _fallback(cmd: str) -> ParseResult:
    """Last-resort split. Treat the whole input as one opaque command."""
    try:
        tokens = shlex.split(cmd, posix=True)
    except ValueError:
        tokens = cmd.split()
    if not tokens:
        return ParseResult(commands=(), parse_ok=False, obfuscation_detected=False)
    ec = EffectiveCommand(
        verb=tokens[0],
        args=tuple(tokens[1:]),
        full_text=" ".join(tokens),
        source_text=cmd,
    )
    return ParseResult(commands=(ec,), parse_ok=False, obfuscation_detected=False)
