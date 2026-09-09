"""
flask_aegis.rules.deserialization
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

AEGIS-DESERIAL-001: insecure deserialization detection.

Flags the magic bytes / structural markers of common serialization
formats known to be exploitable via crafted payloads when deserialized
with an unsafe loader: Python pickle opcodes, Java serialized-object
headers, and PHP's serialized-object notation. Also checks the common
"submitted as base64" variant, since that's how these payloads usually
arrive in a text/JSON field.

This is defense-in-depth for a specific, severe mistake: calling
`pickle.loads()` (or `jsonpickle`, PHP `unserialize()`, Java's
`ObjectInputStream`) on data that ultimately originated from a request.
The actually-correct defense is never doing that -- use a data-only
format (JSON) for anything crossing a trust boundary, and if you
genuinely need to deserialize a richer format from a partially-trusted
source, use a restricted/allowlist deserializer designed for that
purpose.
"""
from __future__ import annotations

import base64
import re
from typing import Optional

from ..decisions import Decision, Finding
from .base import Rule, RuleMeta

# Pickle protocol markers: PROTO opcode (0x80) followed by a protocol
# version byte, or the classic ASCII-protocol GLOBAL opcode pattern
# ("cmodule\nname\n" / "c__main__\n...") used by protocol 0 payloads,
# which is also the most common hand-crafted RCE gadget shape.
_PICKLE_BINARY_PROTO = re.compile(rb"\x80[\x00-\x05]")
_PICKLE_GLOBAL_OPCODE = re.compile(rb"^c[\w.]+\n[\w.]+\n", re.MULTILINE)
_PICKLE_REDUCE_GADGET = re.compile(rb"(os\.system|subprocess\.|__reduce__|posix\.system)")

# Java serialized object stream header: 0xACED 0x0005.
_JAVA_SERIAL_MAGIC = re.compile(rb"\xac\xed\x00\x05")
# The same header, base64-encoded, starts with this fixed prefix.
_JAVA_SERIAL_B64_PREFIX = "rO0AB"

# PHP's serialize() notation for an object: O:<namelen>:"<name>":<n>:{...}
_PHP_SERIALIZED_OBJECT = re.compile(rb'O:\d+:"[^"]+":\d+:\{')

_BASE64_LIKE = re.compile(r"^[A-Za-z0-9+/_-]{16,}={0,2}$")


def _looks_base64(value: str) -> Optional[bytes]:
    """Return decoded bytes if `value` looks like standard/urlsafe base64
    and decodes cleanly, else None. Guards length so we don't spend time
    base64-decoding every short token in every request."""
    stripped = value.strip()
    if len(stripped) < 16 or not _BASE64_LIKE.match(stripped):
        return None
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return decoder(stripped + "=" * (-len(stripped) % 4))
        except Exception:  # noqa: BLE001 -- not valid base64, try the next
            continue
    return None


class DeserializationRule(Rule):
    meta = RuleMeta(
        rule_id="AEGIS-DESERIAL-001",
        category="deserialization",
        severity="critical",
        description=(
            "Detects markers of unsafe-to-deserialize payloads: Python "
            "pickle protocol headers and GLOBAL-opcode gadgets "
            "(including common os.system/subprocess RCE gadget shapes), "
            "Java serialized-object stream headers, and PHP's "
            "serialize() object notation -- checked both raw and "
            "base64-decoded, since that's the common transport form for "
            "a field submitted as text/JSON."
        ),
        mitigation=(
            "Block the request. The durable fix is architectural: never "
            "call pickle.loads()/PHP unserialize()/Java "
            "ObjectInputStream.readObject() on data that originated from "
            "a request, regardless of how it's transported (raw, "
            "base64, a cookie, a hidden form field). Use JSON for any "
            "data crossing a trust boundary; if you need a richer "
            "format, use a restricted/allowlist deserializer built for "
            "untrusted input."
        ),
        false_positive_notes=(
            "Legitimate binary/base64 payloads unrelated to "
            "serialization (uploaded images encoded as base64, "
            "encrypted blobs) can coincidentally match the base64-shape "
            "check, though the subsequent magic-byte/opcode check makes "
            "an accidental match on real serialized-object structure "
            "very unlikely. Exempt known-binary fields with "
            "`aegis.field(route, field_name, deserialization=False)`."
        ),
        limitations=(
            "Detects known, common serialization formats and their "
            "canonical headers -- does not detect every possible gadget "
            "chain within a valid pickle stream, nor formats not covered "
            "here (e.g. .NET BinaryFormatter, Ruby Marshal). Absence of "
            "a finding is not proof a value is safe to deserialize; "
            "the architectural fix above is the actual defense. Raw "
            "(non-base64) binary magic-byte detection only meaningfully "
            "applies to genuinely binary transport -- Werkzeug decodes "
            "ordinary form/query fields as UTF-8, so raw bytes that "
            "aren't valid UTF-8 (as Java's and pickle's binary headers "
            "usually aren't) typically can't survive intact into a "
            "text field at all; base64 encoding is the realistic "
            "transport this rule expects for those two formats, and is "
            "checked explicitly."
        ),
    )

    def applies_to(self, ctx) -> bool:
        return bool(ctx.text_values)

    def check(self, ctx) -> Optional[Finding]:
        for field_name, value in ctx.text_values.items():
            if not ctx.field_option(field_name, "deserialization", default=True):
                continue

            detail = self._scan(value)
            if detail:
                return Finding(
                    rule_id=self.meta.rule_id,
                    decision=Decision.BLOCK,
                    message=f"Potential insecure deserialization payload ({detail}) in field '{field_name}'",
                    severity=self.meta.severity,
                    score=30,
                    meta={"field": field_name, "detail": detail},
                )
        return None

    def _scan(self, value: str) -> Optional[str]:
        raw = value.encode("utf-8", errors="ignore")

        detail = self._scan_bytes(raw)
        if detail:
            return detail

        if value.strip().startswith(_JAVA_SERIAL_B64_PREFIX):
            return "base64-encoded Java serialized object header"

        decoded = _looks_base64(value)
        if decoded is not None:
            detail = self._scan_bytes(decoded)
            if detail:
                return f"base64-encoded {detail}"

        return None

    @staticmethod
    def _scan_bytes(data: bytes) -> Optional[str]:
        if _JAVA_SERIAL_MAGIC.search(data):
            return "Java serialized object stream header"
        if _PHP_SERIALIZED_OBJECT.search(data):
            return "PHP serialized object notation"
        if _PICKLE_GLOBAL_OPCODE.search(data) or _PICKLE_REDUCE_GADGET.search(data):
            return "Python pickle GLOBAL-opcode gadget"
        if _PICKLE_BINARY_PROTO.match(data):
            return "Python pickle protocol header"
        return None
