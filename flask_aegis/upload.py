"""
flask_aegis.upload
~~~~~~~~~~~~~~~~~~~~

File-upload-specific defenses: extension allowlisting, double-extension
detection, dangerous-filename rejection, and safe archive extraction
(Zip Slip protection). These are validation/utility functions your view
calls explicitly around a ``werkzeug.datastructures.FileStorage`` — upload
handling varies too much across applications (streaming vs. buffered,
local disk vs. object storage) to hook transparently into the request
pipeline the way header/body rules do.

Example
-------
>>> from flask_aegis.upload import UploadPolicy, validate_upload
>>> policy = UploadPolicy(allowed_extensions={"png", "jpg", "jpeg", "pdf"})
>>> validate_upload(uploaded_file, policy)  # raises UploadRejected on failure
"""
from __future__ import annotations

import os
import re
import zipfile
from dataclasses import dataclass, field
from typing import Optional

from .exceptions import AegisError
from .rules.traversal import safe_join_root

_DANGEROUS_NAME_PATTERN = re.compile(r"[<>:\"|?*\x00-\x1f]")
_RESERVED_WINDOWS_NAMES = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


class UploadRejected(AegisError):
    """Raised by :func:`validate_upload` when a file fails policy."""


@dataclass
class UploadPolicy:
    allowed_extensions: set = field(default_factory=lambda: {"png", "jpg", "jpeg", "gif", "pdf"})
    max_size_bytes: int = 10 * 1024 * 1024
    block_double_extensions: bool = True
    """Reject filenames like 'invoice.pdf.exe' or 'photo.jpg.php' — a
    common upload-filter bypass technique."""
    allowed_mimetypes: Optional[set] = None
    """If set, the FileStorage's reported Content-Type must be in this
    set. Note this header is client-supplied and not a substitute for
    extension/content checks -- treat it as one more signal, not proof."""


def _extension_of(filename: str) -> str:
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


def _all_extensions(filename: str) -> list:
    """Return every dot-separated suffix, e.g. 'x.tar.gz' -> ['tar', 'gz']."""
    parts = filename.split(".")
    return [p.lower() for p in parts[1:]] if len(parts) > 1 else []


def validate_upload(file_storage, policy: UploadPolicy) -> None:
    """Validate an uploaded file against ``policy``. Raises
    :class:`UploadRejected` on the first failing check. Does not read the
    file contents (for that, pair this with an actual content/magic-byte
    check appropriate to your allowed types -- extension allowlisting
    alone cannot prove a file's real type)."""
    filename = getattr(file_storage, "filename", None)
    if not filename:
        raise UploadRejected("Uploaded file has no filename")

    base = os.path.basename(filename)
    if base != filename:
        raise UploadRejected(f"Filename contains path separators: {filename!r}")

    if _DANGEROUS_NAME_PATTERN.search(filename):
        raise UploadRejected(f"Filename contains disallowed characters: {filename!r}")

    stem = filename.rsplit(".", 1)[0].lower()
    if stem in _RESERVED_WINDOWS_NAMES:
        raise UploadRejected(f"Filename uses a reserved system name: {filename!r}")

    ext = _extension_of(filename)
    if ext not in policy.allowed_extensions:
        raise UploadRejected(
            f"Extension '.{ext}' is not allowed "
            f"(allowed: {', '.join(sorted(policy.allowed_extensions))})"
        )

    if policy.block_double_extensions:
        extensions = _all_extensions(filename)
        disallowed_trailing = [e for e in extensions[:-1] if e not in policy.allowed_extensions]
        if disallowed_trailing:
            raise UploadRejected(
                f"Filename has a suspicious double extension: {filename!r}"
            )

    if policy.allowed_mimetypes is not None:
        content_type = getattr(file_storage, "content_type", None)
        if content_type not in policy.allowed_mimetypes:
            raise UploadRejected(
                f"Content-Type {content_type!r} is not allowed "
                f"(allowed: {', '.join(sorted(policy.allowed_mimetypes))})"
            )

    content_length = getattr(file_storage, "content_length", None)
    if content_length and content_length > policy.max_size_bytes:
        raise UploadRejected(
            f"File exceeds max size of {policy.max_size_bytes} bytes"
        )


def safe_extract_zip(
    zip_path: str,
    dest_dir: str,
    max_ratio: float = 100.0,
    max_uncompressed_size: int = 1 * 1024 * 1024 * 1024,
    max_total_members: int = 10_000,
) -> list:
    """Extract a zip archive to ``dest_dir``, rejecting any member whose
    normalized path would land outside ``dest_dir`` (Zip Slip), and
    guarding against decompression bombs before writing any bytes:

    * ``max_ratio`` -- reject a member whose uncompressed size exceeds
      ``max_ratio`` times its compressed size (the classic "42.zip"
      nested-bomb signature is a ratio in the tens of thousands; 100x
      already comfortably exceeds normal compressible content like text
      or uncompressed bitmaps).
    * ``max_uncompressed_size`` -- reject a member (or the archive's
      total) whose uncompressed size alone exceeds this, regardless of
      ratio -- catches a bomb built from already-compressed-looking
      data that a ratio check alone would miss.
    * ``max_total_members`` -- reject an archive with an implausible
      number of entries (a "file count" bomb -- millions of
      near-empty files that individually pass a ratio/size check but
      exhaust disk inodes or extraction time in aggregate).

    All three checks run against the archive's *central directory*
    metadata before any member is written to disk, so a malicious
    archive is rejected without ever extracting a single byte of it.

    Raises :class:`UploadRejected` on the first unsafe member/archive
    and leaves already-extracted members in place -- callers extracting
    untrusted archives should extract to a fresh temporary directory
    they can discard wholesale on failure.
    """
    os.makedirs(dest_dir, exist_ok=True)
    extracted = []
    with zipfile.ZipFile(zip_path) as zf:
        members = zf.infolist()

        if len(members) > max_total_members:
            raise UploadRejected(
                f"Archive has {len(members)} entries, exceeding the limit "
                f"of {max_total_members} (possible file-count decompression bomb)"
            )

        total_uncompressed = sum(m.file_size for m in members)
        if total_uncompressed > max_uncompressed_size:
            raise UploadRejected(
                f"Archive's total uncompressed size ({total_uncompressed} bytes) "
                f"exceeds the limit of {max_uncompressed_size} bytes"
            )

        for member in members:
            if member.compress_size > 0:
                ratio = member.file_size / member.compress_size
                if ratio > max_ratio:
                    raise UploadRejected(
                        f"Zip member {member.filename!r} has a compression "
                        f"ratio of {ratio:.0f}x, exceeding the limit of "
                        f"{max_ratio}x (possible decompression bomb)"
                    )
            elif member.file_size > 0:
                # Zero compressed size but non-zero uncompressed size is
                # itself a red flag -- a legitimate stored (uncompressed)
                # entry still reports a non-zero compress_size equal to
                # file_size, so this shape shouldn't occur naturally.
                raise UploadRejected(
                    f"Zip member {member.filename!r} reports 0 compressed "
                    f"bytes but {member.file_size} uncompressed bytes"
                )

        for member in members:
            target = safe_join_root(dest_dir, member.filename)
            if target is None:
                raise UploadRejected(
                    f"Zip member escapes destination directory (Zip Slip): "
                    f"{member.filename!r}"
                )
            if member.is_dir():
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zf.open(member) as src, open(target, "wb") as dst:
                dst.write(src.read())
            extracted.append(target)
    return extracted
