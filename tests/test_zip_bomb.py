import zipfile

import pytest

from flask_aegis.upload import UploadRejected, safe_extract_zip


def test_rejects_high_compression_ratio_bomb(tmp_path):
    bomb_path = tmp_path / "bomb.zip"
    with zipfile.ZipFile(bomb_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("bomb.txt", b"A" * (10 * 1024 * 1024))  # highly compressible
    with pytest.raises(UploadRejected, match="compression ratio"):
        safe_extract_zip(str(bomb_path), str(tmp_path / "dest"))


def test_rejects_excessive_total_uncompressed_size(tmp_path):
    zip_path = tmp_path / "big.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_STORED) as z:
        # Stored (uncompressed) so the per-member ratio check doesn't
        # trigger first -- this specifically exercises the total-size cap.
        z.writestr("a.txt", "x" * 1000)
    with pytest.raises(UploadRejected, match="uncompressed size"):
        safe_extract_zip(str(zip_path), str(tmp_path / "dest"), max_uncompressed_size=500)


def test_rejects_excessive_member_count(tmp_path):
    zip_path = tmp_path / "many.zip"
    with zipfile.ZipFile(zip_path, "w") as z:
        for i in range(20):
            z.writestr(f"f{i}.txt", "x")
    with pytest.raises(UploadRejected, match="entries"):
        safe_extract_zip(str(zip_path), str(tmp_path / "dest"), max_total_members=10)


def test_allows_normal_archive_within_limits(tmp_path):
    zip_path = tmp_path / "good.zip"
    with zipfile.ZipFile(zip_path, "w") as z:
        z.writestr("readme.txt", "hello world")
    extracted = safe_extract_zip(str(zip_path), str(tmp_path / "dest"))
    assert len(extracted) == 1


def test_zip_slip_still_rejected_alongside_bomb_guards(tmp_path):
    evil_zip = tmp_path / "evil.zip"
    with zipfile.ZipFile(evil_zip, "w") as z:
        z.writestr("../../../../tmp/pwned.txt", "pwned")
    with pytest.raises(UploadRejected, match="Zip Slip"):
        safe_extract_zip(str(evil_zip), str(tmp_path / "dest"))
