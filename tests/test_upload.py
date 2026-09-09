import os
import zipfile

import pytest

from flask_aegis.upload import UploadPolicy, UploadRejected, safe_extract_zip, validate_upload


class FakeFile:
    def __init__(self, filename, content_type=None, content_length=None):
        self.filename = filename
        self.content_type = content_type
        self.content_length = content_length


@pytest.fixture
def policy():
    return UploadPolicy(allowed_extensions={"png", "jpg", "pdf"})


def test_blocks_double_extension(policy):
    with pytest.raises(UploadRejected):
        validate_upload(FakeFile("invoice.pdf.exe"), policy)


def test_blocks_path_separators_in_filename(policy):
    with pytest.raises(UploadRejected):
        validate_upload(FakeFile("../../etc/passwd.png"), policy)


def test_blocks_disallowed_extension(policy):
    with pytest.raises(UploadRejected):
        validate_upload(FakeFile("report.exe"), policy)


def test_blocks_reserved_windows_name(policy):
    with pytest.raises(UploadRejected):
        validate_upload(FakeFile("con.png"), policy)


def test_allows_clean_upload(policy):
    validate_upload(FakeFile("photo.png", content_length=1024), policy)  # no raise


def test_enforces_max_size():
    policy = UploadPolicy(allowed_extensions={"png"}, max_size_bytes=100)
    with pytest.raises(UploadRejected):
        validate_upload(FakeFile("photo.png", content_length=200), policy)


def test_zip_slip_blocked(tmp_path):
    evil_zip = tmp_path / "evil.zip"
    with zipfile.ZipFile(evil_zip, "w") as z:
        z.writestr("../../../../tmp/pwned.txt", "pwned")
    with pytest.raises(UploadRejected):
        safe_extract_zip(str(evil_zip), str(tmp_path / "dest"))


def test_clean_zip_extracts(tmp_path):
    good_zip = tmp_path / "good.zip"
    with zipfile.ZipFile(good_zip, "w") as z:
        z.writestr("readme.txt", "hello")
    dest = tmp_path / "dest"
    extracted = safe_extract_zip(str(good_zip), str(dest))
    assert len(extracted) == 1
    assert os.path.exists(extracted[0])
