import hashlib

from bait_edr.file_scanner import FileScanner


def test_file_hash_and_inspection(tmp_path) -> None:
    target = tmp_path / "sample.txt"
    target.write_bytes(b"safe synthetic content")
    scanner = FileScanner()
    result = scanner.inspect(target)
    assert result["sha256"] == hashlib.sha256(b"safe synthetic content").hexdigest()
    assert result["size"] == len(b"safe synthetic content")
    assert result["yara_matches"] == []
