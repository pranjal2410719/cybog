"""
Tests for target-manifest normalization.

A manifest line may legitimately be a full URL — that is what users paste from
a browser or a scan result. Before normalization those lines failed the domain
regex and were dropped with only a log warning, so a run could silently scan
fewer hosts than the operator listed.
"""
import pytest

from cybog.ingestion.manifest import (
    ManifestLoadError,
    TargetManifestLoader,
    normalize_domain,
)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("example.com", "example.com"),
        ("EXAMPLE.COM", "example.com"),
        ("  example.com  ", "example.com"),
        ("https://example.com", "example.com"),
        ("http://example.com", "example.com"),
        ("https://example.com/", "example.com"),
        ("https://example.com/path", "example.com"),
        ("https://example.com/path?q=1#frag", "example.com"),
        ("https://example.com:8443/admin", "example.com"),
        ("example.com:8080", "example.com"),
        ("https://user:pass@example.com/x", "example.com"),
        ("example.com.", "example.com"),
        ("https://sub.example.com/a/b", "sub.example.com"),
        ("HTTPS://Example.COM", "example.com"),
        ("", ""),
        # A comment line normalizes to nothing. Comments are filtered before
        # normalization in load_raw_domains(); returning "" here is belt-and-
        # braces so a stray "#" can never become a target.
        ("#comment", ""),
    ],
)
def test_normalize_domain(raw, expected):
    assert normalize_domain(raw) == expected


def test_urls_are_not_silently_dropped(tmp_path):
    """The regression this guards: a URL line used to vanish from the run."""
    manifest = tmp_path / "targets.txt"
    manifest.write_text(
        "example.com\n"
        "https://example.org/path\n"
        "HTTP://Example.NET:8080/admin?x=1\n"
        "\n"
        "# a comment\n",
        encoding="utf-8",
    )
    domains = TargetManifestLoader(manifest).load_raw_domains()
    assert domains == ["example.com", "example.org", "example.net"]


def test_normalized_forms_deduplicate(tmp_path):
    """example.com and https://example.com/ are one host, not two."""
    manifest = tmp_path / "targets.txt"
    manifest.write_text(
        "example.com\nhttps://example.com/\nEXAMPLE.COM\n",
        encoding="utf-8",
    )
    domains = TargetManifestLoader(manifest).load_raw_domains()
    assert domains == ["example.com"]


def test_preserve_existing_behaviour_for_plain_domains(tmp_path):
    """Plain-domain manifests must be unaffected by the change."""
    manifest = tmp_path / "targets.txt"
    manifest.write_text("a.example.com\nexample.com\n#skip\n\n", encoding="utf-8")
    loader = TargetManifestLoader(manifest)
    assert loader.load_raw_domains() == ["a.example.com", "example.com"]
    valid, invalid = loader.validate_domains(loader.load_raw_domains())
    assert valid == ["a.example.com", "example.com"]
    assert invalid == []


def test_still_rejects_garbage(tmp_path):
    """Normalization must not turn junk into a scannable target."""
    manifest = tmp_path / "targets.txt"
    manifest.write_text("not a domain\n..\n", encoding="utf-8")
    loader = TargetManifestLoader(manifest)
    valid, invalid = loader.validate_domains(loader.load_raw_domains())
    assert valid == []
    assert len(invalid) == 2


def test_missing_file_raises(tmp_path):
    with pytest.raises(ManifestLoadError):
        TargetManifestLoader(tmp_path / "nope.txt").load_raw_domains()
