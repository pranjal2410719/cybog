import pytest
from cybog.ingestion.manifest import TargetManifestLoader

def test_manifest_loader(tmp_path):
    targets_file = tmp_path / "targets.txt"
    targets_file.write_text("""
    # This is a comment
    example.com
    api.example.com
    
    # duplicate
    example.com
    sub.domain.org
    invalid_domain_!@#
    """)
    loader = TargetManifestLoader(str(targets_file))
    targets = loader.load(batch_name="test_batch")

    domains = [t.domain for t in targets]
    assert "example.com" in domains
    assert "api.example.com" in domains
    assert "sub.domain.org" in domains
    assert "invalid_domain_!@#" not in domains
    assert domains.count("example.com") == 1  # Deduplicated
