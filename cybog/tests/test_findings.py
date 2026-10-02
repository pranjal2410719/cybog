import asyncio
import pytest
from cybog.models.finding import Finding, Severity
from cybog.findings.deduplicator import FindingDeduplicator

def test_deduplicator():
    async def _run():
        dedup = FindingDeduplicator()

        f1 = Finding(
            finding_type="xss",
            title="Cross Site Scripting",
            severity=Severity.HIGH,
            target_id="t1",
            target_domain="example.com",
            url="https://example.com/search?q=1",
            source_tool="nuclei",
        )

        f2 = Finding(
            finding_type="xss",
            title="Cross Site Scripting",
            severity=Severity.HIGH,
            target_id="t1",
            target_domain="example.com",
            url="https://example.com/search?q=1",
            source_tool="nuclei",
        )

        is_new_1 = await dedup.add(f1)
        assert is_new_1 is True

        is_new_2 = await dedup.add(f2)
        assert is_new_2 is False

        unique = await dedup.get_unique()
        assert len(unique) == 1
        assert unique[0].occurrence_count == 2

    asyncio.run(_run())
