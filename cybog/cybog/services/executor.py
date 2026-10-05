from typing import Protocol, List
from cybog.models.target import Target

class AssessmentExecutor(Protocol):
    async def run(self, targets: List[Target]) -> None:
        ...
