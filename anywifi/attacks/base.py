"""Abstract base class for attack vectors."""

from __future__ import annotations

from abc import ABC, abstractmethod

from anywifi.model import AttackContext, AttackResult, Network


class Attack(ABC):
    """Common interface for all attack vectors."""

    vector: str = "base"
    label: str = "base"

    @abstractmethod
    def applicable(self, net: Network) -> bool:
        """Is this vector applicable to the given network?"""

    @abstractmethod
    def run(self, net: Network, ctx: AttackContext) -> AttackResult:
        """Run the attack and return the result."""

    # helpers
    def _result(self, net: Network, **kwargs) -> AttackResult:
        return AttackResult(network=net, vector=self.vector, **kwargs)
