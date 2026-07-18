from abc import ABC, abstractmethod
from typing import List
from bxp_secretsonar.core.models import Artifact

class BaseInjector(ABC):
    """Interface pour les modules d'injection active."""
    name: str = "base"

    @abstractmethod
    async def inject(self, artifact: Artifact) -> List[Artifact]:
        """
        À partir d'un artefact collecté, génère une liste d'artefacts supplémentaires
        obtenus en envoyant des requêtes modifiées à la cible.
        """
        ...
