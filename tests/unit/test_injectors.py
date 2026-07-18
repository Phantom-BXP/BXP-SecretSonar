import pytest
from unittest.mock import AsyncMock, patch
from bxp_secretsonar.core.models import Artifact, ArtifactType
from bxp_secretsonar.injectors.param_injector import ParamInjector

@pytest.mark.asyncio
async def test_param_injector_generates_artifacts():
    artifact = Artifact(source_url="http://example.com/test?a=1", content="", artifact_type=ArtifactType.HTTP_RESPONSE)
    injector = ParamInjector(ssl_verify=False, max_concurrency=1)
    # Mock de la méthode _fetch pour retourner un artefact avec du contenu injecté
    with patch.object(injector, '_fetch', new_callable=AsyncMock) as mock_fetch:
        mock_fetch.return_value = {
            "url": "http://example.com/injected",
            "content": "injected content",
            "method": "GET",
            "headers": {}
        }
        results = await injector.inject(artifact)
        assert len(results) > 0
        for r in results:
            assert "injected content" in r.content
            assert r.metadata.get("injected") is True
