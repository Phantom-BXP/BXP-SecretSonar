"""Tests unitaires isolés pour PriorityAsyncQueue - Zéro dépendance externe"""
import pytest
from bxp_secretsonar.core.queue import PriorityAsyncQueue
from bxp_secretsonar.core.models import Candidate, Evidence


def _make_candidate(priority: int, value: str = "test") -> Candidate:
    """Factory isolée pour créer des candidats sans état partagé"""
    ev = Evidence(
        artifact_id=f"art-{value}",
        pattern_name="test_pattern",
        matched_value=f"val-{value}",
    )
    return Candidate(evidence=ev, confidence_score=0.5, priority=priority)


@pytest.mark.asyncio
async def test_priority_ordering_strict():
    """Vérifie que les éléments sont défilement dans l'ordre strict de priorité (1=highest)"""
    q = PriorityAsyncQueue()
    
    # Insertion volontairement désordonnée
    await q.put(_make_candidate(priority=5, value="low"))
    await q.put(_make_candidate(priority=1, value="high"))
    await q.put(_make_candidate(priority=3, value="mid"))
    
    results = []
    for _ in range(3):
        c = await q.get()
        results.append(c.priority)
        q.task_done()
    
    assert results == [1, 3, 5], f"Ordre de priorité incorrect: {results}"


@pytest.mark.asyncio
async def test_fifo_within_same_priority():
    """Vérifie la stabilité FIFO lorsque les priorités sont identiques"""
    q = PriorityAsyncQueue()
    
    await q.put(_make_candidate(priority=5, value="first"))
    await q.put(_make_candidate(priority=5, value="second"))
    await q.put(_make_candidate(priority=5, value="third"))
    
    values = []
    for _ in range(3):
        c = await q.get()
        values.append(c.evidence.matched_value)
        q.task_done()
    
    assert values == ["val-first", "val-second", "val-third"], f"FIFO non respecté: {values}"


@pytest.mark.asyncio
async def test_graceful_shutdown_empties_queue():
    """Vérifie que shutdown vide complètement la queue sans erreur"""
    q = PriorityAsyncQueue()
    for i in range(10):
        await q.put(_make_candidate(priority=5, value=str(i)))
    
    assert q.size == 10
    await q.shutdown()
    assert q.size == 0


@pytest.mark.asyncio
async def test_shutdown_on_empty_queue_is_safe():
    """Vérifie que shutdown sur une queue vide ne bloque ni n'erre"""
    q = PriorityAsyncQueue()
    await q.shutdown()  # Ne doit pas lever d'exception
    assert q.size == 0


@pytest.mark.asyncio
async def test_queue_isolation_between_tests():
    """Garantit qu'aucun état n'est partagé entre les exécutions de tests"""
    q1 = PriorityAsyncQueue()
    await q1.put(_make_candidate(priority=1))
    
    q2 = PriorityAsyncQueue()
    assert q2.size == 0, "La nouvelle queue doit être vide - isolation violée"
