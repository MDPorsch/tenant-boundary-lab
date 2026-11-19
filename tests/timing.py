"""Statistics for the timing tests (TL-19). Standard library only.

Why not a ratio of two medians (the first TL-19 test)? Because on this kind of workload:

* time DRIFTS (warm-up, a growing audit table): the first half of a run was ~29% slower than the
  second half, which is larger than the real signal. Sampling all of class A and then all of class B
  confuses drift with difference. Samples are therefore INTERLEAVED in random order, so drift hits
  every class equally;
* a tolerance of "5x" cannot see a 20% difference. The decision rule here is an effect-size
  threshold AND a permutation test, and it must trigger in two independent rounds before a test
  fails, which keeps the false-alarm rate negligible while a consistent difference still fails.
"""

from __future__ import annotations

import random
import statistics
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any, Final

P_THRESHOLD: Final = 0.001
EFFECT_THRESHOLD: Final = 0.15  # the smallest relative difference this test claims to detect
ROUNDS: Final = 2
SAMPLES_PER_CLASS: Final = 200


def relative_difference(a: Sequence[float], b: Sequence[float]) -> float:
    """(median(a) - median(b)) / median(b)."""
    return (statistics.median(a) - statistics.median(b)) / statistics.median(b)


def permutation_p(a: Sequence[float], b: Sequence[float], reps: int = 4000, seed: int = 7) -> float:
    """Two-sided permutation test on the difference of medians. A small p means the observed
    difference is unlikely if both samples came from one distribution."""
    observed = abs(statistics.median(a) - statistics.median(b))
    pool = [*a, *b]
    k = len(a)
    rng = random.Random(seed)
    hits = 0
    for _ in range(reps):
        rng.shuffle(pool)
        if abs(statistics.median(pool[:k]) - statistics.median(pool[k:])) >= observed:
            hits += 1
    return (hits + 1) / (reps + 1)


async def interleaved_samples(
    requests: Mapping[str, Callable[[], Awaitable[Any]]], per_class: int, seed: int
) -> dict[str, list[float]]:
    """Run every class `per_class` times in one shuffled order; returns milliseconds per call."""
    order = [name for name in requests for _ in range(per_class)]
    random.Random(seed).shuffle(order)
    samples: dict[str, list[float]] = {name: [] for name in requests}
    for name in order:
        started = time.perf_counter_ns()
        await requests[name]()
        samples[name].append((time.perf_counter_ns() - started) / 1e6)
    return samples


def flagged(a: Sequence[float], b: Sequence[float]) -> bool:
    """True if `a` and `b` differ by at least EFFECT_THRESHOLD AND the difference is significant."""
    return abs(relative_difference(a, b)) >= EFFECT_THRESHOLD and permutation_p(a, b) < P_THRESHOLD
