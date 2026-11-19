"""The statistics behind the TL-19 timing tests must themselves be right: a detector that cannot
detect, or that cries wolf, would make those tests vacuous or flaky."""

from __future__ import annotations

import random

import pytest

from tests.timing import (
    EFFECT_THRESHOLD,
    flagged,
    interleaved_samples,
    permutation_p,
    relative_difference,
)


def _noisy(median: float, n: int, seed: int) -> list[float]:
    rng = random.Random(seed)
    return [rng.lognormvariate(0, 0.25) * median for _ in range(n)]


def test_relative_difference_is_signed_and_relative_to_the_second_sample() -> None:
    assert relative_difference([2.0, 2.0, 2.0], [1.0, 1.0, 1.0]) == pytest.approx(1.0)
    assert relative_difference([1.0, 1.0, 1.0], [2.0, 2.0, 2.0]) == pytest.approx(-0.5)
    assert relative_difference([3.0], [3.0]) == 0.0


def test_two_samples_from_one_distribution_are_not_significant() -> None:
    a, b = _noisy(2.0, 200, seed=1), _noisy(2.0, 200, seed=2)
    assert permutation_p(a, b) > 0.01


def test_a_real_shift_is_significant() -> None:
    a, b = _noisy(2.5, 200, seed=3), _noisy(2.0, 200, seed=4)  # +25%
    assert permutation_p(a, b) < 0.001


def test_the_detector_flags_a_20_percent_shift_and_ignores_a_5_percent_one() -> None:
    base = _noisy(2.0, 200, seed=5)
    assert flagged(_noisy(2.4, 200, seed=6), base)
    assert not flagged(_noisy(2.1, 200, seed=7), base)
    assert EFFECT_THRESHOLD == 0.15


def test_a_large_difference_that_is_not_significant_is_not_flagged() -> None:
    """Effect size alone is not enough: three samples each cannot establish anything."""
    assert not flagged([1.0, 5.0, 1.2], [3.0, 1.1, 1.4])


def test_the_false_alarm_rate_is_low_for_identical_distributions() -> None:
    alarms = sum(
        flagged(_noisy(2.0, 200, seed=100 + i), _noisy(2.0, 200, seed=500 + i)) for i in range(40)
    )
    assert alarms <= 1  # at p < 0.001 and a 15% floor, almost never


def test_permutation_p_is_deterministic_for_a_fixed_seed() -> None:
    a, b = _noisy(2.0, 50, seed=8), _noisy(2.2, 50, seed=9)
    assert permutation_p(a, b, seed=3) == permutation_p(a, b, seed=3)


async def test_interleaving_mixes_the_classes_in_time() -> None:
    order: list[str] = []

    def make(name: str):  # type: ignore[no-untyped-def]
        async def call() -> None:
            order.append(name)

        return call

    samples = await interleaved_samples({"a": make("a"), "b": make("b")}, per_class=100, seed=1)
    assert [len(samples["a"]), len(samples["b"])] == [100, 100]
    first_half = order[:100]
    assert 30 < first_half.count("a") < 70, "classes must be mixed, not run back to back"
