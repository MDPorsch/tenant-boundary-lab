"""The TL-17 state diff is itself a detector, so it is tested: it must see every kind of change,
name where it happened, and refuse to compare snapshots that do not cover the same tables."""

from __future__ import annotations

import pytest

from tests.harness import BUSINESS_TABLES, Snapshot
from tests.support_m4 import Change, diff_business


def _snap(**tables: tuple[tuple[object, ...], ...]) -> Snapshot:
    business: dict[str, tuple[tuple[object, ...], ...]] = {t: () for t in BUSINESS_TABLES}
    business.update(tables)
    return Snapshot(business, ())


def test_identical_snapshots_have_an_empty_diff() -> None:
    one = _snap(projects=(("p1", "A", "title"),))
    assert diff_business(one, one) == []


def test_an_added_row_is_reported_with_its_table_and_key() -> None:
    before = _snap(projects=(("p1", "t"),))
    after = _snap(projects=(("p1", "t"), ("p2", "t")))
    assert diff_business(before, after) == [Change("projects", "p2", "added")]


def test_a_removed_row_is_reported() -> None:
    before = _snap(invoices=(("i1", 5), ("i2", 6)))
    after = _snap(invoices=(("i1", 5),))
    assert diff_business(before, after) == [Change("invoices", "i2", "removed")]


def test_a_modified_row_is_reported_even_when_only_one_column_changes() -> None:
    before = _snap(projects=(("p1", "A", "old", 1),))
    after = _snap(projects=(("p1", "A", "old", 2),))
    assert diff_business(before, after) == [Change("projects", "p1", "modified")]


def test_changes_in_several_tables_come_back_sorted_and_complete() -> None:
    before = _snap(projects=(("p1", "x"),), memberships=(("m1", "viewer"),))
    after = _snap(projects=(("p1", "y"),), memberships=(("m1", "viewer"), ("m2", "owner")))
    assert diff_business(before, after) == [
        Change("memberships", "m2", "added"),
        Change("projects", "p1", "modified"),
    ]


def test_the_audit_log_is_not_part_of_the_business_diff() -> None:
    before = Snapshot({t: () for t in BUSINESS_TABLES}, ())
    after = Snapshot({t: () for t in BUSINESS_TABLES}, ({"id": "a1", "decision": "deny"},))
    assert diff_business(before, after) == []


def test_snapshots_over_different_tables_cannot_be_compared() -> None:
    full = _snap()
    partial = Snapshot({"projects": ()}, ())
    with pytest.raises(ValueError, match="different tables"):
        diff_business(full, partial)
    with pytest.raises(ValueError, match="different tables"):
        diff_business(partial, full)


def test_a_change_of_a_value_type_is_a_modification_not_silence() -> None:
    before = _snap(projects=((1, "x"),))
    after = _snap(projects=(("1", "x"),))
    assert diff_business(before, after) == [Change("projects", "1", "modified")]
