"""Helpers for the M4 tests (TL-17): a state diff over the harness snapshot.

Independence rule (as in tests/harness.py): the diff reads the raw-SQL snapshot the harness takes
and judges rows, never application code. The business tables are compared; the AUDIT table is not,
on purpose: a denial legitimately APPENDS one audit row (docs/api-contract.md s6), so an audit diff
would flag every correct denial. What must never change on a refusal is business data.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

from tests.harness import Snapshot

ChangeKind = Literal["added", "removed", "modified"]
KINDS: Final[tuple[ChangeKind, ...]] = ("added", "removed", "modified")


@dataclass(frozen=True, order=True)
class Change:
    """One difference between two snapshots. `key` is the row's first column (its primary key);
    values are deliberately not carried (a diff names WHERE state changed, not what it held)."""

    table: str
    key: str
    kind: ChangeKind


def diff_business(before: Snapshot, after: Snapshot) -> list[Change]:
    """Every row added, removed or modified in any business table, in a deterministic order.

    Two snapshots over different table sets cannot be compared: that is an error, never an
    empty diff (an empty diff must mean "nothing changed", not "nothing was compared")."""
    if set(before.business) != set(after.business):
        raise ValueError("snapshots cover different tables; they cannot be compared")
    changes: list[Change] = []
    for table in sorted(before.business):
        old = {str(row[0]): row for row in before.business[table]}
        new = {str(row[0]): row for row in after.business[table]}
        changes.extend(Change(table, key, "removed") for key in old.keys() - new.keys())
        changes.extend(Change(table, key, "added") for key in new.keys() - old.keys())
        changes.extend(
            Change(table, key, "modified")
            for key in old.keys() & new.keys()
            if old[key] != new[key]
        )
    return sorted(changes)
