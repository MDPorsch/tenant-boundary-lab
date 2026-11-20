"""Mutation check for the M4 additions: does the suite notice when the fifth flaw's switch, its
ordering, or the TL-17 state diff is weakened?

    uv run python tools/mutation_m4.py       # baseline (whole suite, no Docker) then the mutants

Same machinery and exit codes as tools/mutation_m1.py. The unmutated suite must be green first. A
mutant is run against the tests that can see it (the flaw tests, TL-17 and the diff's own tests);
a SURVIVOR would mean a weakened control that no test notices.
"""

from __future__ import annotations

import sys

from mutation_m1 import main

HD = "src/tenantlab/lab/vulnerable/handlers.py"
FL = "src/tenantlab/lab/vulnerable/flaws.py"
SD = "tests/support_m4.py"

SWITCH = "    write_first = Flaw.WRITE_BEFORE_AUTHORIZATION in ctx.flaws and target is not None\n"
LATE = "    if not write_first:\n        _apply_patch(ctx, project_id, body)\n"

MUTANTS: dict[str, list[tuple[str, str, str]]] = {
    # ---- the fifth flaw's switch --------------------------------------------------------------
    "flaw5_always_on": [(HD, SWITCH, "    write_first = target is not None\n")],
    "flaw5_never_on": [(HD, SWITCH, "    write_first = False\n")],
    "flaw5_writes_a_project_that_does_not_exist": [
        (HD, SWITCH, "    write_first = Flaw.WRITE_BEFORE_AUTHORIZATION in ctx.flaws\n")
    ],
    "flaw5_also_writes_after_authorizing": [
        (HD, LATE, "    if True:\n        _apply_patch(ctx, project_id, body)\n")
    ],
    "flaw5_never_writes_after_authorizing": [
        (HD, LATE, "    if False:\n        _apply_patch(ctx, project_id, body)\n")
    ],
    "flaw5_does_not_authorize_at_all": [
        (
            HD,
            '    role, _ = authorize(ctx, "project.write", target)\n    if not write_first:',
            "    role = Role.OWNER\n    if not write_first:",
        )
    ],
    "patch_never_commits": [
        (
            HD,
            "        raise _problem(ErrorCode.CONFLICT_STALE_REVISION)\n    ctx.db.commit()\n\n\ndef patch_project",
            "        raise _problem(ErrorCode.CONFLICT_STALE_REVISION)\n    ctx.db.rollback()\n\n\ndef patch_project",
        )
    ],
    "flaw5_is_not_in_the_enum": [
        (FL, '    WRITE_BEFORE_AUTHORIZATION = "write_before_authorization"\n', "")
    ],
    # ---- the state diff (a detector that cannot see is worse than none) -----------------------
    "diff_ignores_removed_rows": [
        (
            SD,
            '        changes.extend(Change(table, key, "removed") for key in old.keys() - new.keys())\n',
            "",
        )
    ],
    "diff_ignores_added_rows": [
        (
            SD,
            '        changes.extend(Change(table, key, "added") for key in new.keys() - old.keys())\n',
            "",
        )
    ],
    "diff_ignores_modified_rows": [
        (SD, "            if old[key] != new[key]\n", "            if False\n")
    ],
    "diff_accepts_different_table_sets": [
        (SD, "    if set(before.business) != set(after.business):", "    if False:")
    ],
    "diff_looks_at_the_first_table_only": [
        (
            SD,
            "    for table in sorted(before.business):",
            "    for table in sorted(before.business)[:1]:",
        )
    ],
    "diff_is_not_sorted": [(SD, "    return sorted(changes)", "    return changes")],
    "diff_key_is_not_text": [
        (
            SD,
            "    old = {str(row[0]): row for row in before.business[table]}",
            "    old = {row[0]: row for row in before.business[table]}",
        )
    ],
}


def paths_for(_name: str) -> list[str]:
    return [
        "tests/negative/test_m4_forbidden_mutation.py",
        "tests/negative/test_m3_flaws.py",
        "tests/negative/test_m3_vulnerable_units.py",
        "tests/unit/test_state_diff_helpers.py",
    ]


if __name__ == "__main__":
    sys.exit(main(MUTANTS, paths_for))
