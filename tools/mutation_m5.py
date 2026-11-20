"""Mutation check for milestone M5: do the PostgreSQL concurrency tests, the exhaustive sweep and the
Hypothesis properties notice when a lock, an ordering or a rule is weakened?

    uv run python tools/mutation_m5.py       # baseline (whole suite, needs Docker) then the mutants

Same machinery and exit codes as tools/mutation_m1.py. The unmutated suite must be green first.

* LOCK mutants change src/tenantlab/lab/patched/service.py and run against tests/postgres (and the
  unit tests): only a real PostgreSQL server can see them, because SQLite ignores row locks.
* APP mutants weaken a gate or a read query and run against the sweep and the properties of M5 ALONE
  (twice, once for each), to show each of the two catches what it was written to catch.

Equivalent mutants (left out on purpose): dropping the `if tenant is None or ...` guard in
`_lock_authority` changes nothing observable, because the write statement repeats every predicate and
refuses by itself (defence in depth, D-35).
"""

from __future__ import annotations

import sys

from mutation_m1 import main

SV = "src/tenantlab/lab/patched/service.py"
GT = "src/tenantlab/api/gates.py"

TENANT_LOCK = (
    "        select(Tenant.id).where(Tenant.id == tenant_id).with_for_update(read=not exclusive)\n"
)
PRINCIPAL_LOCK = (
    "        select(Principal.id).where(Principal.id == actor_id).with_for_update(read=True)\n"
)
MEMBERSHIP_LOCK = (
    "        .where(Membership.principal_id == actor_id, Membership.tenant_id == tenant_id)\n"
    "        .with_for_update(read=True)\n"
)
MARKET_LOCK = (
    "        .where(TenantMarketAccess.tenant_id == tenant_id, TenantMarketAccess.market_id == market_id)\n"
    "        .with_for_update(read=True)\n"
)

LOCK_MUTANTS: dict[str, list[tuple[str, str, str]]] = {
    "lock_tenant_never_exclusive": [
        (
            SV,
            TENANT_LOCK,
            "        select(Tenant.id).where(Tenant.id == tenant_id).with_for_update(read=True)\n",
        )
    ],
    "lock_tenant_always_exclusive": [
        (
            SV,
            TENANT_LOCK,
            "        select(Tenant.id).where(Tenant.id == tenant_id).with_for_update(read=False)\n",
        )
    ],
    "lock_tenant_not_taken": [
        (SV, TENANT_LOCK, "        select(Tenant.id).where(Tenant.id == tenant_id)\n")
    ],
    "lock_principal_not_taken": [
        (SV, PRINCIPAL_LOCK, "        select(Principal.id).where(Principal.id == actor_id)\n")
    ],
    "lock_membership_not_taken": [
        (
            SV,
            MEMBERSHIP_LOCK,
            "        .where(Membership.principal_id == actor_id, Membership.tenant_id == tenant_id)\n",
        )
    ],
    "lock_market_access_not_taken": [
        (
            SV,
            MARKET_LOCK,
            "        .where(TenantMarketAccess.tenant_id == tenant_id, TenantMarketAccess.market_id == market_id)\n",
        )
    ],
    "create_does_not_lock": [
        (
            SV,
            "    if not _lock_authority(\n        db, tenant_id=tenant_id, actor_id=actor_id, exclusive=True, market_id=market_id\n    ):\n        return None\n",
            "",
        )
    ],
    "create_locks_the_tenant_only_shared": [
        (
            SV,
            "db, tenant_id=tenant_id, actor_id=actor_id, exclusive=True, market_id=market_id",
            "db, tenant_id=tenant_id, actor_id=actor_id, exclusive=False, market_id=market_id",
        )
    ],
    "create_ignores_the_market_lock": [
        (
            SV,
            "db, tenant_id=tenant_id, actor_id=actor_id, exclusive=True, market_id=market_id",
            "db, tenant_id=tenant_id, actor_id=actor_id, exclusive=True, market_id=None",
        )
    ],
    "update_project_does_not_lock": [
        (
            SV,
            "    if project_market is None or not _lock_authority(\n        db, tenant_id=tenant_id, actor_id=actor_id, exclusive=False, market_id=project_market\n    ):\n        return False\n",
            "    if project_market is None:\n        return False\n",
        )
    ],
    "update_project_ignores_the_market_lock": [
        (SV, "exclusive=False, market_id=project_market", "exclusive=False, market_id=None")
    ],
    "update_project_locks_exclusively": [
        (
            SV,
            "exclusive=False, market_id=project_market",
            "exclusive=True, market_id=project_market",
        )
    ],
    "update_membership_does_not_lock": [
        (
            SV,
            "    if not _lock_authority(db, tenant_id=tenant_id, actor_id=actor_id, exclusive=True):\n        return False\n",
            "",
        )
    ],
    "update_membership_locks_only_shared": [
        (
            SV,
            "    if not _lock_authority(db, tenant_id=tenant_id, actor_id=actor_id, exclusive=True):",
            "    if not _lock_authority(db, tenant_id=tenant_id, actor_id=actor_id, exclusive=False):",
        )
    ],
    "create_reads_rowcount_again": [
        (SV, "        .returning(Project.id)  # not rowcount: see _rowcount\n", ""),
        (
            SV,
            "    return new_id if result.scalar_one_or_none() is not None else None",
            "    return new_id if _rowcount(result) == 1 else None",
        ),
    ],
    "unknown_rowcount_is_zero": [
        (
            SV,
            '    if count < 0:\n        raise RuntimeError("the database driver did not report how many rows the statement changed")',
            "    if count < 0:\n        return 0",
        )
    ],
}

APP_MUTANTS: dict[str, list[tuple[str, str, str]]] = {
    "gate3_membership_not_scoped_to_the_tenant": [
        (
            GT,
            '            Membership.tenant_id == tenant_id,\n            Membership.status == "active",\n        )\n    ).one_or_none()',
            '            Membership.status == "active",\n        )\n        .limit(1)\n    ).one_or_none()',
        )
    ],
    "gate3_non_member_is_forbidden_not_hidden": [
        (
            GT,
            "        raise _Deny(ErrorCode.RESOURCE_NOT_FOUND, None, target)\n    role_text, tenant_state = membership",
            "        raise _Deny(ErrorCode.AUTHZ_FORBIDDEN, None, target)\n    role_text, tenant_state = membership",
        )
    ],
    "gate4_a_suspended_tenant_is_served": [
        (
            GT,
            '    if tenant_state != "active":\n        raise _Deny(ErrorCode.TENANT_SUSPENDED, scope.tenant_id, target)',
            "    if False:\n        raise _Deny(ErrorCode.TENANT_SUSPENDED, scope.tenant_id, target)",
        )
    ],
    "gate5_the_market_is_ignored": [
        (
            GT,
            "    if not market_permitted:\n        raise _Deny(ErrorCode.RESOURCE_NOT_FOUND, None, target)",
            "    if False:\n        raise _Deny(ErrorCode.RESOURCE_NOT_FOUND, None, target)",
        )
    ],
    "gate6_the_role_is_ignored": [
        (GT, "    if role is None or not role_holds(spec.operation, role):", "    if role is None:")
    ],
    "list_not_scoped_to_the_tenant": [
        (
            SV,
            "        Project.tenant_id == tenant_id,\n        exists().where(\n            TenantMarketAccess.tenant_id == Project.tenant_id,",
            "        true(),\n        exists().where(\n            TenantMarketAccess.tenant_id == Project.tenant_id,",
        )
    ],
}

POSTGRES = ["tests/postgres", "tests/unit/test_patched_service.py"]
SWEEP = ["tests/negative/test_m5_sweep.py"]
PROPERTIES = ["tests/negative/test_m5_properties.py"]

MUTANTS: dict[str, list[tuple[str, str, str]]] = {
    **LOCK_MUTANTS,
    **{f"{name} [sweep]": edits for name, edits in APP_MUTANTS.items()},
    **{f"{name} [properties]": edits for name, edits in APP_MUTANTS.items()},
}


def paths_for(name: str) -> list[str]:
    if name.endswith("[sweep]"):
        return SWEEP
    if name.endswith("[properties]"):
        return PROPERTIES
    return POSTGRES


if __name__ == "__main__":
    sys.exit(main(MUTANTS, paths_for))
