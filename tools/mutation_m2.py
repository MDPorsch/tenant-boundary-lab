"""Mutation check for the M2 implementation (the patched API): does the suite notice a deliberate
security bug in a handler, a write statement, the body parser or the pager?

    uv run python tools/mutation_m2.py            # whole suite, stop at the first failing test

Same machinery and exit codes as tools/mutation_m1.py (which also re-checks the M1 gates; run both).
The unmutated suite must be green first or the tool refuses to run.
"""

from __future__ import annotations

import sys

from mutation_m1 import A, G, main

H = "src/tenantlab/api/handlers.py"
S = "src/tenantlab/lab/patched/service.py"
SC = "src/tenantlab/lab/patched/schemas.py"
PG = "src/tenantlab/lab/patched/paging.py"

MUTANTS: dict[str, list[tuple[str, str, str]]] = {
    # ---- gates 7-11 and the order of checks ------------------------------------------------
    "gate7_skipped_before_validation": [(H, "            isinstance(market, str)\n            and service", "            False\n            and service")],
    "quota_precheck_removed": [(H, "if service.count_projects(db, allowed.tenant_id) >= service.MAX_PROJECTS_PER_TENANT:", "if False:")],
    "quota_is_1001": [(S, "MAX_PROJECTS_PER_TENANT: Final = 1000", "MAX_PROJECTS_PER_TENANT: Final = 1001")],
    "quota_removed_from_the_insert": [(S, "roles), market_permitted, under_quota)", "roles), market_permitted)")],
    "market_removed_from_the_insert": [(S, "roles), market_permitted, under_quota)", "roles), under_quota)")],
    "stale_precheck_removed_patch": [(H, "if stored != body.row_version:  # gate 10", "if False:  # gate 10")],
    "stale_precheck_removed_member": [(H, "if current.version != body.version:  # gate 10", "if False:  # gate 10")],
    "last_owner_precheck_removed": [(H, "if steps_down and not service.other_active_owner_exists(  # gate 11", "if False and not service.other_active_owner_exists(  # gate 11")],
    "max_attempts_is_one": [(H, "MAX_ATTEMPTS: Final = 3", "MAX_ATTEMPTS: Final = 1")],
    "reauthorize_does_not_recheck": [(G, "        granted = _evaluate(db, allowed.spec, caller, allowed.path_ids)", "        granted = _Granted(allowed.tenant_id, allowed.role, allowed.path_ids)")],
    "body_read_before_the_gates": [(A, "        allowed = await run_in_threadpool(run_gates, request, spec, deps)\n        body = await request.body() if spec.has_body else b\"\"", "        body = await request.body() if spec.has_body else b\"\"\n        allowed = await run_in_threadpool(run_gates, request, spec, deps)")],
    # ---- the write statements re-check authority (D-35) -------------------------------------
    "row_version_predicate_removed": [(S, "            Project.row_version == row_version,\n", "")],
    "project_tenant_predicate_removed": [(S, "            Project.tenant_id == tenant_id,\n            Project.row_version == row_version,", "            Project.row_version == row_version,")],
    "role_predicate_removed": [(S, "Membership.role.in_(list(roles)),", 'Membership.role.in_(["owner", "admin", "editor", "viewer"]),')],
    "membership_active_predicate_removed": [(S, 'Membership.status == "active",\n            Membership.role.in_(list(roles)),', 'Membership.status.in_(("active", "revoked")),\n            Membership.role.in_(list(roles)),')],
    "principal_active_predicate_removed": [(S, 'exists().where(Principal.id == actor_id, Principal.status == "active"),', "exists().where(Principal.id == actor_id),")],
    "tenant_active_predicate_removed": [(S, 'exists().where(Tenant.id == tenant_id, Tenant.state == "active"),', "exists().where(Tenant.id == tenant_id),")],
    "membership_tenant_predicate_removed": [(S, "            Membership.tenant_id == tenant_id,\n            Membership.principal_id == target_id,\n            Membership.version == version,", "            Membership.principal_id == target_id,\n            Membership.version == version,")],
    "membership_version_predicate_removed": [(S, "            Membership.version == version,\n", "")],
    "last_owner_removed_from_the_update": [(S, "        true() if stays_active_owner else false(),", "        true(),")],
    "revoked_owner_counts_in_the_update": [(S, '            other.status == "active",\n', "")],
    # ---- visibility, projection, paging -----------------------------------------------------
    "list_ignores_the_market": [(S, "        Project.tenant_id == tenant_id,\n        exists().where(", "        Project.tenant_id == tenant_id,\n        true() | exists().where(")],
    "audit_not_tenant_filtered": [(S, "    query = select(AuditEvent).where(AuditEvent.tenant_id == tenant_id)", "    query = select(AuditEvent)")],
    "audit_oldest_first": [(S, "AuditEvent.id.desc()", "AuditEvent.id.asc()")],
    "page_cannot_tell_there_is_more": [(S, "order_by(Project.id).limit(limit + 1)", "order_by(Project.id).limit(limit)")],
    "permitted_market_ignores_access": [(S, "        .join(TenantMarketAccess, TenantMarketAccess.market_id == Market.id)\n        .where(TenantMarketAccess.tenant_id == tenant_id, Market.code == code)", "        .where(Market.code == code)")],
    "embedded_contacts_uncapped": [(S, ".limit(MAX_EMBEDDED_CONTACTS)", ".limit(100000)")],
    "owner_field_shown_to_everyone": [(H, "    if role in OWNER_FIELD_ROLES:", "    if True:")],
    "next_cursor_always_present": [(H, "return encode_cursor(last) if more and last is not None else None", "return encode_cursor(last) if last is not None else None")],
    "create_answers_200": [(H, "status=201)", "status=200)")],
    # ---- audit ------------------------------------------------------------------------------
    "contact_read_not_audited": [(H, "        record_allow(ctx.deps, db, ctx.allowed)  # a private-contact read is audited (D-10)\n        db.commit()\n", "")],
    "audit_committed_apart_from_the_change": [(H, "                record_allow(ctx.deps, db, allowed)\n                db.commit()\n                record = service.get_project(db, project_id)", "                db.commit()\n                record_allow(ctx.deps, db, allowed)\n                db.commit()\n                record = service.get_project(db, project_id)")],
    "denial_audited_without_the_tenant": [(G, "            tenant_id=allowed.tenant_id,\n            action=allowed.spec.operation,\n            resource_type=allowed.spec.resource_type,\n            resource_id=allowed.path_ids[allowed.spec.target_param],\n            decision=\"deny\",", "            tenant_id=None,\n            action=allowed.spec.operation,\n            resource_type=allowed.spec.resource_type,\n            resource_id=allowed.path_ids[allowed.spec.target_param],\n            decision=\"deny\",")],
    # ---- request parsing (D-30) -------------------------------------------------------------
    "unknown_key_name_echoed": [(SC, 'if item["type"] == "extra_forbidden":', "if False:")],
    "nan_accepted": [(SC, "text, object_pairs_hook=_no_duplicate_keys, parse_constant=_reject_constant", "text, object_pairs_hook=_no_duplicate_keys")],
    "duplicate_keys_accepted": [(SC, '        if key in out:\n            raise ValueError("duplicate key")', '        if False:\n            raise ValueError("duplicate key")')],
    "media_type_not_checked": [(SC, '    if media.lower() != "application/json":', "    if False:")],
    "charset_not_checked": [(SC, 'if name.strip().lower() != "charset" or value.strip().strip(\'"\').lower() != "utf-8":', "if False:")],
    "bidi_controls_allowed": [(SC, "or char in _BIDI_CONTROLS", "or False")],
    "surrogates_allowed": [(SC, 'in ("Cc", "Cs")', 'in ("Cc",)')],
    "control_characters_allowed": [(SC, 'in ("Cc", "Cs")', 'in ("Cs",)')],
    "title_may_be_121": [(SC, "TITLE_MAX: Final = 120", "TITLE_MAX: Final = 121")],
    "version_upper_bound_removed": [(SC, "Version = Annotated[int, Field(ge=1, le=MAX_VERSION)]", "Version = Annotated[int, Field(ge=1)]")],
    "types_not_strict": [(SC, 'ConfigDict(extra="forbid", strict=True, frozen=True)', 'ConfigDict(extra="forbid", frozen=True)')],
    "unknown_keys_ignored": [(SC, 'ConfigDict(extra="forbid", strict=True, frozen=True)', 'ConfigDict(extra="ignore", strict=True, frozen=True)')],
    "empty_patch_allowed": [(SC, "        if self.title is None and self.status is None:", "        if False:")],
    "limit_zero_allowed": [(PG, '_LIMIT: Final = re.compile(r"[1-9][0-9]{0,2}")', '_LIMIT: Final = re.compile(r"[0-9]{1,3}")')],
    "limit_above_100_allowed": [(PG, "int(raw) > MAX_LIMIT", "int(raw) > 999")],
    "noncanonical_cursor_allowed": [(PG, "    if encode_cursor(text) != raw:  # reject non-canonical encodings of the same bytes", "    if False:")],
}  # fmt: skip

if __name__ == "__main__":
    sys.exit(main(MUTANTS))
