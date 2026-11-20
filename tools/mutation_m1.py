"""Mutation check for the M1 implementation: does the test suite notice a deliberate security bug?

    uv run python tools/mutation_m1.py            # whole suite, stop at the first failing test
    uv run python tools/mutation_m1.py tests/unit # or any pytest paths

The repo is copied to a temporary directory and ONE bug is injected into the copy at a time (the
real tree is never modified). A mutant is KILLED when at least one test fails, SURVIVED when every
test still passes, and NOAPPLY when the patch no longer matches the source (the table is stale).
Exit status: 0 when every mutant is killed, 1 when one survived, 2 when one did not apply.

Known limit: killing a mutant shows a test notices THAT bug, not that no other bug exists. One
mutant (`alg_confusion`) is killed only on the verifier's log reason: PyJWT's own refusal to use a
PEM key as an HMAC secret still rejects the forged token in that mutant.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TEST_PATHS = sys.argv[1:] or ["tests"]

G = "src/tenantlab/api/gates.py"
T = "src/tenantlab/auth/tokens.py"
M = "src/tenantlab/api/middleware.py"
H = "src/tenantlab/api/handlers.py"
P = "src/tenantlab/auth/policy.py"
A = "src/tenantlab/api/app.py"

# name -> [(file, old text, new text), ...]; every entry is ONE injected bug.
MUTANTS = {
    # ---- gate 2/3/4/5/6/8 ------------------------------------------------------------------
    "principal_status_unchecked": [(G, 'if caller.status != "active":', "if False:")],
    "revoked_membership_allowed": [
        (G, 'Membership.status == "active",', 'Membership.status.in_(("active", "revoked")),')
    ],
    "tenant_suspension_ignored": [(G, 'if tenant_state != "active":', "if False:")],
    "foreign_tenant_is_403_not_404 (existence oracle)": [
        (
            G,
            "    if scope is None or membership is None:\n        raise _Deny(ErrorCode.RESOURCE_NOT_FOUND, None, target)",
            "    if scope is None or membership is None:\n        raise _Deny(ErrorCode.AUTHZ_FORBIDDEN, None, target)",
        )
    ],
    "audit_poisoning (tenant_id set on 404)": [
        (
            G,
            "    if scope is None or membership is None:\n        raise _Deny(ErrorCode.RESOURCE_NOT_FOUND, None, target)",
            "    if scope is None or membership is None:\n        raise _Deny(ErrorCode.RESOURCE_NOT_FOUND, tenant_id, target)",
        )
    ],
    "capability_unchecked": [
        (G, "if role is None or not role_holds(spec.operation, role):", "if role is None:")
    ],
    "membership_not_filtered_by_tenant (role bleed)": [
        (G, "            Membership.tenant_id == tenant_id,\n", "")
    ],
    "query_params_ignored": [
        (G, "if len(names) != len(set(names)) or not set(names) <= spec.query_params:", "if False:")
    ],
    "market_gate_skipped": [
        (
            G,
            "    if not market_permitted:\n        raise _Deny(ErrorCode.RESOURCE_NOT_FOUND, None, target)",
            "    if False:\n        raise _Deny(ErrorCode.RESOURCE_NOT_FOUND, None, target)",
        )
    ],
    "path_uuid_validation_removed": [(G, "if len(ids) != len(parsed):", "if False:")],
    "invoice_tenant_coherence_removed": [
        (
            G,
            "if invoice is None or project is None or project[0] != invoice.tenant_id:",
            "if invoice is None or project is None:",
        )
    ],
    "nested_invoice_project_not_matched": [
        (
            G,
            '        invoice_query = invoice_query.where(Invoice.project_id == ids["project_id"])',
            "        pass",
        )
    ],
    "suspended_audit_tenant_null": [
        (
            G,
            "raise _Deny(ErrorCode.TENANT_SUSPENDED, scope.tenant_id, target)",
            "raise _Deny(ErrorCode.TENANT_SUSPENDED, None, target)",
        )
    ],
    "forbidden_audit_tenant_null": [
        (
            G,
            "raise _Deny(ErrorCode.AUTHZ_FORBIDDEN, scope.tenant_id, target)",
            "raise _Deny(ErrorCode.AUTHZ_FORBIDDEN, None, target)",
        )
    ],
    "deny_not_audited": [(G, "_record_denial(db, spec, caller, deny, deps.clock())", "pass")],
    "audit_correlation_id_wrong": [
        (G, "correlation_id=caller.request_id,", "correlation_id=UUID(int=0),")
    ],
    "audit_action_wrong": [(G, "action=spec.operation,", 'action="x.y",')],
    "unknown_principal_is_403_not_401": [
        (
            G,
            '_reject_credentials(spec, request_id, "unknown_principal")',
            "raise ApiProblem(ErrorCode.AUTH_PRINCIPAL_DISABLED)",
        )
    ],
    "second_authorization_header_ignored": [(G, "if len(values) != 1:", "if len(values) < 1:")],
    # ---- token verifier ----------------------------------------------------------------------
    "exp_not_verified": [
        (
            T,
            'options={"require": list(REQUIRED_CLAIMS)},',
            'options={"require": list(REQUIRED_CLAIMS), "verify_exp": False},',
        )
    ],
    "nbf_not_verified": [
        (
            T,
            'options={"require": list(REQUIRED_CLAIMS)},',
            'options={"require": list(REQUIRED_CLAIMS), "verify_nbf": False},',
        )
    ],
    "iat_not_verified": [
        (
            T,
            'options={"require": list(REQUIRED_CLAIMS)},',
            'options={"require": list(REQUIRED_CLAIMS), "verify_iat": False},',
        )
    ],
    "aud_not_verified": [
        (
            T,
            'options={"require": list(REQUIRED_CLAIMS)},',
            'options={"require": list(REQUIRED_CLAIMS), "verify_aud": False},',
        ),
        (
            T,
            'if claims.get("iss") != self._issuer or claims.get("aud") != self._audience:',
            'if claims.get("iss") != self._issuer:',
        ),
    ],
    "iss_not_verified": [
        (
            T,
            'options={"require": list(REQUIRED_CLAIMS)},',
            'options={"require": list(REQUIRED_CLAIMS), "verify_iss": False},',
        ),
        (
            T,
            'if claims.get("iss") != self._issuer or claims.get("aud") != self._audience:',
            'if claims.get("aud") != self._audience:',
        ),
    ],
    "required_claims_not_required": [
        (T, 'options={"require": list(REQUIRED_CLAIMS)},', 'options={"require": []},'),
        (T, 'if not (_is_int(iat) and _is_int(exp) and _is_int(claims.get("nbf"))):', "if False:"),
    ],
    "signature_not_verified": [
        (
            T,
            'options={"require": list(REQUIRED_CLAIMS)},',
            'options={"require": list(REQUIRED_CLAIMS), "verify_signature": False},',
        )
    ],
    "lifetime_cap_removed": [
        (T, "if exp <= iat or exp - iat > MAX_TOKEN_LIFETIME_SECONDS:", "if exp <= iat:")
    ],
    "lifetime_cap_off_by_one": [
        (T, "exp - iat > MAX_TOKEN_LIFETIME_SECONDS", "exp - iat >= MAX_TOKEN_LIFETIME_SECONDS")
    ],
    "lifetime_cap_raised_to_one_day": [
        (T, "MAX_TOKEN_LIFETIME_SECONDS: Final = 900", "MAX_TOKEN_LIFETIME_SECONDS: Final = 86400")
    ],
    "leeway_one_hour": [(T, "leeway=0,", "leeway=3600,")],
    "alg_confusion (trust header alg, PEM as key)": [
        (T, 'if header.get("alg") != ALGORITHM:', "if False:"),
        (T, "algorithms=[ALGORITHM],", 'algorithms=[header["alg"]],'),
        (
            T,
            "self._key = public_key",
            "self._key = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)",
        ),
    ],
    # ---- middleware / handlers / policy ------------------------------------------------------
    "client_request_id_trusted": [
        (
            M,
            "request_id = uuid.uuid4()",
            'request_id = uuid.UUID(dict(scope["headers"]).get(b"x-request-id", str(uuid.uuid4()).encode()).decode())',
        )
    ],
    "x_request_id_header_missing": [
        (M, 'headers["X-Request-ID"] = str(request_id)', 'headers["X-Request-ID"] = "static"')
    ],
    "body_cap_removed": [(M, "length > self.max_body_bytes", "length > 10**12")],
    "body_cap_off_by_one": [(M, "length > self.max_body_bytes", "length >= self.max_body_bytes")],
    "db_error_allows (fail open)": [
        (
            M,
            "return ApiProblem(ErrorCode.SERVICE_UNAVAILABLE)",
            "return ApiProblem(ErrorCode.INTERNAL_ERROR)",
        )
    ],
    "me_leaks_extra_field": [
        (
            H,
            'return _json(body.model_dump(mode="json"))',
            'return _json({**body.model_dump(mode="json"), "email": "leak"})',
        )
    ],
    "viewer_may_write_projects": [
        (P, '"project.write": _EDITORS_UP,', '"project.write": _EVERYONE,')
    ],
    "policy_default_allows_unknown_operation": [
        (P, "CAPABILITIES.get(operation, frozenset())", "CAPABILITIES.get(operation, _EVERYONE)")
    ],
    "body_parsed_before_auth": [
        (
            A,
            "        allowed = await run_in_threadpool(run_gates, request, spec, deps)",
            "        import json\n\n        raw = await request.body()\n        if raw:\n            try:\n                json.loads(raw)\n            except ValueError:\n                raise ApiProblem(ErrorCode.REQUEST_INVALID) from None\n        allowed = await run_in_threadpool(run_gates, request, spec, deps)",
        )
    ],
    "401_detail_reveals_reason": [
        (
            G,
            '    raise ApiProblem(ErrorCode.AUTH_TOKEN_INVALID, headers={"WWW-Authenticate": WWW_AUTHENTICATE})',
            "    raise ApiProblem(ErrorCode.AUTH_TOKEN_INVALID, detail=reason + '.', headers={\"WWW-Authenticate\": WWW_AUTHENTICATE})",
        )
    ],
    "token_text_logged": [
        (
            G,
            "_reject_credentials(spec, request_id, exc.reason)",
            "_reject_credentials(spec, request_id, token)",
        )
    ],
    "cache_control_missing": [
        (
            M,
            '("Cache-Control", "no-store"),  # tenant data must not be cached by intermediaries',
            "",
        )
    ],
    "nosniff_missing": [(M, '("X-Content-Type-Options", "nosniff"),', "")],
    "sqlite_foreign_keys_off": [
        (
            "src/tenantlab/db/engine.py",
            'event.listen(engine, "connect", _enable_sqlite_foreign_keys)',
            "pass",
        )
    ],
    "naive_datetime_accepted": [
        (
            "src/tenantlab/db/engine.py",
            'if value.tzinfo is None:\n            raise ValueError("naive datetime refused: timestamps must be timezone-aware")',
            'if False:\n            raise ValueError("x")',
        )
    ],
    "seed_overwrites_existing_data": [
        ("src/tenantlab/db/seed.py", "            _require_empty(session)\n", "")
    ],
    "seed_not_atomic (commit per tier)": [
        (
            "src/tenantlab/db/seed.py",
            '    session.add_all(models.Market(id=ids["market"][m.key], code=m.code) for m in fx.markets)\n    session.flush()',
            '    session.add_all(models.Market(id=ids["market"][m.key], code=m.code) for m in fx.markets)\n    session.commit()',
        )
    ],
    "settings_accept_private_key": [
        (
            "src/tenantlab/config.py",
            "        load_public_key(value)  # raises ConfigurationError (a ValueError) without echoing input\n",
            "",
        )
    ],
    "settings_echo_input_in_errors": [
        ("src/tenantlab/config.py", "hide_input_in_errors=True", "hide_input_in_errors=False")
    ],
    "uuid_parser_accepts_upper_case": [
        (
            "src/tenantlab/ids.py",
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        )
    ],
    "uuid_parser_accepts_any_version": [
        ("src/tenantlab/ids.py", "return parsed if parsed.version == 4 else None", "return parsed")
    ],
    "docs_openapi_exposed": [
        (A, "        openapi_url=None,", '        openapi_url="/openapi.json",')
    ],
    "redirect_slashes_on": [(A, "redirect_slashes=False,", "redirect_slashes=True,")],
    "unknown_principal_audited": [
        (
            G,
            "        if principal_status is None:\n",
            "        if principal_status is None:\n            db.add(AuditEvent(actor_id=None, tenant_id=None, action='x', resource_type='tenant', decision='deny', reason_code='r', timestamp=deps.clock(), correlation_id=request_id)); db.commit()\n",
        )
    ],
    "membership_role_not_validated (unknown role allowed)": [
        (P, "    return role in CAPABILITIES.get(operation, frozenset())", "    return True")
    ],
    "wrong_status_for_403_forbidden": [
        (
            "src/tenantlab/api/problems.py",
            "ErrorCode.AUTHZ_FORBIDDEN: ProblemText(\n            403,",
            "ErrorCode.AUTHZ_FORBIDDEN: ProblemText(\n            401,",
        )
    ],
    "chunked_cap_not_enforced": [(M, "            if seen > limit:", "            if False:")],
    "chunked_cap_off_by_one": [
        (M, "            if seen > limit:", "            if seen >= limit:")
    ],
    "500_leaks_exception_message": [
        (
            M,
            "        return ApiProblem(ErrorCode.INTERNAL_ERROR)\n",
            "        return ApiProblem(ErrorCode.INTERNAL_ERROR, detail=str(exc))\n",
        )
    ],
    "exception_message_logged": [(M, '"error": type(exc).__name__', '"error": str(exc)')],
    "crash_after_start_masked": [
        (
            M,
            "            if started:\n                raise",
            "            if started:\n                return",
        )
    ],
    "multiple_content_length_accepted": [
        (M, "if len(values) != 1 or not values[0].isdigit():", "if not values[0].isdigit():")
    ],
    "validation_handler_not_installed": [
        (A, "app.add_exception_handler(RequestValidationError, unprocessable)", "pass")
    ],
    "other_http_error_echoes_detail": [
        (
            A,
            "return problem_response(_request_id(request), ApiProblem(ErrorCode.INTERNAL_ERROR))\n\n    app.add_exception_handler(StarletteHTTPException",
            "return problem_response(_request_id(request), ApiProblem(ErrorCode.INTERNAL_ERROR, detail=str(getattr(exc, 'detail', ''))))\n\n    app.add_exception_handler(StarletteHTTPException",
        )
    ],
    "request_id_not_unique (constant)": [
        (M, "request_id = uuid.uuid4()", "request_id = uuid.UUID(int=1)")
    ],
    "sub_claim_not_checked_as_uuid4": [
        (T, '        if subject is None:\n            raise TokenError("bad_subject")\n', "")
    ],
    "jti_not_checked": [
        (T, "if not isinstance(jti, str) or not jti or len(jti) > 128:", "if False:")
    ],
    "unknown_route_is_200_html": [(A, "app.add_exception_handler(404, not_found)", "pass")],
}


IGNORE = shutil.ignore_patterns(
    ".venv", ".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "dist", "out"
)


def run_one(
    work: Path, edits: list[tuple[str, str, str]], paths: list[str] | None = None
) -> tuple[str, str]:
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(REPO, work, ignore=IGNORE)
    for relative, old, new in edits:
        path = work / relative
        text = path.read_text(encoding="utf-8")
        if old not in text:
            return "NOAPPLY", f"pattern not found in {relative}"
        path.write_text(text.replace(old, new, 1), encoding="utf-8")
    env = dict(os.environ, PYTHONPATH=f"{work / 'src'}:{work}")
    imported = subprocess.run(
        [sys.executable, "-c", "import tenantlab; print(tenantlab.__file__)"],
        capture_output=True, text=True, env=env, cwd=work, check=False,
    ).stdout.strip()  # fmt: skip
    if not imported.startswith(str(work)):
        return "NOAPPLY", f"the scratch copy is not the imported package: {imported}"
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", *(TEST_PATHS if paths is None else paths), "-q", "--tb=no", "-x",
         "-p", "no:cacheprovider", "--no-header"],
        cwd=work, env=env, capture_output=True, text=True, timeout=600, check=False,
    )  # fmt: skip
    tail = (result.stdout.strip().splitlines() or [result.stderr[-200:]])[-1]
    return ("KILLED" if result.returncode != 0 else "SURVIVED"), tail


def main(
    mutants: dict[str, list[tuple[str, str, str]]] | None = None,
    paths_for: Callable[[str], list[str]] | None = None,
) -> int:
    mutants = MUTANTS if mutants is None else mutants
    counts = {"KILLED": 0, "SURVIVED": 0, "NOAPPLY": 0}
    with tempfile.TemporaryDirectory(prefix="tenantlab-mutation-") as scratch:
        # A mutant only counts as killed if the UNMUTATED suite passes: otherwise every mutant
        # would look killed for an unrelated reason (a red baseline proves nothing).
        verdict, info = run_one(Path(scratch) / "work", [])
        if (
            verdict != "SURVIVED"
        ):  # "SURVIVED" here means: nothing failed, i.e. the baseline is green
            print(f"BASELINE NOT GREEN ({verdict}): {info}\nrefusing to run mutants")
            return 2
        print(f"baseline green | {info}", flush=True)
        for name, edits in mutants.items():
            verdict, info = run_one(
                Path(scratch) / "work", edits, paths_for(name) if paths_for else None
            )
            counts[verdict] += 1
            print(f"{verdict:9} {name} | {info}", flush=True)
    print(
        f"\nTOTAL {len(mutants)}  killed {counts['KILLED']}  "
        f"survived {counts['SURVIVED']}  noapply {counts['NOAPPLY']}"
    )
    if counts["NOAPPLY"]:
        return 2
    return 1 if counts["SURVIVED"] else 0


if __name__ == "__main__":
    sys.exit(main())
