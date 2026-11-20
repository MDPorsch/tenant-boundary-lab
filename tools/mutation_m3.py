"""Mutation check for the vulnerable lab's ISOLATION (milestone M3): does the suite notice when a
guard, a flaw switch, the launcher, the wheel exclusion or a container setting is weakened?

    uv run python tools/mutation_m3.py       # baseline (including the container tests) then mutants

Same machinery and exit codes as tools/mutation_m1.py. Mutants that weaken the container files or
the self-check are run against the Docker tests (an image rebuild each, so they are slower); every
other mutant runs the whole suite except the Docker tests. The unmutated suite must be green first.

Not every guard layer is independently observable, on purpose: the launcher and the factory both
check the bind address and the environment (defence in depth), so removing ONE of them is an
equivalent mutant. Those are removed together below, or left out, and the table says why.
"""

from __future__ import annotations

import sys

from mutation_m1 import main

GD = "src/tenantlab/lab/vulnerable/guard.py"
AP = "src/tenantlab/lab/vulnerable/app.py"
HD = "src/tenantlab/lab/vulnerable/handlers.py"
LA = "src/tenantlab/lab/vulnerable/__main__.py"
PY = "pyproject.toml"
CF = "deploy/compose.vulnerable-lab.yaml"
DF = "deploy/Dockerfile.vulnerable-lab"
SC = "deploy/container_selfcheck.py"

MUTANTS: dict[str, list[tuple[str, str, str]]] = {
    # ---- the start-up guard -----------------------------------------------------------------
    "lab_mode_accepts_any_truthy_value": [(GD, 'if environ.get("LAB_MODE") != "1":', 'if not environ.get("LAB_MODE"):')],
    "lab_mode_not_required": [(GD, 'if environ.get("LAB_MODE") != "1":', "if False:")],
    "production_environment_allowed": [(GD, 'if environ.get("TENANTLAB_ENV") not in ALLOWED_ENVIRONMENTS:', 'if environ.get("TENANTLAB_ENV") == "production":')],
    "environment_not_required": [(GD, 'if environ.get("TENANTLAB_ENV") not in ALLOWED_ENVIRONMENTS:', "if False:")],
    "explicit_environ_ignored": [(AP, "env = os.environ if environ is None else environ", "env = os.environ")],
    "bind_address_not_checked": [(GD, "    if not _is_loopback(host):", "    if False:")],
    "localhost_name_trusted": [(GD, "    if not _is_loopback(host):", '    if not _is_loopback(host) and host != "localhost":')],
    "non_sqlite_database_allowed": [(GD, 'if url.get_backend_name() != "sqlite" or url.database in (None, "", ":memory:"):', "if False:")],
    "in_memory_database_allowed": [(GD, 'if url.get_backend_name() != "sqlite" or url.database in (None, "", ":memory:"):', 'if url.get_backend_name() != "sqlite":')],
    "real_data_allowed": [(GD, "    if real:", "    if False:")],
    "empty_database_allowed": [(GD, "    if not emails:", "    if False:")],
    "synthetic_suffix_matches_everything": [(GD, 'SYNTHETIC_EMAIL_SUFFIX: Final = "@tenantlab.invalid"', 'SYNTHETIC_EMAIL_SUFFIX: Final = ""')],
    # ---- the request guard and the marking --------------------------------------------------
    "request_guard_ignores_the_client": [(GD, 'if client is not None and client[0] != "" and not _is_loopback(str(client[0])):', "if False:")],
    "request_guard_ignores_the_server_address": [(GD, "    return not (server is not None and _is_ip(str(server[0])) and not _is_loopback(str(server[0])))", "    return True")],
    "request_guard_not_installed": [(AP, "    app.add_middleware(LoopbackOnlyMiddleware)\n", "")],
    "responses_not_marked": [(AP, '    app.add_middleware(MarkingMiddleware, value=f"deliberately-broken-lab; flaws={names}")\n', "")],
    "banner_not_logged": [(AP, "    logger.warning(\n        \"DELIBERATELY VULNERABLE LAB", "    logger.debug(\n        \"DELIBERATELY VULNERABLE LAB")],
    # ---- the flaw switches (confinement, causality, attribution) ----------------------------
    "flaw_tenant_predicate_always_on": [(HD, "    if scoped or Flaw.TENANT_PREDICATE_OMITTED not in ctx.flaws:", "    if scoped:")],
    "flaw_tenant_predicate_never_on": [(HD, "    if scoped or Flaw.TENANT_PREDICATE_OMITTED not in ctx.flaws:", "    if True:")],
    "flaw_tenant_predicate_uses_the_lowest_role": [(HD, "    best = max(rows, key=", "    best = min(rows, key=")],
    "flaw_role_check_always_on": [(HD, "    if Flaw.ROLE_CHECK_MISSING not in ctx.flaws and (", "    if False and (")],
    "flaw_private_property_always_on": [(HD, "        if Flaw.PRIVATE_PROPERTY_SERIALIZED in ctx.flaws:", "        if True:")],
    "flaw_market_always_on": [(HD, "        Flaw.MARKET_BOUNDARY_OMITTED not in ctx.flaws\n        and target.market_id is not None", "        False\n        and target.market_id is not None")],
    "flaw_market_always_on_in_the_list": [(HD, "    if Flaw.MARKET_BOUNDARY_OMITTED not in ctx.flaws:\n        visible = and_(", "    if False:\n        visible = and_(")],
    "authentication_weakened": [(HD, "    if scheme.lower() != \"bearer\" or not separator or not token or token != token.strip():\n        raise unauthorized", "    if False:\n        raise unauthorized")],
    # ---- the launcher -----------------------------------------------------------------------
    "launcher_accepts_any_host": [(LA, "            require_loopback_bind(args.host)\n", "            pass\n"), (LA, "bind_host=args.host)", "bind_host=None)")],
    "launcher_accepts_an_open_socket_directory": [(LA, "            _require_private_directory(args.uds)\n", "            pass\n")],
    "socket_not_chmodded_after_bind": [(LA, "                os.chmod(self.config.uds, 0o600)", "                pass")],
    # ---- the wheel and the container --------------------------------------------------------
    "vulnerable_lab_shipped_in_the_wheel": [(PY, 'wheel-exclude = ["tenantlab/lab/vulnerable/**"]', "wheel-exclude = []")],
    "compose_has_a_network": [(CF, "    network_mode: none", "    network_mode: bridge")],
    "compose_publishes_a_port": [(CF, "    read_only: true\n", '    read_only: true\n    ports: ["8099:8099"]\n')],
    "compose_is_privileged": [(CF, "    read_only: true\n", "    read_only: true\n    privileged: true\n")],
    "compose_runs_as_root": [(CF, 'user: "10001:10001"', 'user: "0:0"')],
    "compose_mounts_the_host": [(CF, "    read_only: true\n", '    read_only: true\n    volumes: ["/:/host"]\n')],
    "compose_keeps_all_capabilities": [(CF, "    cap_drop: [ALL]\n", "")],
    "dockerfile_runs_as_root": [(DF, "USER 10001:10001", "USER root")],
    "dockerfile_exposes_a_port": [(DF, "# No LAB_MODE", "EXPOSE 8099\n# No LAB_MODE")],
    "dockerfile_base_image_unpinned": [(DF, "FROM python:3.13-slim-bookworm AS build", "FROM python:latest AS build")],
    # container mutants: need the Docker tests (they rebuild the image)
    "selfcheck_cannot_see_egress": [(SC, '"egress_tcp_blocked": _tcp_blocked(),', '"egress_tcp_blocked": True,')],
    "selfcheck_cannot_see_dns": [(SC, '"dns_blocked": _dns_blocked(),', '"dns_blocked": True,')],
    "selfcheck_cannot_see_interfaces": [(SC, '"interfaces": sorted(os.listdir("/sys/class/net")),', '"interfaces": ["lo"],')],
    "image_runs_the_lab_as_root": [(DF, "USER 10001:10001", "USER 0:0")],
}  # fmt: skip

NEEDS_DOCKER = frozenset(
    {
        "selfcheck_cannot_see_egress", "selfcheck_cannot_see_dns", "selfcheck_cannot_see_interfaces",
        "image_runs_the_lab_as_root",
    }
)  # fmt: skip


def paths_for(name: str) -> list[str]:
    return ["tests/docker"] if name in NEEDS_DOCKER else ["tests", "-m", "not docker"]


if __name__ == "__main__":
    sys.exit(main(MUTANTS, paths_for))
