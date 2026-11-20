"""The supported launcher: `python -m tenantlab.lab.vulnerable`.

It binds a Unix domain socket (no TCP listener exists) or a LITERAL loopback address, and it
refuses everything else with exit status 2. It is not a substitute for the container, which removes
the network altogether (docs/vulnerable-lab.md, decision D-41).
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from pydantic import ValidationError

from tenantlab.config import ConfigurationError, Settings
from tenantlab.lab.vulnerable.app import create_vulnerable_app
from tenantlab.lab.vulnerable.flaws import parse_flaws
from tenantlab.lab.vulnerable.guard import (
    LabIsolationError,
    require_lab_environment,
    require_loopback_bind,
)

REFUSED = 2


def _require_private_directory(socket_path: Path) -> None:
    """uvicorn chmods a Unix socket to 0666 after binding, so the socket file alone protects
    nothing: its DIRECTORY must not be traversable by group or others (the window is then closed
    completely). The socket itself is also chmodded to 0600 once bound (see `_serve`)."""
    parent = socket_path.parent
    try:
        mode = parent.stat().st_mode & 0o777
    except OSError:
        raise LabIsolationError(f"the socket directory {parent} does not exist") from None
    if mode & 0o077:
        raise LabIsolationError(
            f"the socket directory {parent} is accessible by group or others "
            f"({oct(mode)}): make it owner-only (chmod 700)"
        )


def _serve(app: FastAPI, uds: Path | None, host: str | None, port: int) -> None:
    import uvicorn  # noqa: PLC0415

    class OwnerOnlyServer(uvicorn.Server):
        async def startup(self, *args: Any, **kwargs: Any) -> None:
            await super().startup(*args, **kwargs)  # signature passed through unchanged
            if self.config.uds:
                os.chmod(self.config.uds, 0o600)

    if uds is not None:
        config = uvicorn.Config(app, uds=str(uds), log_level="info", access_log=False)
    else:
        config = uvicorn.Config(
            app, host=host or "127.0.0.1", port=port, log_level="info", access_log=False
        )
    OwnerOnlyServer(config).run()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m tenantlab.lab.vulnerable",
        description="DELIBERATELY VULNERABLE lab: local only, synthetic data, never deploy.",
    )
    where = parser.add_mutually_exclusive_group(required=True)
    where.add_argument("--uds", type=Path, help="listen on this Unix socket (preferred)")
    where.add_argument("--host", help="listen on this LITERAL loopback IP (needs --port)")
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--flaws", default="all", help="all, none, or NAMES separated by commas")
    parser.add_argument(
        "--init-synthetic-db",
        type=Path,
        help="create and seed this SQLite file first (must not exist)",
    )
    return parser


def _refuse(message: str) -> int:
    print(f"refused: {message}", file=sys.stderr)  # noqa: T201
    return REFUSED


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    environ = dict(os.environ)
    try:
        require_lab_environment(environ)
        if args.host is not None:
            require_loopback_bind(args.host)
        if args.uds is not None:
            _require_private_directory(args.uds)
        flaws = parse_flaws(args.flaws)
    except (LabIsolationError, ValueError) as exc:
        return _refuse(str(exc))

    if args.init_synthetic_db is not None:
        from tenantlab.db.migrate import upgrade_to_head  # noqa: PLC0415
        from tenantlab.db.seed import seed_fixtures  # noqa: PLC0415

        if args.init_synthetic_db.exists():
            return _refuse("--init-synthetic-db refuses to touch an existing file")
        url = f"sqlite+pysqlite:///{args.init_synthetic_db}"
        upgrade_to_head(url)
        seed_fixtures(url)
        environ["TENANTLAB_DATABASE_URL"] = url
    try:
        settings = Settings.from_env(environ)
        app = create_vulnerable_app(settings, flaws=flaws, environ=environ, bind_host=args.host)
    except (LabIsolationError, ConfigurationError, ValidationError) as exc:
        return _refuse(str(exc))

    try:
        import uvicorn  # noqa: F401, PLC0415
    except ImportError:
        return _refuse("uvicorn is not installed (install the 'lab' extra)")
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    _serve(app, args.uds, args.host, args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
