"""Runs INSIDE the container and prints one JSON line describing what it observes.

It checks the isolation (user, interfaces, outbound TCP, DNS, writable root filesystem, effective
capabilities, no-new-privileges) and demonstrates that each controlled flaw is exploitable in this
sandbox. A control run WITHOUT `--network none` must report egress possible: that is what proves
the 'blocked' answers mean something (tests/docker/test_vulnerable_lab_container.py).
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ISSUER = "https://issuer.tenantlab.invalid"
AUDIENCE = "tenantlab-api"


def _status_field(name: str) -> str:
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith(f"{name}:"):
            return line.split(":", 1)[1].strip()
    return ""


def _tcp_blocked() -> bool:
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=3).close()
    except OSError:
        return True
    return False


def _dns_blocked() -> bool:
    try:
        socket.getaddrinfo("example.com", 80)
    except OSError:
        return True
    return False


def _rootfs_read_only() -> bool:
    try:
        with open("/selfcheck-probe", "w") as handle:
            handle.write("x")
    except OSError:
        return True
    return False


async def _exploits() -> dict[str, bool]:
    from tenantlab.config import Settings  # noqa: PLC0415
    from tenantlab.db.migrate import upgrade_to_head  # noqa: PLC0415
    from tenantlab.db.seed import seed_fixtures  # noqa: PLC0415
    from tenantlab.lab.fixtures.loader import load_fixtures  # noqa: PLC0415
    from tenantlab.lab.vulnerable import Flaw, create_vulnerable_app  # noqa: PLC0415

    fx = load_fixtures()
    private = Ed25519PrivateKey.generate()
    pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()  # fmt: skip

    def token(key: str) -> dict[str, str]:
        now = int(time.time())
        claims = {
            "sub": fx.principal(key).id, "jti": str(uuid.uuid4()), "iss": ISSUER, "aud": AUDIENCE,
            "iat": now, "nbf": now, "exp": now + 300,
        }  # fmt: skip
        return {"Authorization": "Bearer " + jwt.encode(claims, private, algorithm="EdDSA")}

    pa1, pa2, pb1 = (f"/v1/projects/{fx.project(k).id}" for k in ("PA1", "PA2", "PB1"))
    patch_body = {"title": "pwned", "row_version": 1}
    # flaw: (principal, method, path, body, text that proves the exploit worked)
    exploits = {
        Flaw.TENANT_PREDICATE_OMITTED: ("bob", "GET", pb1, None, "SENTINEL-TENANT-B"),
        Flaw.ROLE_CHECK_MISSING: ("bob", "PATCH", pa1, patch_body, "pwned"),
        Flaw.PRIVATE_PROPERTY_SERIALIZED: ("bob", "GET", pa1, None, fx.private_sentinel),
        Flaw.MARKET_BOUNDARY_OMITTED: ("alice", "GET", pa2, None, "US pilot"),
    }
    results: dict[str, bool] = {}
    work = Path(tempfile.mkdtemp(prefix="selfcheck-", dir="/tmp"))
    for flaw, (who, method, path, body, needle) in exploits.items():
        url = f"sqlite+pysqlite:///{work / (flaw.name + '.sqlite')}"
        upgrade_to_head(url)
        seed_fixtures(url)
        settings = Settings(
            database_url=url, jwt_issuer=ISSUER, jwt_audience=AUDIENCE, jwt_public_key_pem=pem
        )  # type: ignore[arg-type]
        app = create_vulnerable_app(
            settings, flaws=frozenset({flaw}), environ={"LAB_MODE": "1", "TENANTLAB_ENV": "lab"}
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://lab.invalid") as client:
            response = await client.request(method, path, headers=token(who), json=body)
        results[flaw.name] = response.status_code == 200 and needle in response.text
    return results


def main() -> None:
    report: dict[str, Any] = {
        "uid": os.getuid(),
        "interfaces": sorted(os.listdir("/sys/class/net")),
        "egress_tcp_blocked": _tcp_blocked(),
        "dns_blocked": _dns_blocked(),
        "root_filesystem_read_only": _rootfs_read_only(),
        "effective_capabilities": _status_field("CapEff"),
        "no_new_privileges": _status_field("NoNewPrivs") == "1",
        "exploits": asyncio.run(_exploits()),
    }
    print(json.dumps(report))  # noqa: T201


if __name__ == "__main__":
    main()
