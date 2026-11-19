"""Secret scan: the whole git history, the working tree, and a canary that proves the scanner works.

    uv run python tools/secret_scan.py

Exit status follows the rule used across this project (a tool failure is never reported as clean):
    0  scanner works (it caught the canary) AND the repository has no findings
    1  the scanner reported findings in the repository (values are redacted in its output)
    2  infrastructure error: gitleaks missing, failed to run, or did NOT catch the canary

The canary is a throwaway repository in a temporary directory holding FAKE, randomly generated
secrets (a GitHub-token shape, a private-key block, a generic API key). It is never inside this
repository and is deleted afterwards. Requires gitleaks (`brew install gitleaks`); no network use.
"""

from __future__ import annotations

import json
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CANARY_RULES = {"github-pat", "private-key"}  # at least these must be detected in the canary
_ALNUM = string.ascii_letters + string.digits


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, check=False)  # noqa: S603


def _scan(kind: str, target: Path, report: Path) -> tuple[int, set[str]]:
    """Run one gitleaks scan; returns (exit code, rule ids found). `kind` is 'git' or 'dir'."""
    args = ["gitleaks", kind, "--no-banner", "--redact", "--report-format", "json"]
    args += ["--report-path", str(report)]
    if kind == "git":
        args += ["--log-opts=--all"]  # every branch and tag, not just HEAD
    result = _run([*args, "."], target)
    findings = json.loads(report.read_text() or "[]") if report.exists() else []
    if result.returncode not in (0, 1):
        sys.stderr.write(result.stderr[-500:])
        return 2, set()
    return (1 if findings else 0), {f["RuleID"] for f in findings}


def _make_canary(root: Path) -> None:
    token = "ghp_" + "".join(secrets.choice(_ALNUM) for _ in range(36))
    api_secret = "".join(secrets.choice(_ALNUM + "+/") for _ in range(40))
    (root / "config.py").write_text(f'TOKEN = "{token}"\naws_secret_access_key = "{api_secret}"\n')
    body = "\n".join("".join(secrets.choice(_ALNUM + "+/") for _ in range(64)) for _ in range(12))
    (root / "key.pem").write_text(
        f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\n"
    )
    for command in (
        ["git", "init", "-q"],
        ["git", "config", "user.email", "canary@example.invalid"],
        ["git", "config", "user.name", "canary"],
        ["git", "add", "-A"],
        ["git", "commit", "-q", "-m", "canary"],
    ):
        _run(command, root)


def main() -> int:
    if shutil.which("gitleaks") is None:
        print("INFRASTRUCTURE ERROR: gitleaks is not installed (brew install gitleaks)")
        return 2
    with tempfile.TemporaryDirectory(prefix="tenantlab-secretscan-") as scratch:
        work = Path(scratch)
        canary = work / "canary"
        canary.mkdir()
        _make_canary(canary)
        code, rules = _scan("git", canary, work / "canary.json")
        if code != 1 or not rules >= CANARY_RULES:
            print(
                f"INFRASTRUCTURE ERROR: the scanner did not catch the canary (saw {sorted(rules)})"
            )
            return 2
        print(f"scanner self-test: caught the canary ({', '.join(sorted(rules))})")

        worst = 0
        for kind, label in (("git", "history (all commits)"), ("dir", "working tree")):
            code, rules = _scan(kind, REPO, work / f"{kind}.json")
            if code == 2:
                print(f"INFRASTRUCTURE ERROR: gitleaks failed on the {label}")
                return 2
            verdict = "no findings" if code == 0 else f"FINDINGS: {sorted(rules)}"
            print(f"{label}: {verdict}")
            worst = max(worst, code)
    return worst


if __name__ == "__main__":
    sys.exit(main())
