# Security policy

## What this repository is

An educational **authorization-testing lab**. From milestone M3 it contains a *deliberately
vulnerable* variant of a small API. That variant exists only to be attacked locally and to prove the
test runner detects the flaws.

* Never deploy it, expose it to a network, or point it at real data.
* It is designed to refuse to start outside `LAB_MODE=1`, outside loopback, or in a production
  environment (spec TL-16). Today (M1) the vulnerable variant does not exist yet.
* Never aim the runner at systems you do not own. The runner only talks to the in-process app.

## Supported versions

Pre-release. Only the latest commit on the default branch is supported.

## Reporting a vulnerability

Please report problems in the **patched** implementation, the oracle, or the test harness (a policy
bypass the tests miss, a secret, an unsafe default) through **GitHub private vulnerability
reporting** on this repository ("Security" tab, "Report a vulnerability"). The owner must enable that
setting; until it is enabled, open no public issue containing exploit detail and contact the owner
through their GitHub profile instead.

Do not include real credentials, personal data or third-party system details in any report or issue.

Flaws in the deliberately vulnerable variant are intentional and are not vulnerabilities.
