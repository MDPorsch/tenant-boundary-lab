# Security policy

## What this repository is

An educational **authorization-testing lab**: a patched multi-tenant API, an independent policy
oracle, and a **deliberately vulnerable** variant of the same API that exists only to be attacked
locally and to prove that test tooling detects the flaws.

* **Never deploy the vulnerable variant, expose it to a network, or point it at real data.** It
  refuses to start outside `LAB_MODE=1`, outside the `lab`/`test` environment, on a non-loopback
  address, on a networked database, or on data that is not synthetic (see
  [docs/vulnerable-lab.md](docs/vulnerable-lab.md)). The container in `deploy/` removes the network
  entirely and is the real boundary.
* **The vulnerable code is not in the published wheel.** It exists only in a source checkout.
* Never aim any tool from this project at a system you do not own or are not authorized to test.

## Supported versions

Pre-release. Only the latest commit on the default branch is supported.

## Reporting a vulnerability

Please use **GitHub private vulnerability reporting**: the repository's **Security** tab, then
**Report a vulnerability**. Do not open a public issue containing exploit detail.

In scope (please report):

* a way to make the **patched** API, the token verifier or the policy oracle allow something the
  documented policy denies, or leak data it should not;
* a way to start, reach or ship the **vulnerable lab** in a way its isolation layers are meant to
  prevent (for example a guard that can be bypassed, or the vulnerable code appearing in the wheel);
* a secret, personal data or an unsafe default in the repository or its CI.

Out of scope: the five **intentional** flaws of the vulnerable variant (tenant predicate omitted, role
check missing, private property serialized, market boundary omitted, write before authorization) and their exploits. They are
documented, switchable and expected.

Do not include real credentials, personal data or third-party system details in any report.
You can expect an acknowledgement within a few days; this is a volunteer project and there is no bounty.
