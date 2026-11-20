# boundarycheck report

* run: `20261120T100547Z-c86cf039`
* scope: lab-vulnerable-demo (target tenant-boundary-lab \(vulnerable\))
* transport: fixture:tenant-boundary-lab:vulnerable\(WRITE\_BEFORE\_AUTHORIZATION\)
* tool: boundarycheck 0.1.0.dev0
* started 2026-11-20T10:05:47Z, finished 2026-11-20T10:05:47Z
* In-process fixture run: no network was used and no authorization attestation is required.
* exit code: **0**

> `no_issue_observed` does not mean the target is secure: it means one request matched the declared policy.

## Summary

| status | cases |
|---|---|
| no_issue_observed | 249 |
| finding_candidate | 0 |
| policy_denied | 0 |
| not_run | 0 |
| incomplete | 0 |
| error | 0 |
| inconclusive | 0 |

## Finding candidates (need human review)

None.

## Not clean and not a finding

None.

## Limitations

* no\_issue\_observed means the response to that one request matched the declared policy. It does not mean the target is secure.
* Expected results come from the policy in the config, written by the assessor. The tool cannot tell a wrong policy from a vulnerable target.
* Reads use GET/HEAD. Write checks exist only on the in-process fixture transport, send only requests the policy says must be refused, and are judged by a state diff. The write behaviour of a live target, concurrency and timing are not tested.
* Only the principals, resources and actions declared in the config were exercised. Undeclared routes and objects were not.
* A SHA-256 over stored evidence proves the integrity of the stored redacted bytes. It does not prove where they came from.
* --reads-only: 37 write case\(s\) were left out at the operator's request; write-path authorization was not tested in this run.
