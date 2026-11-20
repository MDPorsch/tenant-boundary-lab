# boundarycheck report

* run: `20261120T100545Z-10368255`
* scope: lab-vulnerable-demo (target tenant-boundary-lab \(vulnerable\))
* transport: fixture:tenant-boundary-lab:vulnerable\(ROLE\_CHECK\_MISSING\)
* tool: boundarycheck 0.1.0.dev0
* started 2026-11-20T10:05:45Z, finished 2026-11-20T10:05:46Z
* In-process fixture run: no network was used and no authorization attestation is required.
* exit code: **1**

> `no_issue_observed` does not mean the target is secure: it means one request matched the declared policy.

## Summary

| status | cases |
|---|---|
| no_issue_observed | 281 |
| finding_candidate | 5 |
| policy_denied | 0 |
| not_run | 0 |
| incomplete | 0 |
| error | 0 |
| inconclusive | 0 |

## Finding candidates (need human review)

| id | rule | severity | principal | action | resource | expected -> observed | detail |
|---|---|---|---|---|---|---|---|
| BC-0067 | BC-ROLE-01 | high | bob | contact.private.read | PA1 | deny\_forbidden -\> allow | expected deny\_forbidden \(role\_denied\), observed allow \(HTTP 200\): access was granted where the policy denies it |
| BC-0076 | BC-ROLE-01 | high | bob | project.write | PA1 | deny\_forbidden -\> allow | expected deny\_forbidden \(role\_denied\), observed allow \(HTTP 200\): access was granted where the policy denies it; state changed: projects:50000000000040008000000000000001 \(modified\) |
| BC-0120 | BC-ROLE-01 | high | dave | contact.private.read | PA1 | deny\_forbidden -\> allow | expected deny\_forbidden \(role\_denied\), observed allow \(HTTP 200\): access was granted where the policy denies it |
| BC-0122 | BC-ROLE-01 | high | dave | contact.private.read | PB1 | deny\_forbidden -\> allow | expected deny\_forbidden \(role\_denied\), observed allow \(HTTP 200\): access was granted where the policy denies it |
| BC-0130 | BC-ROLE-01 | high | dave | project.write | PB1 | deny\_forbidden -\> allow | expected deny\_forbidden \(role\_denied\), observed allow \(HTTP 200\): access was granted where the policy denies it; state changed: projects:50000000000040008000000000000003 \(modified\) |

## Not clean and not a finding

None.

## Limitations

* no\_issue\_observed means the response to that one request matched the declared policy. It does not mean the target is secure.
* Expected results come from the policy in the config, written by the assessor. The tool cannot tell a wrong policy from a vulnerable target.
* Reads use GET/HEAD. Write checks exist only on the in-process fixture transport, send only requests the policy says must be refused, and are judged by a state diff. The write behaviour of a live target, concurrency and timing are not tested.
* Only the principals, resources and actions declared in the config were exercised. Undeclared routes and objects were not.
* A SHA-256 over stored evidence proves the integrity of the stored redacted bytes. It does not prove where they came from.
* 3 write combination\(s\) that the policy allows were not exercised by design: write checks send only requests the policy says must be refused.
