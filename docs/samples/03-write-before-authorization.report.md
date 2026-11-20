# boundarycheck report

* run: `20261120T100546Z-76075276`
* scope: lab-vulnerable-demo (target tenant-boundary-lab \(vulnerable\))
* transport: fixture:tenant-boundary-lab:vulnerable\(WRITE\_BEFORE\_AUTHORIZATION\)
* tool: boundarycheck 0.1.0.dev0
* started 2026-11-20T10:05:46Z, finished 2026-11-20T10:05:46Z
* In-process fixture run: no network was used and no authorization attestation is required.
* exit code: **1**

> `no_issue_observed` does not mean the target is secure: it means one request matched the declared policy.

## Summary

| status | cases |
|---|---|
| no_issue_observed | 265 |
| finding_candidate | 21 |
| policy_denied | 0 |
| not_run | 0 |
| incomplete | 0 |
| error | 0 |
| inconclusive | 0 |

## Finding candidates (need human review)

| id | rule | severity | principal | action | resource | expected -> observed | detail |
|---|---|---|---|---|---|---|---|
| BC-0050 | BC-MUTATION-01 | high | alice | project.write | PA2 | deny\_not\_found -\> deny\_not\_found | the request was not accepted \(HTTP 404\) but state changed: projects:50000000000040008000000000000002 \(modified\) |
| BC-0051 | BC-MUTATION-01 | high | alice | project.write | PB1 | deny\_not\_found -\> deny\_not\_found | the request was not accepted \(HTTP 404\) but state changed: projects:50000000000040008000000000000003 \(modified\) |
| BC-0052 | BC-MUTATION-01 | high | alice | project.write | PC1 | deny\_not\_found -\> deny\_not\_found | the request was not accepted \(HTTP 404\) but state changed: projects:50000000000040008000000000000004 \(modified\) |
| BC-0076 | BC-MUTATION-01 | high | bob | project.write | PA1 | deny\_forbidden -\> deny\_forbidden | the request was not accepted \(HTTP 403\) but state changed: projects:50000000000040008000000000000001 \(modified\) |
| BC-0077 | BC-MUTATION-01 | high | bob | project.write | PA2 | deny\_not\_found -\> deny\_not\_found | the request was not accepted \(HTTP 404\) but state changed: projects:50000000000040008000000000000002 \(modified\) |
| BC-0078 | BC-MUTATION-01 | high | bob | project.write | PB1 | deny\_not\_found -\> deny\_not\_found | the request was not accepted \(HTTP 404\) but state changed: projects:50000000000040008000000000000003 \(modified\) |
| BC-0079 | BC-MUTATION-01 | high | bob | project.write | PC1 | deny\_not\_found -\> deny\_not\_found | the request was not accepted \(HTTP 404\) but state changed: projects:50000000000040008000000000000004 \(modified\) |
| BC-0103 | BC-MUTATION-01 | high | carla | project.write | PA1 | deny\_not\_found -\> deny\_not\_found | the request was not accepted \(HTTP 404\) but state changed: projects:50000000000040008000000000000001 \(modified\) |
| BC-0104 | BC-MUTATION-01 | high | carla | project.write | PA2 | deny\_not\_found -\> deny\_not\_found | the request was not accepted \(HTTP 404\) but state changed: projects:50000000000040008000000000000002 \(modified\) |
| BC-0105 | BC-MUTATION-01 | high | carla | project.write | PC1 | deny\_not\_found -\> deny\_not\_found | the request was not accepted \(HTTP 404\) but state changed: projects:50000000000040008000000000000004 \(modified\) |
| BC-0129 | BC-MUTATION-01 | high | dave | project.write | PA2 | deny\_not\_found -\> deny\_not\_found | the request was not accepted \(HTTP 404\) but state changed: projects:50000000000040008000000000000002 \(modified\) |
| BC-0130 | BC-MUTATION-01 | high | dave | project.write | PB1 | deny\_forbidden -\> deny\_forbidden | the request was not accepted \(HTTP 403\) but state changed: projects:50000000000040008000000000000003 \(modified\) |
| BC-0131 | BC-MUTATION-01 | high | dave | project.write | PC1 | deny\_not\_found -\> deny\_not\_found | the request was not accepted \(HTTP 404\) but state changed: projects:50000000000040008000000000000004 \(modified\) |
| BC-0182 | BC-MUTATION-01 | high | frank | project.write | PA1 | deny\_not\_found -\> deny\_not\_found | the request was not accepted \(HTTP 404\) but state changed: projects:50000000000040008000000000000001 \(modified\) |
| BC-0183 | BC-MUTATION-01 | high | frank | project.write | PA2 | deny\_not\_found -\> deny\_not\_found | the request was not accepted \(HTTP 404\) but state changed: projects:50000000000040008000000000000002 \(modified\) |
| BC-0184 | BC-MUTATION-01 | high | frank | project.write | PB1 | deny\_not\_found -\> deny\_not\_found | the request was not accepted \(HTTP 404\) but state changed: projects:50000000000040008000000000000003 \(modified\) |
| BC-0185 | BC-MUTATION-01 | high | frank | project.write | PC1 | deny\_not\_found -\> deny\_not\_found | the request was not accepted \(HTTP 404\) but state changed: projects:50000000000040008000000000000004 \(modified\) |
| BC-0209 | BC-MUTATION-01 | high | gina | project.write | PA1 | deny\_not\_found -\> deny\_not\_found | the request was not accepted \(HTTP 404\) but state changed: projects:50000000000040008000000000000001 \(modified\) |
| BC-0210 | BC-MUTATION-01 | high | gina | project.write | PA2 | deny\_not\_found -\> deny\_not\_found | the request was not accepted \(HTTP 404\) but state changed: projects:50000000000040008000000000000002 \(modified\) |
| BC-0211 | BC-MUTATION-01 | high | gina | project.write | PB1 | deny\_not\_found -\> deny\_not\_found | the request was not accepted \(HTTP 404\) but state changed: projects:50000000000040008000000000000003 \(modified\) |
| BC-0212 | BC-MUTATION-01 | high | gina | project.write | PC1 | deny\_forbidden -\> deny\_forbidden | the request was not accepted \(HTTP 403\) but state changed: projects:50000000000040008000000000000004 \(modified\) |

## Not clean and not a finding

None.

## Limitations

* no\_issue\_observed means the response to that one request matched the declared policy. It does not mean the target is secure.
* Expected results come from the policy in the config, written by the assessor. The tool cannot tell a wrong policy from a vulnerable target.
* Reads use GET/HEAD. Write checks exist only on the in-process fixture transport, send only requests the policy says must be refused, and are judged by a state diff. The write behaviour of a live target, concurrency and timing are not tested.
* Only the principals, resources and actions declared in the config were exercised. Undeclared routes and objects were not.
* A SHA-256 over stored evidence proves the integrity of the stored redacted bytes. It does not prove where they came from.
* 3 write combination\(s\) that the policy allows were not exercised by design: write checks send only requests the policy says must be refused.
