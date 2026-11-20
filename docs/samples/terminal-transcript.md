# Terminal transcript (not a screencast)

The commands below were run, in this order, in a fresh clone of boundarycheck (`git clone --recurse-submodules`,
`uv sync`), and the output is pasted as it was printed (stdout and stderr together, long lines cut at 220
characters). Nothing was edited. It is a transcript, not a recording: it has no timing.

```text
$ uv run boundarycheck test --config examples/lab.yaml --transport fixture --runs-dir runs
boundarycheck 0.1.0.dev0 | scope lab-demo | transport fixture:tenant-boundary-lab:patched
cases: no_issue_observed: 419, finding_candidate: 0, policy_denied: 0, not_run: 0, incomplete: 0, error: 0, inconclusive: 0 (total 419)
  note: 7 write combination(s) that the policy allows were not exercised by design: write checks send only requests the policy says must be refused.
run 20261120T100544Z-bd9f8f34 saved to ../samples/runs/20261120T100544Z-bd9f8f34
exit code 0. Note: no_issue_observed does not mean the target is secure.
exit 0

$ uv run boundarycheck test --config examples/lab-vulnerable.yaml --transport fixture --fixture-flaws ROLE_CHECK_MISSING --runs-dir runs
DELIBERATELY VULNERABLE LAB: local only, synthetic data, never deploy. flaws=ROLE_CHECK_MISSING
boundarycheck 0.1.0.dev0 | scope lab-vulnerable-demo | transport fixture:tenant-boundary-lab:vulnerable(ROLE_CHECK_MISSING)
cases: no_issue_observed: 281, finding_candidate: 5, policy_denied: 0, not_run: 0, incomplete: 0, error: 0, inconclusive: 0 (total 286)
  FINDING BC-0067 BC-ROLE-01 [high] bob:contact.private.read:PA1: expected deny_forbidden (role_denied), observed allow (HTTP 200): access was granted where the policy denies it
  FINDING BC-0076 BC-ROLE-01 [high] bob:project.write:PA1: expected deny_forbidden (role_denied), observed allow (HTTP 200): access was granted where the policy denies it; state changed: projects:500000000000400080000...
  FINDING BC-0120 BC-ROLE-01 [high] dave:contact.private.read:PA1: expected deny_forbidden (role_denied), observed allow (HTTP 200): access was granted where the policy denies it
  FINDING BC-0122 BC-ROLE-01 [high] dave:contact.private.read:PB1: expected deny_forbidden (role_denied), observed allow (HTTP 200): access was granted where the policy denies it
  FINDING BC-0130 BC-ROLE-01 [high] dave:project.write:PB1: expected deny_forbidden (role_denied), observed allow (HTTP 200): access was granted where the policy denies it; state changed: projects:50000000000040008000...
  note: 3 write combination(s) that the policy allows were not exercised by design: write checks send only requests the policy says must be refused.
run 20261120T100545Z-10368255 saved to ../samples/runs/20261120T100545Z-10368255
exit code 1. Note: no_issue_observed does not mean the target is secure.
exit 1

$ uv run boundarycheck test --config examples/lab-vulnerable.yaml --transport fixture --fixture-flaws WRITE_BEFORE_AUTHORIZATION --runs-dir runs
DELIBERATELY VULNERABLE LAB: local only, synthetic data, never deploy. flaws=WRITE_BEFORE_AUTHORIZATION
boundarycheck 0.1.0.dev0 | scope lab-vulnerable-demo | transport fixture:tenant-boundary-lab:vulnerable(WRITE_BEFORE_AUTHORIZATION)
cases: no_issue_observed: 265, finding_candidate: 21, policy_denied: 0, not_run: 0, incomplete: 0, error: 0, inconclusive: 0 (total 286)
  FINDING BC-0050 BC-MUTATION-01 [high] alice:project.write:PA2: the request was not accepted (HTTP 404) but state changed: projects:50000000000040008000000000000002 (modified)
  FINDING BC-0051 BC-MUTATION-01 [high] alice:project.write:PB1: the request was not accepted (HTTP 404) but state changed: projects:50000000000040008000000000000003 (modified)
  FINDING BC-0052 BC-MUTATION-01 [high] alice:project.write:PC1: the request was not accepted (HTTP 404) but state changed: projects:50000000000040008000000000000004 (modified)
  FINDING BC-0076 BC-MUTATION-01 [high] bob:project.write:PA1: the request was not accepted (HTTP 403) but state changed: projects:50000000000040008000000000000001 (modified)
  FINDING BC-0077 BC-MUTATION-01 [high] bob:project.write:PA2: the request was not accepted (HTTP 404) but state changed: projects:50000000000040008000000000000002 (modified)
  FINDING BC-0078 BC-MUTATION-01 [high] bob:project.write:PB1: the request was not accepted (HTTP 404) but state changed: projects:50000000000040008000000000000003 (modified)
  FINDING BC-0079 BC-MUTATION-01 [high] bob:project.write:PC1: the request was not accepted (HTTP 404) but state changed: projects:50000000000040008000000000000004 (modified)
  FINDING BC-0103 BC-MUTATION-01 [high] carla:project.write:PA1: the request was not accepted (HTTP 404) but state changed: projects:50000000000040008000000000000001 (modified)
  FINDING BC-0104 BC-MUTATION-01 [high] carla:project.write:PA2: the request was not accepted (HTTP 404) but state changed: projects:50000000000040008000000000000002 (modified)
  FINDING BC-0105 BC-MUTATION-01 [high] carla:project.write:PC1: the request was not accepted (HTTP 404) but state changed: projects:50000000000040008000000000000004 (modified)
  FINDING BC-0129 BC-MUTATION-01 [high] dave:project.write:PA2: the request was not accepted (HTTP 404) but state changed: projects:50000000000040008000000000000002 (modified)
  FINDING BC-0130 BC-MUTATION-01 [high] dave:project.write:PB1: the request was not accepted (HTTP 403) but state changed: projects:50000000000040008000000000000003 (modified)
  FINDING BC-0131 BC-MUTATION-01 [high] dave:project.write:PC1: the request was not accepted (HTTP 404) but state changed: projects:50000000000040008000000000000004 (modified)
  FINDING BC-0182 BC-MUTATION-01 [high] frank:project.write:PA1: the request was not accepted (HTTP 404) but state changed: projects:50000000000040008000000000000001 (modified)
  FINDING BC-0183 BC-MUTATION-01 [high] frank:project.write:PA2: the request was not accepted (HTTP 404) but state changed: projects:50000000000040008000000000000002 (modified)
  FINDING BC-0184 BC-MUTATION-01 [high] frank:project.write:PB1: the request was not accepted (HTTP 404) but state changed: projects:50000000000040008000000000000003 (modified)
  FINDING BC-0185 BC-MUTATION-01 [high] frank:project.write:PC1: the request was not accepted (HTTP 404) but state changed: projects:50000000000040008000000000000004 (modified)
  FINDING BC-0209 BC-MUTATION-01 [high] gina:project.write:PA1: the request was not accepted (HTTP 404) but state changed: projects:50000000000040008000000000000001 (modified)
  FINDING BC-0210 BC-MUTATION-01 [high] gina:project.write:PA2: the request was not accepted (HTTP 404) but state changed: projects:50000000000040008000000000000002 (modified)
  FINDING BC-0211 BC-MUTATION-01 [high] gina:project.write:PB1: the request was not accepted (HTTP 404) but state changed: projects:50000000000040008000000000000003 (modified)
  FINDING BC-0212 BC-MUTATION-01 [high] gina:project.write:PC1: the request was not accepted (HTTP 403) but state changed: projects:50000000000040008000000000000004 (modified)
  note: 3 write combination(s) that the policy allows were not exercised by design: write checks send only requests the policy says must be refused.
run 20261120T100546Z-76075276 saved to ../samples/runs/20261120T100546Z-76075276
exit code 1. Note: no_issue_observed does not mean the target is secure.
exit 1

$ uv run boundarycheck test --config examples/lab-vulnerable.yaml --transport fixture --fixture-flaws WRITE_BEFORE_AUTHORIZATION --reads-only --runs-dir runs
DELIBERATELY VULNERABLE LAB: local only, synthetic data, never deploy. flaws=WRITE_BEFORE_AUTHORIZATION
boundarycheck 0.1.0.dev0 | scope lab-vulnerable-demo | transport fixture:tenant-boundary-lab:vulnerable(WRITE_BEFORE_AUTHORIZATION)
cases: no_issue_observed: 249, finding_candidate: 0, policy_denied: 0, not_run: 0, incomplete: 0, error: 0, inconclusive: 0 (total 249)
  note: --reads-only: 37 write case(s) were left out at the operator's request; write-path authorization was not tested in this run.
run 20261120T100547Z-c86cf039 saved to ../samples/runs/20261120T100547Z-c86cf039
exit code 0. Note: no_issue_observed does not mean the target is secure.
exit 0

```
