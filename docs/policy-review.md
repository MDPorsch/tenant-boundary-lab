# Policy review (milestone M6)

The spec asks for a human policy review before the release. This page is what to review: the policy
the lab enforces, the decisions that shaped it, and what is still waiting for you. It is generated from
the oracle data (`src/tenantlab/oracle/data/capabilities.csv`), not retyped, and a test compares the
application's own table with that file.

## 1. The authorization policy (what the lab enforces)

Roles in one tenant: `owner`, `admin`, `editor`, `viewer`. A caller must be an **active** member of the
tenant that owns the target (otherwise the answer is 404, never 403, so existence is not revealed), the
tenant must be active, the target's market must be one the tenant may use, and only then is the role
checked against this matrix:

| Operation | owner | admin | editor | viewer |
|---|---|---|---|---|
| `tenant.context.read` | Y | Y | Y | Y |
| `project.list` | Y | Y | Y | Y |
| `project.read` | Y | Y | Y | Y |
| `project.create` | Y | Y | Y | N |
| `project.write` | Y | Y | Y | N |
| `invoice.read` | Y | Y | Y | Y |
| `contact.private.read` | Y | Y | N | N |
| `member.role.write` | Y | N | N | N |
| `audit.read` | Y | Y | N | N |

Rules around the matrix (each is a decision in `DECISIONS.md`):

* **Ownership of a row grants nothing** (D-04). A revoked member who owns a project reads nothing.
* **Market scope comes before role** (D-05): a project in a market the tenant may not use looks missing.
* **Every "not visible" case is one response** (D-06, D-40): a hidden, a foreign, a revoked and a missing
  target answer identically and do the same database work.
* **A suspended tenant refuses its members with 403** and answers non-members 404 (D-07).
* **A disabled principal is refused before any object is looked at** (403).
* **Fail closed**: a database error is 503, never a pass (D-28), and a write that keeps losing a race is
  503 (D-38).
* **Private contact data** is visible to `admin` and `owner` only, in the dedicated route, never in the
  general project JSON (TL-09).
* **The last owner cannot leave** (TL-11), including when two owners try at once (M5, D-56).

## 2. Approvals, as recorded

| Milestone | Decisions needing approval | Status |
|---|---|---|
| M0, M1, M2 | D-03, D-04, D-05, D-06, D-24 to D-26, D-28, D-31, D-32, D-34, D-37, D-38 and the rest marked **Yes** up to D-40 | Approved with the milestone (you approved M0, M1 and M2); D-40 approved explicitly |
| M3 | D-41, D-43, D-44, D-46, D-48 (the isolation review) | **Approved 2026-11-20** |
| Licence | D-16 (Apache-2.0) | **Confirmed 2026-11-20**; copyright holder named in `NOTICE` |
| M4 | **D-53**: the fifth flaw in the vulnerable lab | **Approved 2026-11-20** |
| M5 | **D-58**: the sweep and properties use one checker with no application code | Needed no approval; the owner also approved it 2026-11-20 |
| M5 | **D-56**: authority locks, per-tenant serialisation of creates and role changes | **Approved 2026-11-20** |

## 3. What a reviewer should challenge

1. **Hidden objects answer 404 even to members** (market scope). Is that the intended product behaviour,
   or should a member be told "not available in your market"?
2. **Role changes and creates serialise per tenant** (D-56). Is the throughput cost acceptable?
3. **Reads keep a check-then-use window** (L-16). Do you want it closed before anything relies on this?
4. **The audit table is append-only by convention** (L-17). A trigger would enforce it.
5. **The vulnerable lab's isolation is the author's own work**, tested and mutation-tested, not audited
   by a third party (`docs/vulnerable-lab.md` s4). Run it in the container.
