# sqlguard

The SQL safety gate for an LLM-driven analytics product: the piece that stands
between a language model's output and a customer's Microsoft SQL Server.

This repository exists so the safety argument can be *read and run* rather than
described in a chat window. It is a self-contained slice of the B2B AI Data
Analyst MVP - the part where getting it wrong means someone's production sales
database gets dropped.

```
$ python -m pytest -q
101 passed

$ python scripts/attack_report.py
59 attacks, 25 real questions, 0 unexpected outcomes
```

## The claim

> Nothing a language model writes is ever executed.

The model's output goes into `validate()`, which either rejects it with a
reason, or returns a **new statement re-serialised from the syntax tree it
approved**. The executor runs that second string and refuses anything else.

That is the whole idea, and it is why "the model was tricked into appending a
second statement" is not an interesting attack here: a second statement is not
in the tree, so it is not in the string generated from the tree.

## Seven layers

| # | Layer | Rejects |
|---|-------|---------|
| 1 | Parse as T-SQL | prose, markdown, half-SQL, `WAITFOR DELAY`, `BACKUP DATABASE` |
| 2 | Exactly one statement | `SELECT ...; DROP TABLE ...`, `GO` batches |
| 3 | Root must be a read | `UPDATE`, `DELETE`, `MERGE`, `EXEC`, `DECLARE`, `SHUTDOWN` |
| 4 | Node allowlist (default deny) | `SELECT INTO`, `FOR XML`, `OPTION (MAXDOP)`, hex literals, table hints, `@@VERSION` |
| 5 | Table allowlist, per tenant | unmapped tables, `sys.*`, `information_schema`, other databases, linked servers, `OPENROWSET` |
| 6 | Column allowlist, per tenant | any column nobody mapped, including inside subqueries and CTEs |
| 7 | Re-serialise and cap | comments, anything the validator did not understand; forces `TOP n` |

Layer 4 is the one that matters most. The validator does **not** carry a list
of dangerous things to look for - a blocklist is only ever as good as the last
attack someone thought of. It carries a list of the 91 syntax-tree node types an
analytics question legitimately needs (`sqlguard/policy.py`) and rejects
everything else. Unfamiliar constructs fail closed.

## What the tests actually assert

`tests/test_attacks.py` - 59 hostile inputs. Each one must be rejected **and
rejected for the stated reason**. Asserting only "not allowed" would still pass
if the validator rejected everything, so the reason code is part of every
assertion.

`tests/test_legitimate.py` - 25 queries of the kind "what were my sales
yesterday" and "top 5 stores last month" actually produce. All must pass. A
validator that rejects everything is trivially safe and completely useless;
this file is what stops the safety work quietly destroying the product.

`tests/test_rewrite.py` - the row cap is injected, an oversized `TOP` is
clamped, comments do not survive, the rewritten SQL re-validates unchanged, the
executor refuses a rejected query, and the audit entry records the verdict
without row values.

One of those tests is a regression guard for a real bug this suite caught
during development: `GuardResult.__bool__` returns `allowed`, and an internal
`if denial:` check on a *rejection* object was therefore falsy - which let
`xp_dirtree` and `sp_OACreate` straight through. Two lines, invisible on
review, caught immediately by the attack list.

## The layer that does not depend on my code

Everything above is application logic, and application logic has bugs - see the
paragraph you just read. So it is not the only defence.

The connection the MVP opens uses a per-customer SQL Server login that is a
member of `db_datareader` and nothing else, with `DENY INSERT, UPDATE, DELETE,
EXECUTE, ALTER, CREATE` at database scope, and every statement runs inside a
transaction that is always rolled back (`sqlguard/execution.py`). A perfect
exploit of every layer above still cannot change a row, because permission is
checked by SQL Server rather than by me.

## What is proven here and what is not

Proven by `pytest` in this repo: the validator, the rewrite, the mapping, the
per-tenant allowlist. No database required - `sqlguard/validator.py` is pure
and opens no sockets, which is exactly what makes the adversarial suite
meaningful.

Not proven here: `sqlguard/execution.py` needs a live SQL Server and `pyodbc`,
so it is written out as the pattern rather than covered by tests. It is
exercised end to end in the MVP against the dockerised sample database. I would
rather say that plainly than imply a green test run covers more than it does.

## Where this sits in the product

```
user question
      |
      v
semantic mapping  ---------->  LLM  (sees schema + roles, never customer rows)
      |                          |
      |                          v
      |                    generated SQL
      |                          |
      +----------------->  sqlguard.validate()  --- rejected ---> explain, log,
                                 |                                 do not execute
                            approved tree
                                 |
                           re-serialised SQL  ------> read-only connection,
                                 |                    transaction, rolled back
                                 v
                            capped result rows
                                 |
                                 v
                    LLM (sees only the aggregate) -> answer, table, chart
```

Multi-tenancy note: the allowlist is per tenant, so the *same* SQL that is
approved for tenant A is rejected for tenant B (`test_a_second_tenant_cannot_
use_the_first_tenants_tables`). In the full MVP that is backed by PostgreSQL
row-level security on the SaaS side, so a forgotten `WHERE tenant_id = ...` in
application code cannot leak rows either - the database refuses.

## Running it

```bash
python -m venv .venv && . .venv/bin/activate
pip install sqlglot pytest
python -m pytest -q
python scripts/attack_report.py
```

Python 3.10+. The only runtime dependency is `sqlglot`.

## Using it

```python
from sqlguard import TenantMapping, validate
from sqlguard.execution import execute

mapping = TenantMapping.from_json(open("sample/mapping.json").read())

result = validate(llm_output, mapping)
if not result.allowed:
    log.warning("blocked %s: %s", result.code.value, result.reason)
    return "I can't answer that from the data you've connected."

rows = execute(connection, result)   # runs result.sql, never llm_output
```

## Adding a construct

When a real customer query is rejected for something genuinely safe - a
function or a node type nobody anticipated - the fix is a one-line addition to
`ALLOWED_NODES` or `ALLOWED_ANONYMOUS_FUNCTIONS` in `sqlguard/policy.py`, plus
a case in `tests/test_legitimate.py`. Deliberate, reviewed, and visible in the
diff. That is the point of default-deny: the list only grows on purpose.
