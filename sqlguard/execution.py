"""Read-only execution contract for a customer's SQL Server.

Status: this module is the *pattern*, written out so the whole safety contract
is readable in one repository. It needs a live SQL Server and pyodbc to run, so
unlike :mod:`sqlguard.validator` it is not covered by the test suite in this
repo. It is exercised end to end in the MVP, against the dockerised sample
database. Nothing here is claimed to be proven by `pytest` - the validator is.

The point of the module is the defence that does not depend on my code being
correct: the login itself cannot write.

Provisioning (run once per customer, by the customer's own DBA):

    -- a login that owns nothing and can change nothing
    CREATE LOGIN ai_analyst_ro WITH PASSWORD = '<generated>';
    USE [CustomerSales];
    CREATE USER ai_analyst_ro FOR LOGIN ai_analyst_ro;
    ALTER ROLE db_datareader ADD MEMBER ai_analyst_ro;

    -- belt and braces: deny every write verb at database scope
    DENY INSERT, UPDATE, DELETE, EXECUTE, ALTER, CREATE TABLE,
         CREATE VIEW, CREATE PROCEDURE, BACKUP DATABASE
      TO ai_analyst_ro;

    -- and narrow the read further, to the mapped tables only
    DENY SELECT ON SCHEMA::sys TO ai_analyst_ro;

With that in place a perfect exploit of everything above this line still cannot
modify a row, because permission is checked by SQL Server, not by us.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator, Sequence

from .policy import DEFAULT_POLICY, GuardPolicy
from .validator import GuardResult


@dataclass(frozen=True)
class QueryResult:
    columns: tuple[str, ...]
    rows: tuple[tuple[Any, ...], ...]
    truncated: bool
    elapsed_ms: int


def build_connection_string(
    host: str,
    database: str,
    username: str,
    password: str,
    *,
    port: int = 1433,
    read_only_replica: bool = False,
    timeout: int = 10,
) -> str:
    """ODBC connection string for the per-tenant read-only login.

    `ApplicationIntent=ReadOnly` routes to a secondary replica when the
    customer runs an availability group, so analytical queries never touch the
    box that takes their order traffic.
    """
    parts = [
        "DRIVER={ODBC Driver 18 for SQL Server}",
        f"SERVER={host},{port}",
        f"DATABASE={database}",
        f"UID={username}",
        f"PWD={password}",
        "Encrypt=yes",
        "TrustServerCertificate=no",
        f"Connection Timeout={timeout}",
    ]
    if read_only_replica:
        parts.append("ApplicationIntent=ReadOnly")
    return ";".join(parts)


@contextmanager
def read_only_transaction(connection, policy: GuardPolicy = DEFAULT_POLICY) -> Iterator:
    """Run inside a transaction that is *always* rolled back.

    Even if a write somehow reached the server and the login somehow had
    permission, the rollback undoes it. Three independent things would have to
    fail together for a customer row to change.
    """
    cursor = connection.cursor()
    try:
        cursor.execute(f"SET LOCK_TIMEOUT {policy.lock_timeout_ms}")
        cursor.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        connection.autocommit = False
        yield cursor
    finally:
        try:
            connection.rollback()
        finally:
            cursor.close()


def execute(
    connection,
    result: GuardResult,
    policy: GuardPolicy = DEFAULT_POLICY,
) -> QueryResult:
    """Execute an *approved* statement. Refuses anything else."""
    import time

    if not result.allowed or not result.sql:
        raise ValueError(
            "execute() was handed a rejected query; the executor only ever "
            "runs GuardResult.sql produced by validator.validate()"
        )

    started = time.monotonic()
    connection.timeout = policy.query_timeout_seconds
    with read_only_transaction(connection, policy) as cursor:
        cursor.execute(result.sql)
        columns = tuple(c[0] for c in cursor.description or ())
        rows: list[tuple] = []
        # One row beyond the cap, so we can tell the user the answer was
        # truncated instead of silently lying to them.
        for row in cursor.fetchmany(policy.max_rows + 1):
            rows.append(tuple(row))
        truncated = len(rows) > policy.max_rows
        rows = rows[: policy.max_rows]

    return QueryResult(
        columns=columns,
        rows=tuple(rows),
        truncated=truncated,
        elapsed_ms=int((time.monotonic() - started) * 1000),
    )


def redact_for_log(result: GuardResult, rows: Sequence[Sequence[Any]]) -> dict:
    """What goes in the audit table: the SQL and the shape, never the values."""
    return {
        "tenant_allowed": result.allowed,
        "code": result.code.value if result.code else None,
        "reason": result.reason,
        "generated_sql": result.original_sql,
        "executed_sql": result.sql,
        "tables": list(result.tables),
        "row_count": len(rows),
    }


__all__ = [
    "QueryResult",
    "build_connection_string",
    "read_only_transaction",
    "execute",
    "redact_for_log",
]
