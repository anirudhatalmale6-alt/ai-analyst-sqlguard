"""The SQL safety gate.

Contract
--------
Nothing the language model writes is ever sent to a customer database. The
model's output goes into :func:`validate`, which either rejects it with a
reason, or returns a *new* statement that this module re-serialised from the
syntax tree it approved. The executor runs that second string.

The distinction matters: anything that survived parsing but the validator did
not understand - a trailing batch, a comment carrying a second statement, an
encoded payload - simply does not exist in the tree, so it cannot exist in the
string generated from the tree.

Layers, in order:

1. Parse as T-SQL. A parse failure is a rejection, not a fallback to regex.
2. Exactly one statement.
3. The root must be a SELECT (optionally with CTEs) or a set operation.
4. Every node in the tree must be on the policy allowlist (default deny).
5. Every table must be on the tenant's semantic mapping. No other database,
   no linked server, no system catalogue.
6. Every column must belong to a mapped table or be an alias defined in the
   query itself.
7. Re-serialise, and force a row cap.

This module is pure and side-effect free. It opens no sockets and needs no
database, which is what makes the adversarial test suite meaningful.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError, TokenError

from .mapping import TenantMapping
from .policy import (
    DEFAULT_POLICY,
    NAMED_THREATS,
    THREAT_PREFIXES,
    GuardPolicy,
)

DIALECT = "tsql"


class Reject(str, Enum):
    """Machine-readable rejection codes, stored with every audit row."""

    PARSE_ERROR = "parse_error"
    EMPTY = "empty"
    MULTIPLE_STATEMENTS = "multiple_statements"
    NOT_A_SELECT = "not_a_select"
    WRITES_DATA = "writes_data"
    SELECT_INTO = "select_into"
    FORBIDDEN_NODE = "forbidden_node"
    FORBIDDEN_FUNCTION = "forbidden_function"
    TABLE_HINT = "table_hint"
    VARIABLE = "variable"
    STAR_NOT_ALLOWED = "star_not_allowed"
    UNKNOWN_TABLE = "unknown_table"
    UNKNOWN_COLUMN = "unknown_column"
    CROSS_DATABASE = "cross_database"
    TOO_MANY_JOINS = "too_many_joins"
    TOO_DEEP = "too_deep"
    REWRITE_FAILED = "rewrite_failed"


#: Statement types that write. Listed explicitly so the audit log names the
#: actual threat; the allowlist in :mod:`policy` would reject them anyway.
_WRITE_STATEMENTS = (
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Merge,
    exp.Drop,
    exp.Create,
    exp.Alter,
    exp.TruncateTable,
    exp.Grant,
)

_ROOT_TYPES = (exp.Select, exp.Union, exp.Except, exp.Intersect, exp.Subquery)


@dataclass(frozen=True)
class GuardResult:
    allowed: bool
    #: The statement to execute. Re-generated from the approved tree, never
    #: the model's original string. ``None`` when rejected.
    sql: str | None = None
    code: Reject | None = None
    reason: str | None = None
    tables: tuple[str, ...] = ()
    columns: tuple[str, ...] = ()
    row_cap: int | None = None
    original_sql: str = ""

    def __bool__(self) -> bool:  # pragma: no cover - convenience only
        return self.allowed


def _deny(code: Reject, reason: str, original: str) -> GuardResult:
    return GuardResult(
        allowed=False, code=code, reason=reason, original_sql=original
    )


def _strip_code_fence(sql: str) -> str:
    """LLMs like to answer in markdown. Unwrap it before parsing."""
    text = sql.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text


def _qualified(table: exp.Table) -> str:
    parts = [p for p in (table.catalog, table.db, table.name) if p]
    return ".".join(parts).lower()


def _local_names(tree: exp.Expression) -> frozenset[str]:
    """Names the query defines for itself: CTEs, table aliases, output aliases.

    These are legitimate identifiers that will not appear in the tenant
    mapping. Collecting them is what lets ``ORDER BY total`` work while
    ``SELECT secret_column`` still fails - an alias can only ever rename
    something that already passed the column check.
    """
    names: set[str] = set()
    for node in tree.walk():
        if isinstance(node, exp.CTE):
            if node.alias:
                names.add(node.alias.lower())
            for col in node.args.get("columns") or []:
                names.add(col.name.lower())
        elif isinstance(node, exp.TableAlias):
            if node.name:
                names.add(node.name.lower())
            for col in node.args.get("columns") or []:
                names.add(col.name.lower())
        elif isinstance(node, exp.Alias):
            if node.alias:
                names.add(node.alias.lower())
    return frozenset(names)


def _depth(node: exp.Expression, current: int = 0, limit: int = 100) -> int:
    if current > limit:
        return current
    deepest = current
    for child in node.args.values():
        for item in child if isinstance(child, list) else [child]:
            if isinstance(item, exp.Expression):
                deepest = max(deepest, _depth(item, current + 1, limit))
                if deepest > limit:
                    return deepest
    return deepest


def _check_function(
    node: exp.Anonymous, policy: GuardPolicy, original: str
) -> GuardResult | None:
    """Name-based check for functions sqlglot leaves as generic nodes."""
    name = (node.name or "").lower()
    if name in NAMED_THREATS or name.startswith(THREAT_PREFIXES):
        return _deny(
            Reject.FORBIDDEN_FUNCTION,
            f"{node.name} is a system, extended or remote-access procedure "
            "and is never permitted",
            original,
        )
    if name not in policy.allowed_functions:
        return _deny(
            Reject.FORBIDDEN_FUNCTION,
            f"function {node.name} is not on the allowlist",
            original,
        )
    return None


def validate(
    sql: str,
    mapping: TenantMapping,
    policy: GuardPolicy = DEFAULT_POLICY,
) -> GuardResult:
    """Validate model-generated SQL against one tenant's allowlist."""

    original = sql
    text = _strip_code_fence(sql)

    if not text.strip():
        return _deny(Reject.EMPTY, "empty statement", original)

    # ---- 1. parse -------------------------------------------------------
    try:
        statements = [s for s in sqlglot.parse(text, dialect=DIALECT) if s]
    except (ParseError, TokenError) as err:
        first = str(err).splitlines()[0]
        return _deny(
            Reject.PARSE_ERROR,
            f"could not be parsed as T-SQL: {first}",
            original,
        )

    # ---- 2. exactly one statement ---------------------------------------
    if not statements:
        return _deny(Reject.EMPTY, "no statement found", original)
    if len(statements) > 1:
        kinds = ", ".join(type(s).__name__.upper() for s in statements)
        return _deny(
            Reject.MULTIPLE_STATEMENTS,
            f"{len(statements)} statements in one request ({kinds}); "
            "only a single SELECT may be executed",
            original,
        )

    tree = statements[0]

    # ---- 3. root must be a read ----------------------------------------
    if isinstance(tree, _WRITE_STATEMENTS):
        return _deny(
            Reject.WRITES_DATA,
            f"{type(tree).__name__.upper()} modifies the database; "
            "only SELECT is permitted",
            original,
        )
    if not isinstance(tree, _ROOT_TYPES):
        return _deny(
            Reject.NOT_A_SELECT,
            f"statement type {type(tree).__name__.upper()} is not a SELECT",
            original,
        )

    if _depth(tree, limit=policy.max_depth + 1) > policy.max_depth:
        return _deny(
            Reject.TOO_DEEP,
            f"query nests deeper than {policy.max_depth} levels",
            original,
        )

    local = _local_names(tree)
    allowed_tables = mapping.table_names
    allowed_columns = mapping.column_names
    tenant_db = (mapping.database or "").lower()

    seen_tables: set[str] = set()
    seen_columns: set[str] = set()
    joins = 0

    # ---- 4-5. walk every node: structure, functions, tables -------------
    #
    # Columns are checked in a second pass below. The order is deliberate: a
    # query against an unmapped table should be rejected as UNKNOWN_TABLE, not
    # as "unknown column", because the table is the real finding and that is
    # what lands in the audit log.
    for node in tree.walk():
        node_type = type(node)

        # SELECT ... INTO creates a table. It is a write dressed as a read.
        if isinstance(node, exp.Select) and node.args.get("into"):
            return _deny(
                Reject.SELECT_INTO,
                "SELECT ... INTO creates a table; it is a write operation",
                original,
            )

        if isinstance(node, exp.Table) and node.args.get("hints"):
            return _deny(
                Reject.TABLE_HINT,
                "table hints are not permitted (they can take locks on the "
                "customer's production tables)",
                original,
            )

        # @variables, @@SERVERNAME and friends.
        if isinstance(node, (exp.Parameter, exp.SessionParameter, exp.Placeholder)):
            return _deny(
                Reject.VARIABLE,
                "variables and session parameters are not permitted",
                original,
            )

        # Functions sqlglot does not model get checked by name.
        if isinstance(node, exp.Anonymous):
            denial = _check_function(node, policy, original)
            if denial is not None:
                return denial
            continue

        if isinstance(node, exp.Join):
            joins += 1
            if joins > policy.max_joins:
                return _deny(
                    Reject.TOO_MANY_JOINS,
                    f"{joins} joins exceeds the limit of {policy.max_joins}",
                    original,
                )

        if isinstance(node, exp.Star):
            if not policy.allow_star and not isinstance(node.parent, exp.Count):
                return _deny(
                    Reject.STAR_NOT_ALLOWED,
                    "SELECT * is not permitted; it would return columns the "
                    "tenant never mapped. Name the columns explicitly",
                    original,
                )
            continue

        if node_type not in policy.allowed_nodes:
            return _deny(
                Reject.FORBIDDEN_NODE,
                f"{node_type.__name__.upper()} is not permitted in a "
                "read-only analytical query",
                original,
            )

        # ---- tables -----------------------------------------------------
        if isinstance(node, exp.Table):
            # A table function such as OPENROWSET(...) parses as a Table
            # wrapping a function, so it is reported as a function, not as a
            # mystery table source.
            if isinstance(node.this, exp.Anonymous):
                denial = _check_function(node.this, policy, original)
                if denial is not None:
                    return denial

            if isinstance(node.this, exp.Dot):
                return _deny(
                    Reject.CROSS_DATABASE,
                    f"'{_qualified(node)}' has more than two name parts, which "
                    "means a linked server or another database",
                    original,
                )
            if not isinstance(node.this, exp.Identifier):
                return _deny(
                    Reject.FORBIDDEN_NODE,
                    f"{type(node.this).__name__.upper()} cannot be used as a "
                    "table source",
                    original,
                )

            # sqlglot fills `catalog` with the left-most part, which in T-SQL
            # is the database (or the linked server, in a four-part name).
            if node.catalog and node.catalog.lower() != tenant_db:
                return _deny(
                    Reject.CROSS_DATABASE,
                    f"'{_qualified(node)}' names another database or a linked "
                    "server; the connection is pinned to a single database",
                    original,
                )

            name = ".".join(
                p.lower() for p in (node.db, node.name) if p
            )

            # A CTE or derived table defined in this query.
            if name in local:
                continue

            if name.startswith(THREAT_PREFIXES) or name.startswith(
                ("information_schema.", "sys.")
            ):
                return _deny(
                    Reject.UNKNOWN_TABLE,
                    f"'{name}' is a system catalogue and is not queryable",
                    original,
                )

            if name not in allowed_tables:
                return _deny(
                    Reject.UNKNOWN_TABLE,
                    f"'{name}' is not in this tenant's semantic mapping",
                    original,
                )
            seen_tables.add(name)

    if not seen_tables:
        return _deny(
            Reject.UNKNOWN_TABLE,
            "the query reads no mapped table",
            original,
        )

    # ---- 6. second pass: every column must be mapped or locally defined --
    for node in tree.find_all(exp.Column):
        if isinstance(node.this, exp.Star):
            # `t.*`. Already decided in the first pass.
            continue
        col = node.name.lower()
        qualifier = (node.table or "").lower()

        if qualifier and qualifier not in local and qualifier not in allowed_tables:
            return _deny(
                Reject.UNKNOWN_TABLE,
                f"'{node.table}' is not a mapped table or a known alias",
                original,
            )
        if col not in allowed_columns and col not in local:
            where = f"{node.table}.{node.name}" if node.table else node.name
            return _deny(
                Reject.UNKNOWN_COLUMN,
                f"column '{where}' is not in this tenant's semantic mapping",
                original,
            )
        seen_columns.add(col)

    # ---- 7. re-serialise and cap ---------------------------------------
    try:
        capped = _apply_row_cap(tree, policy.max_rows)
        safe_sql = capped.sql(dialect=DIALECT, comments=False)
    except Exception as err:  # pragma: no cover - defensive
        return _deny(
            Reject.REWRITE_FAILED,
            f"approved tree could not be re-serialised: {err}",
            original,
        )

    return GuardResult(
        allowed=True,
        sql=safe_sql,
        tables=tuple(sorted(seen_tables)),
        columns=tuple(sorted(seen_columns)),
        row_cap=policy.max_rows,
        original_sql=original,
    )


def _apply_row_cap(tree: exp.Expression, max_rows: int) -> exp.Expression:
    """Force TOP n onto the statement, clamping anything larger."""
    tree = tree.copy()
    limit = tree.args.get("limit")
    if isinstance(limit, exp.Limit):
        value = limit.expression
        if isinstance(value, exp.Literal) and not value.is_string:
            try:
                requested = int(value.this)
            except ValueError:
                requested = max_rows
            if requested <= max_rows:
                return tree
    return tree.limit(max_rows)


__all__ = ["Reject", "GuardResult", "validate", "DIALECT"]
