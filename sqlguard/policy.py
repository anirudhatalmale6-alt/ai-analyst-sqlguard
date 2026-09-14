"""Validator policy: the node and function allowlists, and the limits.

The design rule here is *default deny*. The validator does not carry a list of
dangerous things to look for - a blocklist is only ever as good as the last
attack someone thought of. It carries a list of the SQL constructs an analytics
question legitimately needs, and rejects every node type that is not on it.

That means an unfamiliar construct fails closed. When a real customer query is
rejected for a construct that is genuinely safe, the fix is to add that node
class here, deliberately, in a commit someone reviewed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlglot import exp


# --------------------------------------------------------------------------
# Structural nodes an analytical SELECT is allowed to contain.
# --------------------------------------------------------------------------

_STRUCTURE = {
    exp.Select,
    exp.Union,
    exp.Except,
    exp.Intersect,
    exp.With,
    exp.CTE,
    exp.Subquery,
    exp.From,
    exp.Join,
    exp.Where,
    exp.Group,
    exp.Having,
    exp.Order,
    exp.Ordered,
    exp.Limit,
    exp.Offset,
    exp.Distinct,
    exp.Table,
    exp.TableAlias,
    exp.Alias,
    exp.Column,
    exp.Identifier,
    exp.Literal,
    exp.Boolean,
    exp.Null,
    exp.Star,  # only ever reached inside COUNT(*) - see validator
    exp.Paren,
    exp.Tuple,
    exp.Array,
    exp.DataType,
    exp.DataTypeParam,
    exp.Var,
    exp.Window,
    exp.WindowSpec,
    exp.Interval,
    exp.Lateral,  # CROSS APPLY; the tables it references are still checked
}

# --------------------------------------------------------------------------
# Operators.
# --------------------------------------------------------------------------

_OPERATORS = {
    exp.And,
    exp.Or,
    exp.Not,
    exp.EQ,
    exp.NEQ,
    exp.GT,
    exp.GTE,
    exp.LT,
    exp.LTE,
    exp.Is,
    exp.In,
    exp.Between,
    exp.Like,
    exp.ILike,
    exp.Add,
    exp.Sub,
    exp.Mul,
    exp.Div,
    exp.Mod,
    exp.Neg,
    exp.Case,
    exp.If,
    exp.Cast,
    exp.TryCast,
}

# --------------------------------------------------------------------------
# Functions sqlglot models as their own node classes.
# --------------------------------------------------------------------------

_FUNCTIONS = {
    exp.Count,
    exp.Sum,
    exp.Avg,
    exp.Min,
    exp.Max,
    exp.Coalesce,
    exp.Round,
    exp.Abs,
    exp.Ceil,
    exp.Floor,
    exp.Extract,
    exp.DateAdd,
    exp.DateSub,
    exp.DateDiff,
    exp.DateTrunc,
    exp.CurrentDate,
    exp.CurrentTimestamp,
    exp.Concat,
    exp.Substring,
    exp.Upper,
    exp.Lower,
    exp.Trim,
    exp.Length,
    exp.Year,
    exp.Month,
    exp.Day,
    exp.Nullif,
    exp.Stddev,
    exp.Variance,
    exp.Convert,
    exp.GroupConcat,
}

ALLOWED_NODES: frozenset[type] = frozenset(_STRUCTURE | _OPERATORS | _FUNCTIONS)


# Functions sqlglot leaves as a generic `Anonymous` node. These are matched by
# name, case-insensitively. Everything else anonymous is rejected.
ALLOWED_ANONYMOUS_FUNCTIONS: frozenset[str] = frozenset(
    {
        "datepart",
        "datename",
        "eomonth",
        "iif",
        "row_number",
        "rank",
        "dense_rank",
        "ntile",
        "percentile_cont",
        "format",
        "getdate",
        "sysdatetime",
        "cast",
        "convert",
        "left",
        "right",
        "replace",
        "ltrim",
        "rtrim",
        "string_agg",
    }
)

# Named purely so the rejection message says *why* rather than "unknown
# function". Anything here would already be rejected by the allowlist above;
# this list exists so the audit log reads usefully.
NAMED_THREATS: frozenset[str] = frozenset(
    {
        "openrowset",
        "openquery",
        "opendatasource",
        "openxml",
        "xp_cmdshell",
        "xp_dirtree",
        "xp_regread",
        "xp_fileexist",
        "sp_executesql",
        "sp_oacreate",
        "sp_oamethod",
        "sp_addlinkedserver",
        "fn_get_audit_file",
        "fn_trace_gettable",
        "suser_name",
        "system_user",
        "db_name",
        "host_name",
        "pwdencrypt",
        "pwdcompare",
    }
)

# Prefixes that identify SQL Server system / extended stored procedures.
THREAT_PREFIXES: tuple[str, ...] = ("xp_", "sp_", "fn_", "sys.")


@dataclass(frozen=True)
class GuardPolicy:
    """Execution limits applied to every approved query."""

    # Hard row cap. Injected as TOP n into the rewritten statement.
    max_rows: int = 1000
    # `SELECT *` hides columns the tenant never mapped, so it is off by
    # default. COUNT(*) is unaffected.
    allow_star: bool = False
    # Joins beyond this are almost always a model mistake, and a cartesian
    # product on a customer's production box is a real outage.
    max_joins: int = 8
    # Depth guard against pathological nesting.
    max_depth: int = 40
    # Seconds. Applied by the execution layer, recorded here so the whole
    # contract lives in one object.
    query_timeout_seconds: int = 30
    lock_timeout_ms: int = 5000
    allowed_nodes: frozenset[type] = field(default_factory=lambda: ALLOWED_NODES)
    allowed_functions: frozenset[str] = field(
        default_factory=lambda: ALLOWED_ANONYMOUS_FUNCTIONS
    )


DEFAULT_POLICY = GuardPolicy()


__all__ = [
    "ALLOWED_NODES",
    "ALLOWED_ANONYMOUS_FUNCTIONS",
    "NAMED_THREATS",
    "THREAT_PREFIXES",
    "GuardPolicy",
    "DEFAULT_POLICY",
]
