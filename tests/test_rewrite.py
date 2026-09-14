"""The rewrite is the part people miss.

Rejecting bad SQL is only half the guarantee. The other half is that the string
we execute is regenerated from the approved tree, so anything the validator did
not look at cannot ride along into the executor.
"""

import sqlglot

from sqlguard import DEFAULT_POLICY, GuardPolicy, TenantMapping, validate
from sqlguard.execution import execute, redact_for_log


def test_row_cap_is_injected(mapping):
    result = validate("SELECT amount FROM dbo.fact_sales", mapping)
    assert result.allowed
    assert f"TOP {DEFAULT_POLICY.max_rows}" in result.sql
    assert result.row_cap == DEFAULT_POLICY.max_rows


def test_existing_small_top_is_kept(mapping):
    result = validate("SELECT TOP 5 amount FROM dbo.fact_sales", mapping)
    assert result.allowed
    assert "TOP 5" in result.sql


def test_oversized_top_is_clamped(mapping):
    result = validate("SELECT TOP 5000000 amount FROM dbo.fact_sales", mapping)
    assert result.allowed
    assert "TOP 5000000" not in result.sql
    assert f"TOP {DEFAULT_POLICY.max_rows}" in result.sql


def test_policy_row_cap_is_honoured(mapping):
    policy = GuardPolicy(max_rows=25)
    result = validate("SELECT amount FROM dbo.fact_sales", mapping, policy)
    assert result.allowed
    assert "TOP 25" in result.sql


def test_executed_sql_is_not_the_model_output(mapping):
    raw = "-- give me everything\nSELECT   amount   FROM dbo.fact_sales"
    result = validate(raw, mapping)
    assert result.allowed
    assert result.sql != raw
    assert "--" not in result.sql, "comments must not survive the rewrite"
    assert result.original_sql == raw


def test_rewritten_sql_reparses_to_the_same_shape(mapping):
    """Round trip: what we execute must itself pass the validator."""
    sql = (
        "SELECT s.store_name, SUM(f.amount) AS total FROM dbo.fact_sales AS f "
        "JOIN dbo.dim_store AS s ON s.store_id = f.store_id GROUP BY s.store_name"
    )
    first = validate(sql, mapping)
    assert first.allowed
    second = validate(first.sql, mapping)
    assert second.allowed, f"rewritten SQL was rejected: {second.reason}"
    assert second.sql == first.sql, "rewrite is not idempotent"


def test_rewritten_sql_is_valid_tsql(mapping):
    for sql in (
        "SELECT amount FROM dbo.fact_sales",
        "SELECT TOP 3 amount FROM dbo.fact_sales ORDER BY amount DESC",
        "SELECT store_name AS l FROM dbo.dim_store UNION ALL "
        "SELECT product_name AS l FROM dbo.dim_product",
    ):
        result = validate(sql, mapping)
        assert result.allowed
        sqlglot.parse_one(result.sql, dialect="tsql")  # raises if malformed


def test_executor_refuses_a_rejected_query(mapping):
    rejected = validate("DROP TABLE dbo.fact_sales", mapping)
    assert not rejected.allowed
    try:
        execute(object(), rejected)
    except ValueError as err:
        assert "rejected" in str(err)
    else:  # pragma: no cover
        raise AssertionError("executor ran a rejected query")


def test_audit_log_records_the_rejection_without_row_data(mapping):
    rejected = validate("SELECT salary FROM dbo.employee_salary", mapping)
    entry = redact_for_log(rejected, [])
    assert entry["tenant_allowed"] is False
    assert entry["code"] == "unknown_table"
    assert entry["executed_sql"] is None
    assert entry["generated_sql"].startswith("SELECT salary")


def test_tables_and_columns_are_reported_for_the_audit_trail(mapping):
    result = validate(
        "SELECT s.store_name, SUM(f.amount) AS total FROM dbo.fact_sales AS f "
        "JOIN dbo.dim_store AS s ON s.store_id = f.store_id GROUP BY s.store_name",
        mapping,
    )
    assert result.allowed
    assert set(result.tables) == {"dbo.fact_sales", "dbo.dim_store"}
    assert "amount" in result.columns and "store_name" in result.columns


def test_mapping_round_trips_through_json(mapping):
    restored = TenantMapping.from_dict(mapping.to_dict())
    assert restored == mapping


def test_prompt_context_contains_no_data(mapping):
    context = mapping.prompt_context()
    assert "fact_sales" in context and "[amount]" in context
    assert "PWD" not in context and "password" not in context.lower()


def test_a_second_tenant_cannot_use_the_first_tenants_tables(mapping):
    """The allowlist is per tenant, so the same SQL fails for another tenant."""
    other = TenantMapping(tenant_id="other", database="OtherSales", tables=())
    sql = "SELECT SUM(amount) AS total FROM dbo.fact_sales"
    assert validate(sql, mapping).allowed
    result = validate(sql, other)
    assert not result.allowed
    assert result.code.value == "unknown_table"


def test_a_rejected_result_is_falsy(mapping):
    """Regression guard.

    GuardResult defines __bool__ so application code can write `if result:`.
    An early version of the validator used `if denial:` on a *rejection*
    object internally, which is falsy - and two extended stored procedures
    sailed straight through. The attack suite caught it. This test keeps the
    semantics nailed down so nobody re-introduces it.
    """
    assert not validate("DROP TABLE dbo.fact_sales", mapping)
    assert validate("SELECT SUM(amount) AS t FROM dbo.fact_sales", mapping)
