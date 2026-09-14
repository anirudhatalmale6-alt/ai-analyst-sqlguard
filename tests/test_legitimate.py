"""The other half of the job.

A validator that rejects everything is trivially safe and completely useless.
These are the shapes a sales question actually produces - "what were my sales
yesterday", "top 5 stores last month", "which categories grew" - and all of
them must pass.
"""

import pytest

from sqlguard import validate

QUERIES = [
    (
        "sales yesterday",
        "SELECT SUM(amount) AS total FROM dbo.fact_sales "
        "WHERE sale_date = CAST(DATEADD(day, -1, GETDATE()) AS date)",
    ),
    (
        "row count",
        "SELECT COUNT(*) AS n FROM dbo.fact_sales",
    ),
    (
        "top stores last month",
        "SELECT TOP 5 s.store_name, SUM(f.amount) AS total "
        "FROM dbo.fact_sales AS f "
        "JOIN dbo.dim_store AS s ON s.store_id = f.store_id "
        "WHERE f.sale_date >= DATEADD(month, -1, GETDATE()) "
        "GROUP BY s.store_name ORDER BY total DESC",
    ),
    (
        "daily series for a chart",
        "SELECT CAST(sale_date AS date) AS day, SUM(amount) AS total "
        "FROM dbo.fact_sales GROUP BY CAST(sale_date AS date) ORDER BY day",
    ),
    (
        "category breakdown",
        "SELECT p.category, SUM(f.amount) AS total, SUM(f.quantity) AS units "
        "FROM dbo.fact_sales AS f "
        "JOIN dbo.dim_product AS p ON p.product_id = f.product_id "
        "GROUP BY p.category HAVING SUM(f.amount) > 0 ORDER BY total DESC",
    ),
    (
        "average basket",
        "SELECT AVG(amount) AS avg_amount, MIN(amount) AS lowest, "
        "MAX(amount) AS highest FROM dbo.fact_sales",
    ),
    (
        "cte for a month-on-month comparison",
        "WITH monthly AS ("
        "  SELECT DATEPART(month, sale_date) AS m, SUM(amount) AS total "
        "  FROM dbo.fact_sales GROUP BY DATEPART(month, sale_date)"
        ") SELECT m, total FROM monthly ORDER BY m",
    ),
    (
        "three table join",
        "SELECT s.region, p.category, SUM(f.amount) AS total "
        "FROM dbo.fact_sales AS f "
        "JOIN dbo.dim_store AS s ON s.store_id = f.store_id "
        "JOIN dbo.dim_product AS p ON p.product_id = f.product_id "
        "GROUP BY s.region, p.category",
    ),
    (
        "case expression",
        "SELECT CASE WHEN amount > 100 THEN 'large' ELSE 'small' END AS band, "
        "COUNT(*) AS n FROM dbo.fact_sales GROUP BY "
        "CASE WHEN amount > 100 THEN 'large' ELSE 'small' END",
    ),
    (
        "window function",
        "SELECT p.category, SUM(f.amount) OVER (PARTITION BY p.category) AS total "
        "FROM dbo.fact_sales AS f "
        "JOIN dbo.dim_product AS p ON p.product_id = f.product_id",
    ),
    (
        "unqualified table name",
        "SELECT SUM(amount) AS total FROM fact_sales",
    ),
    (
        "in list",
        "SELECT SUM(f.amount) AS total FROM dbo.fact_sales AS f "
        "JOIN dbo.dim_store AS s ON s.store_id = f.store_id "
        "WHERE s.region IN ('north', 'south')",
    ),
    (
        "between dates",
        "SELECT SUM(amount) AS total FROM dbo.fact_sales "
        "WHERE sale_date BETWEEN '2026-01-01' AND '2026-01-31'",
    ),
    (
        "coalesce and null handling",
        "SELECT ISNULL(SUM(amount), 0) AS total FROM dbo.fact_sales "
        "WHERE store_id IS NOT NULL",
    ),
    (
        "subquery in the from clause",
        "SELECT d.day, d.total FROM ("
        "  SELECT CAST(sale_date AS date) AS day, SUM(amount) AS total "
        "  FROM dbo.fact_sales GROUP BY CAST(sale_date AS date)"
        ") AS d ORDER BY d.total DESC",
    ),
    (
        "union of two mapped tables",
        "SELECT store_name AS label FROM dbo.dim_store "
        "UNION ALL SELECT product_name AS label FROM dbo.dim_product",
    ),
    (
        "convert for date formatting",
        "SELECT CONVERT(varchar, sale_date, 112) AS d, SUM(amount) AS total "
        "FROM dbo.fact_sales GROUP BY CONVERT(varchar, sale_date, 112)",
    ),
    (
        "string_agg",
        "SELECT STRING_AGG(store_name, ', ') AS stores FROM dbo.dim_store",
    ),
    (
        "cross apply",
        "SELECT f.amount FROM dbo.fact_sales AS f "
        "CROSS APPLY (SELECT TOP 1 store_name FROM dbo.dim_store) AS s",
    ),
    (
        "bracket quoted identifiers",
        "SELECT SUM([amount]) AS total FROM [dbo].[fact_sales]",
    ),
    (
        "lowercase keywords and uppercase object names",
        "select sum(amount) as total from DBO.FACT_SALES",
    ),
    (
        "block comment in the middle",
        "SELECT SUM(amount) /* the money column */ AS total FROM dbo.fact_sales",
    ),
    (
        "markdown fenced answer from the model",
        "```sql\nSELECT SUM(amount) AS total FROM dbo.fact_sales\n```",
    ),
    (
        "answer with a trailing semicolon",
        "SELECT SUM(amount) AS total FROM dbo.fact_sales;",
    ),
    (
        "answer with explanatory comments",
        "-- total sales for the period\nSELECT SUM(amount) AS total "
        "FROM dbo.fact_sales",
    ),
]


@pytest.mark.parametrize(
    "label,sql", QUERIES, ids=[q[0] for q in QUERIES]
)
def test_legitimate_query_is_allowed(label, sql, mapping):
    result = validate(sql, mapping)
    assert result.allowed, f"{label}: rejected as {result.code} - {result.reason}"
    assert result.sql, f"{label}: allowed but produced no executable SQL"
    assert result.tables, f"{label}: allowed but recorded no tables"


def test_allowed_queries_only_touch_mapped_tables(mapping):
    for label, sql in QUERIES:
        result = validate(sql, mapping)
        for table in result.tables:
            assert table in mapping.table_names, f"{label}: {table} not mapped"
