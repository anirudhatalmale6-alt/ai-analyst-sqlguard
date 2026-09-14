import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlguard import Column, Table, TenantMapping  # noqa: E402


@pytest.fixture(scope="session")
def mapping() -> TenantMapping:
    """A small sales star schema, the way a tenant would map it in the UI.

    Note what is deliberately absent: dbo.employee_salary exists in the
    customer's database but was never mapped, so it must be unreachable.
    """
    return TenantMapping(
        tenant_id="acme",
        database="CustomerSales",
        tables=(
            Table(
                name="fact_sales",
                schema="dbo",
                description="one row per sales line",
                columns=(
                    Column("sale_id", "key"),
                    Column("sale_date", "date"),
                    Column("amount", "amount"),
                    Column("quantity", "quantity"),
                    Column("store_id", "key"),
                    Column("product_id", "key"),
                ),
            ),
            Table(
                name="dim_store",
                schema="dbo",
                columns=(
                    Column("store_id", "key"),
                    Column("store_name", "store"),
                    Column("region", "other"),
                ),
            ),
            Table(
                name="dim_product",
                schema="dbo",
                columns=(
                    Column("product_id", "key"),
                    Column("product_name", "product"),
                    Column("category", "category"),
                ),
            ),
        ),
    )
