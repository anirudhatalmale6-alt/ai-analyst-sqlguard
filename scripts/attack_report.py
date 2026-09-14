#!/usr/bin/env python3
"""Print the whole adversarial suite and what the validator did with each case.

    python scripts/attack_report.py

No database needed. This is the same list the test suite asserts on - the
script just renders it so you can read the verdicts without running pytest.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

# sqlglot logs a warning when it meets T-SQL it cannot model. That is a
# rejection for us, not a problem, so keep the report clean.
logging.getLogger("sqlglot").setLevel(logging.ERROR)

from sqlguard import Column, Table, TenantMapping, validate  # noqa: E402
from test_attacks import ATTACKS  # noqa: E402
from test_legitimate import QUERIES  # noqa: E402


MAPPING = TenantMapping(
    tenant_id="acme",
    database="CustomerSales",
    tables=(
        Table(
            "fact_sales",
            "dbo",
            (
                Column("sale_id", "key"),
                Column("sale_date", "date"),
                Column("amount", "amount"),
                Column("quantity", "quantity"),
                Column("store_id", "key"),
                Column("product_id", "key"),
            ),
        ),
        Table(
            "dim_store",
            "dbo",
            (
                Column("store_id", "key"),
                Column("store_name", "store"),
                Column("region", "other"),
            ),
        ),
        Table(
            "dim_product",
            "dbo",
            (
                Column("product_id", "key"),
                Column("product_name", "product"),
                Column("category", "category"),
            ),
        ),
    ),
)

GREEN = "\033[32m"
RED = "\033[31m"
DIM = "\033[2m"
OFF = "\033[0m"


def main() -> int:
    failures = 0

    print()
    print("TENANT MAPPING (the allowlist)")
    print("-" * 78)
    print(MAPPING.prompt_context())

    print()
    print("ATTACKS - every one of these must be rejected")
    print("-" * 78)
    for label, sql, _expected in ATTACKS:
        result = validate(sql, MAPPING)
        if result.allowed:
            failures += 1
            print(f"{RED}ALLOWED{OFF}  {label}")
            print(f"         {DIM}{sql}{OFF}")
            print(f"         would execute: {result.sql}")
        else:
            print(f"{GREEN}blocked{OFF}  {label:<48} {result.code.value}")
            print(f"         {DIM}{result.reason}{OFF}")

    print()
    print("REAL QUESTIONS - every one of these must be allowed")
    print("-" * 78)
    for label, sql in QUERIES:
        result = validate(sql, MAPPING)
        if not result.allowed:
            failures += 1
            print(f"{RED}REJECTED{OFF} {label}: {result.reason}")
        else:
            print(f"{GREEN}allowed{OFF}  {label}")
            print(f"         {DIM}executes: {result.sql}{OFF}")

    print()
    print("-" * 78)
    print(
        f"{len(ATTACKS)} attacks, {len(QUERIES)} real questions, "
        f"{failures} unexpected outcomes"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
