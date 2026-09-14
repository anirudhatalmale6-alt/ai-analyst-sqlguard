"""Tenant semantic mapping.

The semantic mapping is the contract between a tenant's business vocabulary
("sales", "store", "category") and the physical tables and columns in that
tenant's Microsoft SQL Server database.

It has two jobs:

1. It is the grounding context handed to the LLM so it can write SQL at all.
2. It is the *allowlist* the validator checks the generated SQL against.

Job 2 is the important one. A query may only touch objects a tenant has
explicitly mapped. Anything else - another schema, another database, a system
view, a column nobody registered - is rejected before execution, which is what
stops an LLM (or a prompt-injected LLM) from wandering out of its lane.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Iterable, Mapping


# Business roles the MVP understands. `other` is for columns that are mapped
# and therefore queryable, but carry no special meaning to the planner.
COLUMN_ROLES = (
    "date",
    "amount",
    "quantity",
    "store",
    "product",
    "category",
    "key",
    "other",
)


@dataclass(frozen=True)
class Column:
    name: str
    role: str = "other"
    description: str = ""

    def __post_init__(self) -> None:
        if self.role not in COLUMN_ROLES:
            raise ValueError(f"unknown column role: {self.role!r}")


@dataclass(frozen=True)
class Table:
    name: str
    schema: str = "dbo"
    columns: tuple[Column, ...] = ()
    description: str = ""

    @property
    def qualified(self) -> str:
        return f"{self.schema.lower()}.{self.name.lower()}"

    @property
    def column_names(self) -> frozenset[str]:
        return frozenset(c.name.lower() for c in self.columns)


@dataclass(frozen=True)
class TenantMapping:
    """Everything one tenant is allowed to query."""

    tenant_id: str
    tables: tuple[Table, ...] = ()
    default_schema: str = "dbo"
    # The single database this tenant's connection is pinned to. A query that
    # names any other database (or a linked server) is rejected.
    database: str | None = None
    notes: str = ""

    # -- allowlists used by the validator ---------------------------------

    @property
    def table_names(self) -> frozenset[str]:
        """Both `schema.table` and bare `table` forms, lowercased."""
        names: set[str] = set()
        for t in self.tables:
            names.add(t.qualified)
            names.add(t.name.lower())
        return frozenset(names)

    @property
    def schema_names(self) -> frozenset[str]:
        return frozenset(t.schema.lower() for t in self.tables)

    @property
    def column_names(self) -> frozenset[str]:
        names: set[str] = set()
        for t in self.tables:
            names |= t.column_names
        return frozenset(names)

    def table(self, name: str) -> Table | None:
        key = name.lower()
        for t in self.tables:
            if key in (t.qualified, t.name.lower()):
                return t
        return None

    def columns_with_role(self, role: str) -> tuple[tuple[Table, Column], ...]:
        return tuple(
            (t, c) for t in self.tables for c in t.columns if c.role == role
        )

    # -- serialisation ----------------------------------------------------

    @classmethod
    def from_dict(cls, data: Mapping) -> "TenantMapping":
        tables = tuple(
            Table(
                name=t["name"],
                schema=t.get("schema", data.get("default_schema", "dbo")),
                description=t.get("description", ""),
                columns=tuple(
                    Column(
                        name=c["name"],
                        role=c.get("role", "other"),
                        description=c.get("description", ""),
                    )
                    for c in t.get("columns", [])
                ),
            )
            for t in data.get("tables", [])
        )
        return cls(
            tenant_id=data["tenant_id"],
            tables=tables,
            default_schema=data.get("default_schema", "dbo"),
            database=data.get("database"),
            notes=data.get("notes", ""),
        )

    @classmethod
    def from_json(cls, raw: str) -> "TenantMapping":
        return cls.from_dict(json.loads(raw))

    def to_dict(self) -> dict:
        return {
            "tenant_id": self.tenant_id,
            "default_schema": self.default_schema,
            "database": self.database,
            "notes": self.notes,
            "tables": [
                {
                    "name": t.name,
                    "schema": t.schema,
                    "description": t.description,
                    "columns": [
                        {
                            "name": c.name,
                            "role": c.role,
                            "description": c.description,
                        }
                        for c in t.columns
                    ],
                }
                for t in self.tables
            ],
        }

    # -- LLM grounding ----------------------------------------------------

    def prompt_context(self) -> str:
        """Compact schema description for the SQL-generation prompt.

        Note what is *not* here: no data, no row samples, no credentials. The
        model that writes the SQL never sees customer rows.
        """
        lines: list[str] = []
        if self.database:
            lines.append(f"Database: {self.database} (read-only)")
        for t in self.tables:
            head = f"{t.schema}.{t.name}"
            if t.description:
                head += f"  -- {t.description}"
            lines.append(head)
            for c in t.columns:
                bits = [f"  {c.name}", f"[{c.role}]"]
                if c.description:
                    bits.append(f"-- {c.description}")
                lines.append(" ".join(bits))
        return "\n".join(lines)


def mapping_from_tables(tenant_id: str, tables: Iterable[Table]) -> TenantMapping:
    return TenantMapping(tenant_id=tenant_id, tables=tuple(tables))


__all__ = [
    "COLUMN_ROLES",
    "Column",
    "Table",
    "TenantMapping",
    "mapping_from_tables",
]
