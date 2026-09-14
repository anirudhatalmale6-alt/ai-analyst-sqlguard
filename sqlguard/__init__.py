"""sqlguard - the SQL safety gate for an LLM-driven analytics product.

    from sqlguard import TenantMapping, validate

    result = validate(llm_output, mapping)
    if not result.allowed:
        ...  # show the user a refusal, log result.code
    else:
        rows = execute(connection, result)   # runs result.sql, never llm_output
"""

from .mapping import Column, Table, TenantMapping, mapping_from_tables
from .policy import DEFAULT_POLICY, GuardPolicy
from .validator import GuardResult, Reject, validate

__version__ = "0.1.0"

__all__ = [
    "Column",
    "Table",
    "TenantMapping",
    "mapping_from_tables",
    "GuardPolicy",
    "DEFAULT_POLICY",
    "GuardResult",
    "Reject",
    "validate",
    "__version__",
]
