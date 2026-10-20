import uuid
from typing import Any, Dict, List, Optional
from app.firewall.behavior_models import DataSensitivity
from app.firewall.sensitivity import classify_resource_sensitivity
from app.models.schemas import DataProvenance

SENSITIVITY_HIERARCHY = {
    DataSensitivity.PUBLIC.value: 0,
    DataSensitivity.INTERNAL.value: 1,
    DataSensitivity.CONFIDENTIAL.value: 2,
    DataSensitivity.RESTRICTED.value: 3,
}


def create_tool_provenance(
    tool_name: str,
    arguments: Dict[str, Any],
    session_id: Optional[str] = None,
    is_trusted: bool = False,
) -> DataProvenance:
    """Generate a provenance record capturing the origin and sensitivity of a tool invocation."""
    sensitivity = classify_resource_sensitivity(tool_name, arguments)
    resource_id = None

    if tool_name == "file_read":
        resource_id = str(arguments.get("filename", "unknown_file"))
    elif tool_name == "database_read":
        resource_id = str(arguments.get("employee_id", "unknown_employee"))
    elif tool_name == "calculator":
        resource_id = "math_expression"
    elif tool_name == "web_search":
        resource_id = "web_knowledge"
    elif tool_name == "send_email":
        resource_id = f"email:{arguments.get('recipient', 'unknown')}"

    # Determine disclosure permission requirement
    req_permission = None
    if sensitivity == DataSensitivity.RESTRICTED:
        req_permission = "disclose:restricted"
    elif sensitivity == DataSensitivity.CONFIDENTIAL:
        req_permission = "disclose:confidential"
    elif sensitivity == DataSensitivity.INTERNAL:
        req_permission = "disclose:internal"

    return DataProvenance(
        provenance_id=str(uuid.uuid4()),
        source_tool=tool_name,
        source_resource=resource_id,
        session_id=session_id,
        sensitivity=sensitivity.value,
        required_permission=req_permission,
        is_trusted=is_trusted,
        disclosure_policy=f"requires_{req_permission}" if req_permission else "open",
    )


def elevate_provenance(
    provenances: List[DataProvenance],
    default_session: Optional[str] = None,
) -> DataProvenance:
    """Propagate the highest observed sensitivity across multiple provenance records.
    Enforces the security invariant: sensitivity cannot be downgraded merely by summarization.
    """
    if not provenances:
        return DataProvenance(
            provenance_id=str(uuid.uuid4()),
            session_id=default_session,
            sensitivity=DataSensitivity.PUBLIC.value,
            is_trusted=True,
            disclosure_policy="open",
        )

    highest_rank = -1
    highest_prov = provenances[0]

    for prov in provenances:
        rank = SENSITIVITY_HIERARCHY.get(prov.sensitivity, 0)
        if rank > highest_rank:
            highest_rank = rank
            highest_prov = prov

    return DataProvenance(
        provenance_id=str(uuid.uuid4()),
        source_tool=highest_prov.source_tool,
        source_resource=highest_prov.source_resource,
        session_id=default_session or highest_prov.session_id,
        sensitivity=highest_prov.sensitivity,
        required_permission=highest_prov.required_permission,
        is_trusted=all(p.is_trusted for p in provenances),
        disclosure_policy=highest_prov.disclosure_policy,
    )
