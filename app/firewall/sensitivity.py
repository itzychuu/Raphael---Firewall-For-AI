import re
from typing import Any, Dict
from app.firewall.behavior_models import DataSensitivity

# Predefined sensitivity for mock files
FILE_SENSITIVITY: Dict[str, DataSensitivity] = {
    "public_report.txt": DataSensitivity.PUBLIC,
    "instructions.txt": DataSensitivity.INTERNAL,
    "confidential.txt": DataSensitivity.CONFIDENTIAL,
}

SSN_REGEX = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
API_KEY_REGEX = re.compile(r"(?i)(api[_-]?key|secret|token)")


def classify_resource_sensitivity(tool_name: str, arguments: Dict[str, Any]) -> DataSensitivity:
    """Classify the sensitivity of a resource targeted by a tool invocation."""
    if tool_name == "calculator" or tool_name == "web_search":
        return DataSensitivity.PUBLIC

    if tool_name == "file_read":
        filename = str(arguments.get("filename", "")).lower()
        if "confidential" in filename:
            return DataSensitivity.CONFIDENTIAL
        return FILE_SENSITIVITY.get(filename, DataSensitivity.INTERNAL)

    if tool_name == "database_read":
        # Database employee records contain salary (CONFIDENTIAL) and SSN (RESTRICTED)
        return DataSensitivity.CONFIDENTIAL

    if tool_name == "send_email":
        # Check message body or recipient for sensitivity
        message = str(arguments.get("message", ""))
        return classify_content_sensitivity(message)

    return DataSensitivity.INTERNAL


def classify_content_sensitivity(content: str) -> DataSensitivity:
    """Examine content strings for indicators of sensitive or restricted data."""
    if not content:
        return DataSensitivity.PUBLIC

    if SSN_REGEX.search(content):
        return DataSensitivity.RESTRICTED

    if API_KEY_REGEX.search(content) or "CONFIDENTIAL" in content:
        return DataSensitivity.CONFIDENTIAL

    return DataSensitivity.INTERNAL
