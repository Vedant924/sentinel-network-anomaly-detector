"""Deterministic tool-call policy engine for AI Guardrail."""

import os
import re
from typing import Any, Dict, List, Optional, Tuple

# Allowed tools registry with typed required arguments
ALLOWED_TOOLS = {
    "search_docs": {
        "description": "Search documentation articles",
        "required_args": {"query": str},
    },
    "read_demo_file": {
        "description": "Read approved demo file from the allowed demo directory",
        "required_args": {"path": str},
    },
    "query_demo_database": {
        "description": "Execute read-only demo SQL queries",
        "required_args": {"sql": str},
    },
}

# Shell command attack patterns: (Rule ID, Risk Level, Description, Pattern)
SHELL_ATTACK_PATTERNS: List[Tuple[str, str, str, re.Pattern]] = [
    (
        "DESTRUCTIVE_COMMAND",
        "CRITICAL",
        "Destructive file or filesystem deletion command",
        re.compile(
            r"\b(?:rm\s+-(?:r|f|rf|fr)|rmdir\s+/s|del\s+/[fqs]|mkfs|format\s+[a-z]:)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "DESTRUCTIVE_COMMAND",
        "CRITICAL",
        "Dangerous permission or ownership modification",
        re.compile(
            r"\b(?:chmod\s+(?:-R\s+)?777|chown\s+-R)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "DESTRUCTIVE_COMMAND",
        "CRITICAL",
        "Remote script download piped into shell or encoded powershell",
        re.compile(
            r"(?:curl|wget)\s+[^\n|;]+?\|\s*(?:bash|sh|zsh|dash|powershell|pwsh)\b|"
            r"\bpowershell(?:\.exe)?\s+(?:-[a-z]+\s+)*-(?:enc|encodedcommand)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "DESTRUCTIVE_COMMAND",
        "CRITICAL",
        "Reverse shell or raw interactive network socket command",
        re.compile(
            r"\b(?:nc\s+(?:-[a-z]+\s+)*-e|bash\s+-i\s+>&|/dev/tcp/)\b",
            re.IGNORECASE,
        ),
    ),
]

# SQL attack patterns: (Rule ID, Risk Level, Description, Pattern)
SQL_ATTACK_PATTERNS: List[Tuple[str, str, str, re.Pattern]] = [
    (
        "DESTRUCTIVE_SQL",
        "CRITICAL",
        "Destructive DROP TABLE or DROP DATABASE statement",
        re.compile(
            r"\bDROP\s+(?:TABLE|DATABASE|SCHEMA|VIEW)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "DESTRUCTIVE_SQL",
        "CRITICAL",
        "Destructive TRUNCATE statement",
        re.compile(
            r"\bTRUNCATE\s+(?:TABLE\s+)?[a-zA-Z0-9_]+",
            re.IGNORECASE,
        ),
    ),
    (
        "DESTRUCTIVE_SQL",
        "CRITICAL",
        "Destructive or unrestricted DELETE statement",
        re.compile(
            r"\bDELETE\s+FROM\s+[a-zA-Z0-9_]+(?:\s*;|\s*$|\s+WHERE\s+(?:1\s*=\s*1|true|'1'\s*=\s*'1'))",
            re.IGNORECASE,
        ),
    ),
    (
        "MUTATING_SQL",
        "CRITICAL",
        "Unauthorized database mutation or schema alteration statement",
        re.compile(
            r"\b(?:UPDATE\s+[a-zA-Z0-9_`\"\[\]]+\s+SET|"
            r"INSERT\s+(?:INTO\s+)?[a-zA-Z0-9_`\"\[\]]+|"
            r"ALTER\s+(?:TABLE|DATABASE|SCHEMA|VIEW)\b|"
            r"CREATE\s+(?:TABLE|DATABASE|SCHEMA|VIEW|INDEX|USER|TRIGGER|PROCEDURE)\b|"
            r"GRANT\s+[a-zA-Z0-9_,\s]+\s+TO\b|"
            r"REVOKE\s+[a-zA-Z0-9_,\s]+\s+FROM\b|"
            r"EXEC(?:UTE)?\s+[a-zA-Z0-9_@]+|"
            r"REPLACE\s+INTO\s+[a-zA-Z0-9_`\"\[\]]+)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "SQL_INJECTION",
        "HIGH",
        "SQL injection sequence or stacked comment attack",
        re.compile(
            r"(?:;\s*--|;\s*DROP|;\s*(?:SELECT|UPDATE|INSERT|DELETE|DROP|ALTER|CREATE|TRUNCATE|GRANT|REVOKE|EXEC(?:UTE)?|REPLACE)\b|"
            r"'\s*OR\s+'1'\s*=\s*'1|UNION\s+ALL\s+SELECT|UNION\s+SELECT)",
            re.IGNORECASE,
        ),
    ),
]

# Sensitive file and directory indicators
SENSITIVE_TARGETS = [
    ".env",
    ".git",
    "id_rsa",
    "passwd",
    "shadow",
    "system32",
]


def _scan_for_malicious_commands(text: str) -> Optional[Dict[str, Any]]:
    """Scan string arguments for destructive shell or SQL commands."""
    for rule_id, risk_level, description, pattern in SHELL_ATTACK_PATTERNS:
        match = pattern.search(text)
        if match:
            return {
                "allowed": False,
                "risk_level": risk_level,
                "rule_triggered": rule_id,
                "reason": f"Blocked by tool policy: {description} ('{match.group(0)}').",
            }

    for rule_id, risk_level, description, pattern in SQL_ATTACK_PATTERNS:
        match = pattern.search(text)
        if match:
            return {
                "allowed": False,
                "risk_level": risk_level,
                "rule_triggered": rule_id,
                "reason": f"Blocked by tool policy: {description} ('{match.group(0)}').",
            }

    return None


def _inspect_argument_recursively(
    arg_path: str,
    value: Any,
    current_depth: int = 1,
    max_depth: int = 20,
) -> Optional[Dict[str, Any]]:
    """Recursively scan arguments (dict, list, tuple, str) for malicious patterns.

    Nesting depth convention:
        - The top-level argument value in arguments begins at current_depth = 1.
        - Each nested dictionary level or sequence level increments depth by 1.
        - If current_depth > max_depth, returns a structured MAX_NESTING_DEPTH_EXCEEDED verdict.

    Safely rejects unsupported types (e.g. sets, bytes, custom classes) by default.
    Guards against unhandled RecursionError with bounded recursion and exception handling.
    """
    if current_depth > max_depth:
        return {
            "allowed": False,
            "risk_level": "HIGH",
            "rule_triggered": "MAX_NESTING_DEPTH_EXCEEDED",
            "reason": (
                f"Argument '{arg_path}' exceeds maximum nesting depth of {max_depth} "
                f"(current depth: {current_depth})."
            ),
        }

    try:
        if isinstance(value, str):
            return _scan_for_malicious_commands(value)
        elif isinstance(value, (int, float, bool)) or value is None:
            return None
        elif isinstance(value, dict):
            for k, v in value.items():
                if not isinstance(k, str):
                    return {
                        "allowed": False,
                        "risk_level": "HIGH",
                        "rule_triggered": "UNSUPPORTED_ARGUMENT_TYPE",
                        "reason": (
                            f"Dictionary key in '{arg_path}' must be a string, got '{type(k).__name__}'."
                        ),
                    }
                violation = _inspect_argument_recursively(
                    f"{arg_path}.{k}",
                    v,
                    current_depth=current_depth + 1,
                    max_depth=max_depth,
                )
                if violation:
                    return violation
            return None
        elif isinstance(value, (list, tuple)):
            for idx, item in enumerate(value):
                violation = _inspect_argument_recursively(
                    f"{arg_path}[{idx}]",
                    item,
                    current_depth=current_depth + 1,
                    max_depth=max_depth,
                )
                if violation:
                    return violation
            return None
        else:
            return {
                "allowed": False,
                "risk_level": "HIGH",
                "rule_triggered": "UNSUPPORTED_ARGUMENT_TYPE",
                "reason": (
                    f"Argument '{arg_path}' contains unsupported type '{type(value).__name__}'. "
                    "Only JSON-compatible primitives (str, int, float, bool, None, dict, list) are permitted."
                ),
            }
    except RecursionError:
        return {
            "allowed": False,
            "risk_level": "HIGH",
            "rule_triggered": "MAX_NESTING_DEPTH_EXCEEDED",
            "reason": f"Argument '{arg_path}' caused recursion depth limit to be exceeded.",
        }


def evaluate_tool_call(
    tool_name: str,
    arguments: Dict[str, Any],
    allowed_dir: str = "data",
    max_depth: int = 20,
) -> Dict[str, Any]:
    """Validate a proposed tool call and arguments before any execution.

    Args:
        tool_name: The name of the proposed tool.
        arguments: Dictionary of arguments proposed for the tool.
        allowed_dir: Directory to which file operations are strictly restricted.
        max_depth: Maximum permitted nesting depth for arguments (default: 20).

    Returns:
        dict containing:
            - allowed (bool): True if permitted, False if blocked.
            - risk_level (str): "NONE", "HIGH", or "CRITICAL".
            - rule_triggered (Optional[str]): Triggered rule name, or None.
            - reason (str): Human-readable rationale.

    Raises:
        ValueError: If tool_name is not a non-empty string or arguments is not a dict.
    """
    if not isinstance(tool_name, str) or not tool_name.strip():
        raise ValueError("tool_name must be a non-empty string")
    if not isinstance(arguments, dict):
        raise ValueError("arguments must be a dictionary")
    # bool is a subclass of int in Python, so explicitly reject it.
    if isinstance(max_depth, bool) or not isinstance(max_depth, int) or max_depth < 1:
        raise ValueError("max_depth must be a positive integer")

    clean_tool_name = tool_name.strip()

    # Rule 1: Unknown tool rejection (deny-by-default)
    if clean_tool_name not in ALLOWED_TOOLS:
        return {
            "allowed": False,
            "risk_level": "HIGH",
            "rule_triggered": "UNKNOWN_TOOL",
            "reason": (
                f"Tool '{clean_tool_name}' is not in the allowed tools registry. "
                f"Permitted tools: {list(ALLOWED_TOOLS.keys())}."
            ),
        }

    tool_meta = ALLOWED_TOOLS[clean_tool_name]

    # Rule 2: Missing or invalid required arguments & type enforcement
    for req_arg, expected_type in tool_meta["required_args"].items():
        if req_arg not in arguments or arguments[req_arg] is None:
            return {
                "allowed": False,
                "risk_level": "HIGH",
                "rule_triggered": "MISSING_REQUIRED_ARGUMENT",
                "reason": f"Tool '{clean_tool_name}' requires argument '{req_arg}'.",
            }

        arg_val = arguments[req_arg]

        # Enforce expected argument type (e.g. str for query, sql, path)
        if not isinstance(arg_val, expected_type):
            return {
                "allowed": False,
                "risk_level": "HIGH",
                "rule_triggered": "INVALID_ARGUMENT_TYPE",
                "reason": (
                    f"Argument '{req_arg}' for tool '{clean_tool_name}' must be of type "
                    f"'{expected_type.__name__}', got '{type(arg_val).__name__}'."
                ),
            }

        # Check for empty string if argument is a string
        if expected_type is str and not arg_val.strip():
            return {
                "allowed": False,
                "risk_level": "HIGH",
                "rule_triggered": "INVALID_ARGUMENT",
                "reason": f"Argument '{req_arg}' cannot be empty.",
            }

    # Rule 3: Recursively inspect nested dictionaries, lists, and strings for attacks & types
    for arg_key, arg_val in arguments.items():
        violation = _inspect_argument_recursively(
            arg_key,
            arg_val,
            current_depth=1,
            max_depth=max_depth,
        )
        if violation:
            return violation

    # Rule 4: File path validation for read_demo_file
    if clean_tool_name == "read_demo_file":
        raw_path_val = arguments["path"]
        if not isinstance(raw_path_val, str) or not raw_path_val.strip():
            return {
                "allowed": False,
                "risk_level": "HIGH",
                "rule_triggered": "INVALID_ARGUMENT",
                "reason": "Path argument must be a non-empty string.",
            }

        raw_path = raw_path_val.strip()

        # Reject embedded null bytes
        if "\0" in raw_path or "%00" in raw_path:
            return {
                "allowed": False,
                "risk_level": "CRITICAL",
                "rule_triggered": "PATH_TRAVERSAL",
                "reason": f"Null bytes are forbidden in file path: '{raw_path}'.",
            }

        # SEC-04: Reject Windows Alternate Data Streams (ADS) and colon characters
        if ":" in raw_path:
            return {
                "allowed": False,
                "risk_level": "CRITICAL",
                "rule_triggered": "PATH_TRAVERSAL",
                "reason": f"Colons and Windows Alternate Data Streams (ADS) are forbidden: '{raw_path}'.",
            }

        # Check raw path traversal sequences (.. in normalized path tokens)
        normalized_tokens = [
            token
            for token in raw_path.replace("\\", "/").split("/")
            if token and token != "."
        ]
        if ".." in normalized_tokens:
            return {
                "allowed": False,
                "risk_level": "CRITICAL",
                "rule_triggered": "PATH_TRAVERSAL",
                "reason": f"Path traversal token '..' detected in path: '{raw_path}'.",
            }

        # Check for absolute path indicators (/ or drive letter C:\ or UNC \\)
        if (
            raw_path.startswith("/")
            or raw_path.startswith("\\")
            or re.match(r"^[a-zA-Z]:", raw_path)
            or re.match(r"^\\\\", raw_path)
        ):
            return {
                "allowed": False,
                "risk_level": "CRITICAL",
                "rule_triggered": "PATH_TRAVERSAL",
                "reason": f"Absolute or network UNC paths are forbidden: '{raw_path}'.",
            }

        # Check for Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
        if re.match(
            r"^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", raw_path, re.IGNORECASE
        ):
            return {
                "allowed": False,
                "risk_level": "CRITICAL",
                "rule_triggered": "PATH_TRAVERSAL",
                "reason": f"Windows reserved device names are forbidden: '{raw_path}'.",
            }

        # Check sensitive file name and directory patterns
        lower_path = raw_path.lower()
        for sensitive_target in SENSITIVE_TARGETS:
            if sensitive_target in lower_path:
                return {
                    "allowed": False,
                    "risk_level": "CRITICAL",
                    "rule_triggered": "SENSITIVE_FILE_ACCESS",
                    "reason": f"Access to sensitive file or pattern is forbidden: '{raw_path}'.",
                }

        # Canonical path resolution & symlink sandbox containment
        real_allowed = os.path.realpath(os.path.abspath(allowed_dir))
        candidate_abs = os.path.abspath(os.path.join(real_allowed, raw_path))
        candidate_real = os.path.realpath(candidate_abs)

        try:
            common_abs = os.path.commonpath([real_allowed, candidate_abs])
            common_real = os.path.commonpath([real_allowed, candidate_real])
        except ValueError:
            # Raised on Windows when paths belong to different drives
            return {
                "allowed": False,
                "risk_level": "CRITICAL",
                "rule_triggered": "DISALLOWED_DIRECTORY",
                "reason": (
                    f"Path '{raw_path}' resolves to a different drive or invalid path."
                ),
            }

        # Ensure resolved path is strictly inside allowed_dir (not pointing outside or equal to root dir)
        if (
            common_abs != real_allowed
            or common_real != real_allowed
            or candidate_real == real_allowed
        ):
            return {
                "allowed": False,
                "risk_level": "CRITICAL",
                "rule_triggered": "DISALLOWED_DIRECTORY",
                "reason": (
                    f"Path '{raw_path}' resolves outside the allowed demo directory '{allowed_dir}'."
                ),
            }

    # Rule 5: Read-only query validation for query_demo_database (SEC-02: read-only enforcement)
    if clean_tool_name == "query_demo_database":
        raw_sql = arguments["sql"].strip()
        # Strip leading SQL comments to inspect effective statement opening
        effective_sql = re.sub(r"^/\*.*?\*/", "", raw_sql, flags=re.DOTALL).strip()
        effective_sql = re.sub(r"^--[^\r\n]*", "", effective_sql).strip()
        if not re.match(r"^(?:SELECT|WITH|EXPLAIN)\b", effective_sql, re.IGNORECASE):
            return {
                "allowed": False,
                "risk_level": "CRITICAL",
                "rule_triggered": "MUTATING_SQL",
                "reason": (
                    f"Tool '{clean_tool_name}' only permits read-only queries (SELECT/WITH/EXPLAIN); "
                    "mutating or unauthorized statements are blocked."
                ),
            }

    return {
        "allowed": True,
        "risk_level": "NONE",
        "rule_triggered": None,
        "reason": f"Tool call '{clean_tool_name}' passed all pre-execution policy checks.",
    }


def simulate_tool_call(
    tool_name: str,
    arguments: Dict[str, Any],
    allowed_dir: str = "data",
    max_depth: int = 20,
) -> Dict[str, Any]:
    """Simulate tool execution safely after policy validation.

    NEVER executes real system commands, real database mutations, or unvetted code.
    """
    verdict = evaluate_tool_call(
        tool_name,
        arguments,
        allowed_dir=allowed_dir,
        max_depth=max_depth,
    )

    if not verdict["allowed"]:
        return {
            "status": "BLOCKED",
            "tool": tool_name,
            "arguments": arguments,
            "simulated_output": None,
            "policy_verdict": verdict,
        }

    clean_tool_name = tool_name.strip()
    simulated_payload: Any = None

    if clean_tool_name == "search_docs":
        query = arguments["query"]
        simulated_payload = f"Simulated search results for query: '{query}' (Found 2 mock articles)."
    elif clean_tool_name == "read_demo_file":
        rel_path = arguments["path"]
        simulated_payload = f"Simulated file read for allowed demo file: '{rel_path}' (Header: sample_data)."
    elif clean_tool_name == "query_demo_database":
        sql = arguments["sql"]
        simulated_payload = f"Simulated read-only query executed: '{sql}' (Returned 1 mock row)."

    return {
        "status": "SIMULATED_SUCCESS",
        "tool": clean_tool_name,
        "arguments": arguments,
        "simulated_output": simulated_payload,
        "policy_verdict": verdict,
    }
