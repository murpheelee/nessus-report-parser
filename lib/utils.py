"""Utility functions for Nessus report parsing."""


def truncate(text: str, max_length: int = 50) -> str:
    """Truncate text to max_length with ellipsis."""
    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."


def severity_to_int(severity: str) -> int:
    """Convert severity string to integer for sorting."""
    mapping = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
    return mapping.get(severity.lower(), 0)
